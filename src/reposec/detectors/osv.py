"""Thin client for the OSV vulnerability database (https://osv.dev).

Two calls: `querybatch` maps (package, version) pairs to vulnerability ids in
one request, then each unique id is fetched for its details. Batching matters —
a repo with a large lockfile would otherwise be hundreds of round-trips.

Every failure mode here is non-fatal. If OSV is unreachable (offline, rate
limited, blocked) the scan reports the dependency detector as degraded rather
than silently returning "no vulnerabilities", which would be a lie.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import httpx

OSV_API = "https://api.osv.dev"

# Bound the work: a huge lockfile shouldn't turn one scan into a thousand
# requests. Findings past the cap are reported as a degraded detector.
MAX_QUERIES = 1000
MAX_VULN_DETAILS = 150
# Enough to hide the round-trip latency without hammering a free public API.
DETAIL_WORKERS = 8


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # "PyPI" | "npm"
    manifest: str  # the file it came from
    line: int = 0


class OSVUnavailable(RuntimeError):
    """OSV could not be reached or refused the request."""


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def query_batch(
    packages: list[Package], *, timeout: float = 20.0, client: httpx.Client | None = None
) -> dict[Package, list[str]]:
    """Map each package to the OSV ids affecting it. Raises OSVUnavailable."""
    if not packages:
        return {}
    packages = packages[:MAX_QUERIES]
    owns_client = client is None
    client = client or httpx.Client(timeout=timeout)
    result: dict[Package, list[str]] = {}
    try:
        # The API accepts large batches, but keep requests modest so a single
        # slow response can't stall the whole scan.
        for batch in _chunks(packages, 200):
            payload = {
                "queries": [
                    {
                        "version": p.version,
                        "package": {"name": p.name, "ecosystem": p.ecosystem},
                    }
                    for p in batch
                ]
            }
            resp = client.post(f"{OSV_API}/v1/querybatch", json=payload)
            resp.raise_for_status()
            results = resp.json().get("results", [])
            # strict=False on purpose: OSV returns results positionally, and a
            # short list means the API misbehaved. Truncating loses coverage for
            # the tail of the batch, but raising would lose the whole scan.
            for pkg, entry in zip(batch, results, strict=False):
                ids = [v["id"] for v in (entry or {}).get("vulns", []) if v.get("id")]
                if ids:
                    result[pkg] = ids
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise OSVUnavailable(str(exc)) from exc
    finally:
        if owns_client:
            client.close()
    return result


def fetch_details(
    vuln_ids: list[str], *, timeout: float = 20.0, client: httpx.Client | None = None
) -> dict[str, dict]:
    """Fetch the full OSV record for each id. Missing ids are simply absent.

    Fetched concurrently: OSV has no batch detail endpoint, so a repo with a
    large lockfile needs one request per vulnerability. Serially that is the
    slowest part of a scan by an order of magnitude — 150 round trips at ~200ms
    is half a minute, which is enough to trip an HTTP proxy timeout on the
    /security/scan route.
    """
    unique = list(dict.fromkeys(vuln_ids))[:MAX_VULN_DETAILS]
    if not unique:
        return {}
    owns_client = client is None
    client = client or httpx.Client(
        timeout=timeout,
        # The pool has to be at least as wide as the worker count or the
        # workers just queue against each other.
        limits=httpx.Limits(max_connections=DETAIL_WORKERS),
    )
    out: dict[str, dict] = {}

    def fetch(vid: str) -> tuple[str, dict | None]:
        try:
            resp = client.get(f"{OSV_API}/v1/vulns/{vid}")
            if resp.status_code != 200:
                return vid, None
            return vid, resp.json()
        except (httpx.HTTPError, ValueError):
            # One bad record shouldn't lose the other 149.
            return vid, None

    try:
        with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
            for vid, record in pool.map(fetch, unique):
                if record is not None:
                    out[vid] = record
    finally:
        if owns_client:
            client.close()
    return out
