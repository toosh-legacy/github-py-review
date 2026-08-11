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
# requests. Anything past a cap is *reported*, never silently dropped — see
# `truncated` on the return values.
MAX_QUERIES = 1000
MAX_VULN_DETAILS = 500
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


class _Result(dict):
    """A dict that also remembers how much was left unchecked.

    The caps exist so one scan cannot fire thousands of requests, but a cap that
    silently shortens the answer is the exact failure this tool reports in other
    people's code. `truncated` is how the caller learns to say so.

    `unmatched` counts packages the API returned no result slot for at all,
    which is a different failure with the same consequence — see `query_batch`.
    """

    def __init__(self, data: dict, truncated: int = 0, unmatched: int = 0) -> None:
        super().__init__(data)
        self.truncated = truncated
        self.unmatched = unmatched


def _parse_batch_entry(entry: object) -> list[str]:
    """The vulnerability ids in one `querybatch` result slot.

    Every branch here raises rather than returning `[]`, and that asymmetry is
    the whole point. A package with no known vulnerabilities is `{}` or `null` —
    OSV omits the key. So `[]` from a *malformed* slot is indistinguishable from
    a genuinely clean package, and the scanner would print "no vulnerable
    dependencies" for a lockfile full of them. Reporting a schema change as a
    degraded detector costs the user a warning; reading it as an all-clear costs
    them the vulnerability.
    """
    if entry is None or entry == {}:
        return []
    if not isinstance(entry, dict):
        raise OSVUnavailable(
            f"unexpected response schema: result slot is {type(entry).__name__}, "
            "expected an object"
        )
    if "vulns" not in entry:
        # A non-empty slot that says nothing about vulnerabilities means the
        # field was renamed or moved. Do not read silence as safety.
        raise OSVUnavailable(
            "unexpected response schema: result slot has no 'vulns' field "
            f"(keys: {sorted(entry)[:5]})"
        )
    vulns = entry["vulns"]
    if not isinstance(vulns, list):
        raise OSVUnavailable(
            f"unexpected response schema: 'vulns' is {type(vulns).__name__}, "
            "expected a list"
        )
    return [v["id"] for v in vulns if isinstance(v, dict) and v.get("id")]


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def query_batch(
    packages: list[Package], *, timeout: float = 20.0, client: httpx.Client | None = None
) -> dict[Package, list[str]]:
    """Map each package to the OSV ids affecting it. Raises OSVUnavailable.

    Sets a `truncated` attribute on the returned dict-like when the cap was hit,
    so the caller can say so rather than quietly reporting a partial answer.
    """
    if not packages:
        return _Result({}, 0)
    skipped = max(0, len(packages) - MAX_QUERIES)
    packages = packages[:MAX_QUERIES]
    owns_client = client is None
    client = client or httpx.Client(timeout=timeout)
    result: dict[Package, list[str]] = {}
    unmatched = 0
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
            body = resp.json()
            if not isinstance(body, dict) or "results" not in body:
                raise OSVUnavailable(
                    "unexpected response schema: no 'results' field in the "
                    "querybatch reply"
                )
            results = body["results"]
            if not isinstance(results, list):
                # A dict here used to be worse than useless: `zip` walked its
                # keys, so `entry` was a str and `entry.get` raised
                # AttributeError — which escaped this function's except clause
                # and killed the scan outright instead of degrading it.
                raise OSVUnavailable(
                    f"unexpected response schema: 'results' is "
                    f"{type(results).__name__}, expected a list"
                )
            # strict=False on purpose: OSV returns results positionally, and a
            # short list means the API misbehaved. Losing coverage for the tail
            # of the batch beats losing the whole scan — but it is counted, not
            # swallowed, because an unchecked package that reads as a checked
            # one is the failure this detector exists to prevent.
            unmatched += max(0, len(batch) - len(results))
            for pkg, entry in zip(batch, results, strict=False):
                if ids := _parse_batch_entry(entry):
                    result[pkg] = ids
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise OSVUnavailable(str(exc)) from exc
    finally:
        if owns_client:
            client.close()
    return _Result(result, skipped, unmatched)


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
    all_ids = list(dict.fromkeys(vuln_ids))
    unique = all_ids[:MAX_VULN_DETAILS]
    skipped = len(all_ids) - len(unique)
    if not unique:
        return _Result({}, 0)
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
    return _Result(out, skipped)
