"""The OSV HTTP path: parsing real payloads, and failing loudly when it can't.

`SECURITY_OFFLINE=1` short-circuits this module in CI and the dependency
detector tests stub `query_batch` outright, so lines 68-103 and 117-149 of
`detectors/osv.py` had never executed. That is the dangerous kind of untested:
if osv.dev renames a field, the parser returns nothing and the scan reports a
clean bill of health for dependencies.

Nothing here touches the network. Both entry points accept `client=`, so a
stubbed client is injected through that seam rather than monkeypatching httpx
globally — the code under test builds and closes its own client on the real
path, and that behaviour is asserted too.

Payload shapes are taken from `src/evaluation/security_benchmark/osv_snapshot.json`,
which holds genuinely recorded osv.dev responses; the fixtures under
`tests/fixtures/osv/` are cut from it rather than invented.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import httpx
import pytest

from reposec.detectors import deps
from reposec.detectors import osv as osv_mod
from reposec.detectors.osv import (
    MAX_QUERIES,
    MAX_VULN_DETAILS,
    OSVUnavailable,
    Package,
    fetch_details,
    query_batch,
)

FIXTURES = Path(__file__).parent / "fixtures" / "osv"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text("utf-8"))


# --------------------------------------------------------------------------- #
# A stand-in for httpx.Client.
#
# The *responses* are real `httpx.Response` objects so that `raise_for_status`,
# `.json()` and `.status_code` behave exactly as they do in production — a
# hand-rolled response object would let a wrong assumption about httpx pass.
# --------------------------------------------------------------------------- #
class FakeClient:
    """Records requests and replays whatever the handler returns or raises."""

    def __init__(self, handler):
        self._handler = handler
        self.requests: list[tuple[str, str, dict | None]] = []
        self.closed = False
        self._lock = threading.Lock()  # fetch_details calls this from 8 threads

    def _call(self, method: str, url: str, payload: dict | None):
        with self._lock:
            self.requests.append((method, url, payload))
            n = len(self.requests) - 1
        result = self._handler(n, url, payload)
        if isinstance(result, Exception):
            raise result
        return result

    def post(self, url, json=None):  # noqa: A002 - matches httpx's signature
        return self._call("POST", url, json)

    def get(self, url):
        return self._call("GET", url, None)

    def close(self):
        self.closed = True


def ok(payload: dict) -> httpx.Response:
    return httpx.Response(
        200, json=payload, request=httpx.Request("POST", "https://api.osv.dev/")
    )


def status(code: int, *, body: dict | None = None) -> httpx.Response:
    req = httpx.Request("GET", "https://api.osv.dev/")
    if body is None:
        return httpx.Response(code, text="upstream said no", request=req)
    return httpx.Response(code, json=body, request=req)


def replies(*responses):
    """Handler that returns the nth canned response, then repeats the last."""

    def handler(n, url, payload):
        return responses[min(n, len(responses) - 1)]

    return handler


REQUESTS_2_19 = Package("requests", "2.19.0", "PyPI", "requirements.txt", 1)
IDNA_3_10 = Package("idna", "3.10", "PyPI", "requirements.txt", 2)
PYYAML_5_1 = Package("pyyaml", "5.1", "PyPI", "requirements.txt", 3)
THREE = [REQUESTS_2_19, IDNA_3_10, PYYAML_5_1]


# --------------------------------------------------------------------------- #
# query_batch — the happy path, against recorded payload shapes
# --------------------------------------------------------------------------- #
def test_recorded_querybatch_response_is_parsed_into_ids_per_package():
    client = FakeClient(replies(ok(fixture("querybatch_response.json"))))
    result = query_batch(THREE, client=client)

    # Positional: OSV answers a querybatch in the order the queries were sent.
    assert result[REQUESTS_2_19][0] == "GHSA-9hjg-9r4m-mvj7"
    assert result[IDNA_3_10] == ["GHSA-65pc-fj4g-8rjx", "PYSEC-2026-215"]
    assert "PYSEC-2020-176" in result[PYYAML_5_1]
    assert result.truncated == 0


def test_the_request_body_is_the_shape_osv_documents():
    # If this drifts, every response is empty and every scan looks clean — so
    # assert the outgoing payload, not just what we do with the reply.
    client = FakeClient(replies(ok({"results": [{}]})))
    query_batch([REQUESTS_2_19], client=client)

    method, url, payload = client.requests[0]
    assert (method, url) == ("POST", "https://api.osv.dev/v1/querybatch")
    assert payload == {
        "queries": [
            {"version": "2.19.0", "package": {"name": "requests", "ecosystem": "PyPI"}}
        ]
    }


def test_a_package_with_no_advisories_is_absent_rather_than_empty():
    # OSV returns `{}` for a clean package. Storing it as an empty list would
    # make `hits` iterate packages that have nothing to report.
    client = FakeClient(replies(ok(fixture("querybatch_empty.json"))))
    result = query_batch(THREE, client=client)
    assert result == {}
    assert result.truncated == 0


def test_no_packages_means_no_request_at_all():
    client = FakeClient(replies(ok({"results": []})))
    assert query_batch([], client=client) == {}
    assert client.requests == []


def test_a_caller_supplied_client_is_left_open_but_an_owned_one_is_closed():
    # The client is shared across a scan; closing someone else's connection
    # pool mid-scan would fail every later request.
    client = FakeClient(replies(ok({"results": [{}]})))
    query_batch([REQUESTS_2_19], client=client)
    assert client.closed is False


def test_owned_client_is_constructed_and_closed_when_none_is_passed(monkeypatch):
    made: list[FakeClient] = []

    def factory(**kwargs):
        client = FakeClient(replies(ok({"results": [{}]})))
        client.kwargs = kwargs
        made.append(client)
        return client

    monkeypatch.setattr(osv_mod.httpx, "Client", factory)
    query_batch([REQUESTS_2_19], timeout=3.5)
    assert made[0].kwargs["timeout"] == 3.5
    assert made[0].closed is True  # no leaked connection pool


def test_large_batches_are_chunked_and_every_chunk_is_kept():
    # 200 queries per request; a bug that only kept the last chunk would lose
    # every advisory for the first 200 packages in a big lockfile.
    packages = [
        Package(f"pkg{i}", "1.0.0", "PyPI", "requirements.txt", i) for i in range(250)
    ]

    def handler(n, url, payload):
        assert len(payload["queries"]) == (200 if n == 0 else 50)
        slot = {"vulns": [{"id": f"OSV-{n}"}]}
        return ok({"results": [slot] * len(payload["queries"])})

    client = FakeClient(handler)
    result = query_batch(packages, client=client)

    assert len(client.requests) == 2
    assert len(result) == 250
    assert result[packages[0]] == ["OSV-0"]
    assert result[packages[249]] == ["OSV-1"]


def test_a_short_results_list_maps_positionally_and_counts_the_tail():
    # `zip(..., strict=False)` on purpose: a short list means the API
    # misbehaved. Losing the tail is bad; raising and losing the whole scan is
    # worse. This pins which trade-off is in force — and that the tail is
    # *counted*, so the caller can report it rather than implying it was clean.
    client = FakeClient(replies(ok({"results": [{"vulns": [{"id": "OSV-1"}]}]})))
    result = query_batch(THREE, client=client)
    assert result == {REQUESTS_2_19: ["OSV-1"]}
    assert IDNA_3_10 not in result and PYYAML_5_1 not in result
    assert result.unmatched == 2


def test_an_unmatched_tail_is_reported_as_degraded(monkeypatch):
    client = FakeClient(replies(ok({"results": []})))
    monkeypatch.setattr(
        deps, "query_batch", lambda pkgs: query_batch(pkgs, client=client)
    )

    findings, degraded = deps.scan_dependencies(
        [("requirements.txt", "requests==2.19.0\npyyaml==5.1\n")]
    )
    assert findings == []
    assert any("left unchecked" in d for d in degraded), degraded


def test_vulns_entries_without_an_id_are_skipped_not_crashed():
    client = FakeClient(
        replies(
            ok({"results": [{"vulns": [{"id": ""}, {"modified": "x"}, {"id": "OK"}]}]})
        )
    )
    assert query_batch([REQUESTS_2_19], client=client) == {REQUESTS_2_19: ["OK"]}


# --------------------------------------------------------------------------- #
# query_batch — failure must be loud
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("code", [400, 429, 500, 503])
def test_an_http_error_becomes_osv_unavailable(code):
    client = FakeClient(replies(status(code)))
    with pytest.raises(OSVUnavailable):
        query_batch([REQUESTS_2_19], client=client)


def test_a_transport_error_becomes_osv_unavailable():
    client = FakeClient(replies(httpx.ConnectError("connection refused")))
    with pytest.raises(OSVUnavailable) as exc:
        query_batch([REQUESTS_2_19], client=client)
    assert "connection refused" in str(exc.value)


def test_a_non_json_body_becomes_osv_unavailable():
    # A captive portal or proxy error page returns 200 with HTML. That must not
    # be read as "no vulnerabilities".
    html = httpx.Response(
        200, text="<html>proxy auth required</html>",
        request=httpx.Request("POST", "https://api.osv.dev/"),
    )
    client = FakeClient(replies(html))
    with pytest.raises(OSVUnavailable):
        query_batch([REQUESTS_2_19], client=client)


def test_an_owned_client_is_closed_even_when_the_request_fails(monkeypatch):
    made: list[FakeClient] = []

    def factory(**kwargs):
        client = FakeClient(replies(httpx.ConnectError("down")))
        made.append(client)
        return client

    monkeypatch.setattr(osv_mod.httpx, "Client", factory)
    with pytest.raises(OSVUnavailable):
        query_batch([REQUESTS_2_19])
    assert made[0].closed is True


def test_packages_past_the_query_cap_are_reported_as_truncated():
    packages = [
        Package(f"pkg{i}", "1.0.0", "PyPI", "requirements.txt")
        for i in range(MAX_QUERIES + 7)
    ]
    client = FakeClient(replies(ok({"results": []})))
    result = query_batch(packages, client=client)
    # Capped, and the caller is told exactly how much was left unchecked.
    assert result.truncated == 7
    assert len(client.requests) == MAX_QUERIES // 200


# --------------------------------------------------------------------------- #
# A schema change must degrade, never read as a clean bill of health.
#
# This is the failure mode `docs/PRODUCTION_READINESS.md` §2.1 was written
# about, and the reason every branch of `_parse_batch_entry` raises rather than
# returning an empty list: a clean package and an unparseable one both produce
# "no vulnerability ids", and only one of them is safe to report as clean.
# --------------------------------------------------------------------------- #
def test_a_renamed_vulns_key_raises_rather_than_reporting_clean():
    # If osv.dev renames `vulns`, the slot is non-empty but says nothing about
    # vulnerabilities. Silence there must not be read as safety.
    client = FakeClient(replies(ok(fixture("querybatch_schema_changed.json"))))
    with pytest.raises(OSVUnavailable) as exc:
        query_batch(THREE, client=client)
    assert "schema" in str(exc.value)


def test_a_renamed_results_key_raises_rather_than_reporting_clean():
    client = FakeClient(replies(ok({"data": [{"vulns": [{"id": "GHSA-x"}]}]})))
    with pytest.raises(OSVUnavailable) as exc:
        query_batch(THREE, client=client)
    assert "results" in str(exc.value)


def test_results_as_a_dict_degrades_instead_of_crashing_the_scan():
    # `zip(batch, {"a": {...}})` walks the dict's *keys*, so `entry` used to be
    # a str and `entry.get` exploded with an AttributeError — which is not in
    # the except clause, so it escaped query_batch, and scan_dependencies only
    # catches OSVUnavailable. A schema change of this shape killed the whole
    # scan rather than degrading one detector.
    client = FakeClient(replies(ok({"results": {"0": {"vulns": [{"id": "GHSA-x"}]}}})))
    with pytest.raises(OSVUnavailable):
        query_batch(THREE, client=client)


def test_vulns_of_the_wrong_type_raises():
    client = FakeClient(replies(ok({"results": [{"vulns": "GHSA-x"}]})))
    with pytest.raises(OSVUnavailable):
        query_batch([REQUESTS_2_19], client=client)


@pytest.mark.parametrize("clean", [None, {}])
def test_a_genuinely_clean_package_is_still_clean(clean):
    # The other half of the contract. If this raised, every scan of a healthy
    # lockfile would report a degraded detector, and the warning would stop
    # meaning anything.
    client = FakeClient(replies(ok({"results": [clean]})))
    result = query_batch([REQUESTS_2_19], client=client)
    assert result == {}
    assert result.unmatched == 0


def test_a_schema_change_reads_as_degraded_not_as_a_clean_repository(monkeypatch):
    # The end-to-end statement, through the real detector entry point: no
    # findings, but a degraded note that says why — so the report cannot be
    # mistaken for a genuinely clean repository.
    client = FakeClient(replies(ok(fixture("querybatch_schema_changed.json"))))
    monkeypatch.setattr(
        deps, "query_batch", lambda pkgs: query_batch(pkgs, client=client)
    )
    monkeypatch.setattr(
        deps, "fetch_details", lambda ids: fetch_details(ids, client=client)
    )

    findings, degraded = deps.scan_dependencies(
        [("requirements.txt", "requests==2.19.0\npyyaml==5.1\n")]
    )
    assert findings == []
    assert degraded, "a schema change must never yield findings==[] and degraded==[]"
    assert any("schema" in d for d in degraded), degraded


# --------------------------------------------------------------------------- #
# The contract that *does* hold: an unreachable OSV degrades rather than lying.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "failure", [status(503), httpx.ConnectError("refused"), httpx.ReadTimeout("slow")]
)
def test_an_unreachable_osv_degrades_through_scan_dependencies(monkeypatch, failure):
    client = FakeClient(replies(failure))
    monkeypatch.setattr(
        deps, "query_batch", lambda pkgs: query_batch(pkgs, client=client)
    )

    findings, degraded = deps.scan_dependencies(
        [("requirements.txt", "requests==2.19.0\n")]
    )
    assert findings == []
    assert any("OSV unreachable" in d for d in degraded)


def test_a_well_formed_response_produces_real_findings_end_to_end(monkeypatch):
    # The whole HTTP path, wired to the detector: recorded querybatch reply,
    # recorded advisory records, real findings out.
    batch = ok({"results": [{"vulns": [{"id": "GHSA-9hjg-9r4m-mvj7"}]}]})
    detail = ok(fixture("vuln_requests.json"))
    batch_client = FakeClient(replies(batch))
    detail_client = FakeClient(replies(detail))
    monkeypatch.setattr(
        deps, "query_batch", lambda pkgs: query_batch(pkgs, client=batch_client)
    )
    monkeypatch.setattr(
        deps, "fetch_details", lambda ids: fetch_details(ids, client=detail_client)
    )

    findings, degraded = deps.scan_dependencies(
        [("requirements.txt", "requests==2.19.0\n")]
    )
    assert degraded == []
    assert len(findings) == 1
    assert findings[0].rule_id == "CVE-2024-47081"  # CVE alias from the real record
    assert "2.32.4" in findings[0].suggested_fix


# --------------------------------------------------------------------------- #
# fetch_details
# --------------------------------------------------------------------------- #
def test_details_are_fetched_once_per_unique_id():
    record = fixture("vuln_pyyaml.json")
    client = FakeClient(replies(ok(record)))
    out = fetch_details(["GHSA-3pqx-4fqf-j49f", "GHSA-3pqx-4fqf-j49f"], client=client)

    assert list(out) == ["GHSA-3pqx-4fqf-j49f"]
    assert out["GHSA-3pqx-4fqf-j49f"]["summary"] == record["summary"]
    assert len(client.requests) == 1
    assert client.requests[0][1] == (
        "https://api.osv.dev/v1/vulns/GHSA-3pqx-4fqf-j49f"
    )
    assert out.truncated == 0


def test_no_ids_means_no_request():
    client = FakeClient(replies(ok({})))
    assert fetch_details([], client=client) == {}
    assert client.requests == []


@pytest.mark.parametrize(
    ("bad", "why"),
    [
        (status(404), "withdrawn advisory"),
        (status(500), "upstream error"),
        (httpx.ConnectError("reset"), "transport failure"),
        (
            httpx.Response(
                200, text="<html>nope</html>",
                request=httpx.Request("GET", "https://api.osv.dev/"),
            ),
            "unparseable body",
        ),
    ],
)
def test_one_bad_record_does_not_lose_the_others(bad, why):
    # 150 details per scan is normal; a single dud must not cost the other 149.
    good = ok(fixture("vuln_requests.json"))

    def handler(n, url, payload):
        return bad if url.endswith("/BAD") else good

    client = FakeClient(handler)
    out = fetch_details(["GOOD-1", "BAD", "GOOD-2"], client=client)

    assert set(out) == {"GOOD-1", "GOOD-2"}, why
    assert out["GOOD-1"]["id"] == "GHSA-9hjg-9r4m-mvj7"


def test_ids_past_the_detail_cap_are_reported_as_truncated():
    ids = [f"OSV-{i}" for i in range(MAX_VULN_DETAILS + 3)]
    client = FakeClient(replies(ok({"id": "x"})))
    out = fetch_details(ids, client=client)
    assert out.truncated == 3
    assert len(client.requests) == MAX_VULN_DETAILS


def test_fetch_details_closes_only_the_client_it_owns(monkeypatch):
    caller_owned = FakeClient(replies(ok({"id": "x"})))
    fetch_details(["OSV-1"], client=caller_owned)
    assert caller_owned.closed is False

    made: list[FakeClient] = []

    def factory(**kwargs):
        client = FakeClient(replies(ok({"id": "x"})))
        client.kwargs = kwargs
        made.append(client)
        return client

    monkeypatch.setattr(osv_mod.httpx, "Client", factory)
    fetch_details(["OSV-1"])
    assert made[0].closed is True
    # The pool has to be at least as wide as the worker count or the concurrent
    # fetches just queue behind each other.
    assert made[0].kwargs["limits"].max_connections == osv_mod.DETAIL_WORKERS
