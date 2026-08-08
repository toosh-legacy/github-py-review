"""The /security/* routes, end to end through the graph and the database."""
from __future__ import annotations

REPO_FILES = [
    {
        "path": "app/settings.py",
        "content": 'GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"\n',
    },
    {
        "path": "app/db.py",
        "content": (
            "def get_user(conn, uid):\n"
            '    return conn.execute("SELECT * FROM users WHERE id = " + uid)\n'
        ),
    },
    {"path": "assets/logo.png", "content": "\x00\x01\x02binary"},
    {"path": "node_modules/x/index.js", "content": "eval(userInput);\n"},
]


def _scan(client, files=None):
    body = {
        "repo": "acme/demo",
        "ref": "main",
        "files": REPO_FILES if files is None else files,
    }
    return client.post("/security/scan/full", json=body)


def _cap(monkeypatch, **overrides):
    """Override a scan guardrail for one test.

    `backend.service` binds the settings object at import time, so patching it
    there is what the running app actually reads.
    """
    import backend.service

    patched = backend.service.settings.model_copy(update=overrides)
    monkeypatch.setattr(backend.service, "settings", patched)


def test_scan_returns_findings_from_the_detectors(client, monkeypatch):
    monkeypatch.setenv("SECURITY_OFFLINE", "1")
    resp = _scan(client)
    assert resp.status_code == 200
    report = resp.json()["report"]

    rules = {f["rule_id"] for f in report["findings"]}
    assert "github-pat" in rules  # secret detector
    assert report["counts_by_category"]["secret"] >= 1
    # Binary and vendored files are dropped before any detector runs.
    assert report["scanned_files"] == 2
    assert report["skipped_files"] == 2


def test_secrets_are_redacted_in_the_stored_report(client):
    report = _scan(client).json()["report"]
    secret = next(f for f in report["findings"] if f["category"] == "secret")
    assert "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" not in str(report)
    assert "*" in secret["evidence"]


def test_scan_is_persisted_and_listable(client):
    scan_id = _scan(client).json()["id"]

    listing = client.get("/security/scans")
    assert listing.status_code == 200
    rows = listing.json()
    assert rows[0]["id"] == scan_id
    assert rows[0]["repo"] == "acme/demo"
    assert rows[0]["ref"] == "main"

    detail = client.get(f"/security/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["report"]["findings"]


def test_unknown_scan_returns_the_error_contract(client):
    resp = client.get("/security/scans/4242")
    assert resp.status_code == 404
    assert resp.json()["error"]["type"] == "not_found"


def test_plain_scan_route_returns_just_the_report(client):
    resp = client.post(
        "/security/scan", json={"repo": "acme/demo", "files": REPO_FILES}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "findings" in body and "id" not in body


def test_empty_repo_scans_clean(client):
    report = _scan(client, files=[]).json()["report"]
    assert report["findings"] == []
    assert report["summary"] == "No security findings."


def test_too_many_files_is_rejected(client, monkeypatch):
    _cap(monkeypatch, max_scan_files=1)
    resp = _scan(client)
    assert resp.status_code == 413
    assert resp.json()["error"]["type"] == "too_many_files"


def test_oversized_payload_is_rejected(client, monkeypatch):
    _cap(monkeypatch, max_scan_bytes=10)
    resp = _scan(client)
    assert resp.status_code == 413
    assert resp.json()["error"]["type"] == "scan_too_large"


def test_health_reports_triage_state(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert "security_triage" in body
