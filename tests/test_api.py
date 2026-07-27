"""Contract + integration tests for the HTTP surface."""


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["llm_mode"] in {"mock", "local", "openai"}


def test_review_returns_report_contract(client, sample_diff):
    r = client.post("/review", json={"diff": sample_diff})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"summary", "issues", "tokens_used", "latency_ms"}
    assert isinstance(body["issues"], list) and body["issues"]
    issue = body["issues"][0]
    assert set(issue) == {
        "file",
        "line_start",
        "line_end",
        "severity",
        "description",
        "suggested_fix",
    }
    assert issue["severity"] in {"high", "medium", "low"}
    assert body["tokens_used"] == 0  # mock reviewer spends nothing


def test_review_persists_and_history_reads(client, sample_diff):
    created = client.post("/review/full", json={"diff": sample_diff}).json()
    rid = created["id"]

    listing = client.get("/reviews").json()
    assert any(row["id"] == rid for row in listing)

    fetched = client.get(f"/reviews/{rid}").json()
    assert fetched["id"] == rid
    assert fetched["report"]["issues"] == created["report"]["issues"]


def test_missing_source_returns_uniform_error(client):
    r = client.post("/review", json={})
    assert r.status_code == 400
    assert set(r.json()["error"]) == {"type", "message"}


def test_invalid_pr_url_rejected(client):
    # Malformed URL fails the regex before any network call.
    r = client.post("/review", json={"pr_url": "not-a-github-pr-url"})
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "invalid_pr_url"


def test_unknown_review_404(client):
    r = client.get("/reviews/9999")
    assert r.status_code == 404
    assert r.json()["error"]["type"] == "not_found"


def test_post_comment_requires_pr_url(client, sample_diff):
    # A diff-sourced review has no PR URL; posting without one is rejected
    # before any network call.
    rid = client.post("/review/full", json={"diff": sample_diff}).json()["id"]
    r = client.post(f"/reviews/{rid}/post-comment", json={})
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "no_pr_url"
