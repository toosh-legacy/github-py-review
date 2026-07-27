"""RAG indexing + /scan/repo degrade gracefully without chromadb.

chromadb is an optional dependency. With it absent (the CI/default case), both
the indexer and the endpoint must no-op cleanly rather than error.
"""
from rag.indexer import index_files, rag_available


def test_index_files_noop_without_chromadb():
    # No chromadb installed → 0 indexed, and no exception.
    assert index_files([("a.py", "x = 1\n")]) == 0
    assert rag_available() is False


def test_scan_repo_route_degrades_gracefully(client):
    r = client.post(
        "/scan/repo",
        json={
            "repo": "me/proj",
            "files": [
                {"path": "a.py", "content": "x = 1\n"},
                {"path": "notes.txt", "content": "ignored"},
            ],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"indexed", "rag_available"}
    assert body["indexed"] == 0  # chromadb absent
    assert body["rag_available"] is False


def test_scan_repo_empty_files_ok(client):
    r = client.post("/scan/repo", json={"files": []})
    assert r.status_code == 200
    assert r.json()["indexed"] == 0
