"""The two MCP tools' logic: fetch a PR diff, and search indexed repo context.

Both are thin wrappers over the real implementations (`github_client`, `rag`)
so the FastAPI path can call those directly without going through MCP. Neither
tool can modify anything — read-only by design.
"""
from __future__ import annotations

from github_client.diff import fetch_diff_from_url


def fetch_diff_tool(pr_url: str) -> str:
    """Fetch the unified diff for a GitHub pull request URL."""
    return fetch_diff_from_url(pr_url)


def repo_context_search(query: str, k: int = 4) -> str:
    """Return repo context relevant to `query` from the RAG index.

    Degrades to an empty string when the RAG store is unavailable (e.g.
    chromadb not installed), so callers never break.
    """
    try:
        from rag.indexer import search
    except Exception:  # noqa: BLE001
        return ""
    return search(query, k=k)
