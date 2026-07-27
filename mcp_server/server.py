"""MCP server exposing the two review tools.

Run standalone:  python -m mcp_server.server

Requires the `mcp` package (optional dependency). The same tool logic is used
directly by the FastAPI request path via `tools.py`; this module just makes the
tools available over the MCP protocol.
"""
from __future__ import annotations

from .tools import fetch_diff_tool, repo_context_search


def build_server():
    from mcp.server.fastmcp import FastMCP  # lazy: optional dependency

    mcp = FastMCP("code-review-copilot")

    @mcp.tool()
    def fetch_diff(pr_url: str) -> str:
        """Fetch the unified diff for a GitHub pull request URL."""
        return fetch_diff_tool(pr_url)

    @mcp.tool()
    def repo_context(query: str, k: int = 4) -> str:
        """Search indexed repository context relevant to a query."""
        return repo_context_search(query, k=k)

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
