"""Read-only GitHub access: fetch the unified diff for a pull request URL."""
from __future__ import annotations

import re

import httpx

from backend.errors import APIError
from config import settings

PR_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)")


def parse_pr_url(pr_url: str) -> tuple[str, str, str]:
    """Split a PR URL into (owner, repo, number). Raises on anything else."""
    m = PR_RE.search(pr_url)
    if not m:
        raise APIError(
            400, "invalid_pr_url", "expected a https://github.com/<o>/<r>/pull/<n> URL"
        )
    return m.group(1), m.group(2), m.group(3)


def fetch_diff_from_url(pr_url: str) -> str:
    """Fetch the unified diff for a GitHub PR URL via the GitHub API."""
    owner, repo, number = parse_pr_url(pr_url)
    api = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
    headers = {"Accept": "application/vnd.github.v3.diff"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    try:
        resp = httpx.get(api, headers=headers, timeout=30, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise APIError(502, "github_error", f"failed to reach GitHub: {exc}") from exc
    if resp.status_code == 404:
        raise APIError(404, "pr_not_found", f"PR not found: {pr_url}")
    if resp.status_code == 403:
        raise APIError(
            502,
            "github_rate_limited",
            "GitHub rate limit or auth error — set GITHUB_TOKEN",
        )
    if resp.status_code >= 400:
        raise APIError(502, "github_error", f"GitHub returned {resp.status_code}")
    return resp.text
