"""Posting a stored report to a GitHub PR as a comment.

This is the ONLY write path in the system, and it lives entirely outside the
agent graph. The agent can never call it — it is reachable only through the
explicit, authenticated `POST /reviews/{id}/post-comment` route a human triggers.
"""
from __future__ import annotations

import httpx

from backend.errors import APIError
from config import settings
from schemas import Report

from .diff import parse_pr_url

_SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def render_markdown(report: Report) -> str:
    lines = ["## 🤖 AI Code Review Copilot", "", report.summary, ""]
    for i in report.issues:
        emoji = _SEVERITY_EMOJI.get(i.severity, "⚪")
        lines.append(
            f"- {emoji} **{i.severity}** `{i.file}:{i.line_start}` — {i.description}"
        )
        if i.suggested_fix:
            lines.append(f"  - _Suggested fix:_ {i.suggested_fix}")
    lines += ["", f"_Reviewed {len(report.issues)} finding(s) · "
              f"{report.tokens_used} tokens · {report.latency_ms} ms._"]
    return "\n".join(lines)


def post_pr_comment(pr_url: str, report: Report) -> str:
    """Post the report as a comment on the PR. Returns the comment URL."""
    if not settings.github_token:
        raise APIError(
            400, "missing_github_token", "GITHUB_TOKEN with write scope is required"
        )
    owner, repo, number = parse_pr_url(pr_url)
    api = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}/comments"
    headers = {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
    }
    try:
        resp = httpx.post(
            api, headers=headers, json={"body": render_markdown(report)}, timeout=30
        )
    except httpx.HTTPError as exc:
        raise APIError(502, "github_error", f"failed to reach GitHub: {exc}") from exc
    if resp.status_code == 403:
        raise APIError(
            502, "github_forbidden", "token lacks write scope or is rate limited"
        )
    if resp.status_code >= 400:
        raise APIError(502, "github_error", f"GitHub returned {resp.status_code}")
    return resp.json().get("html_url", "")
