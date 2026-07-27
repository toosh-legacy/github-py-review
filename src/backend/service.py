"""Review orchestration + persistence.

Sits between the HTTP routes and the agent: resolves the diff, enforces the
size guardrails, runs the graph, and stores the result. The only place that
touches both the agent and the database.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.diff_utils import parse_unified_diff
from agent.graph import run_debug_file, run_review_graph
from config import settings
from database.models import Review
from github_client.diff import fetch_diff_from_url
from schemas import (
    DebugFileRequest,
    Report,
    ReviewRecord,
    ReviewRequest,
    ReviewSummary,
    ScanRepoRequest,
    ScanRepoResponse,
)

from .errors import APIError


def _guard_diff(diff: str) -> None:
    if len(diff.encode("utf-8")) > settings.max_diff_bytes:
        raise APIError(
            413,
            "diff_too_large",
            f"diff exceeds MAX_DIFF_BYTES ({settings.max_diff_bytes} bytes)",
        )
    py_files = [f for f in parse_unified_diff(diff) if f.is_python]
    if len(py_files) > settings.max_files:
        raise APIError(
            413,
            "too_many_files",
            f"diff touches {len(py_files)} Python files (MAX_FILES={settings.max_files})",
        )


def _to_record(row: Review) -> ReviewRecord:
    return ReviewRecord(
        id=row.id,
        source=row.source,
        summary=row.summary,
        issue_count=row.issue_count,
        created_at=row.created_at,
        report=Report.model_validate(row.report),
    )


def create_review(db: Session, request: ReviewRequest) -> ReviewRecord:
    # Resolve the diff (fetching from GitHub for the URL path) before guarding,
    # so oversized PRs are rejected before any LLM work.
    if request.pr_url:
        diff = fetch_diff_from_url(request.pr_url)
        source, pr_url = "url", request.pr_url
    else:
        diff = request.diff or ""
        source, pr_url = "diff", None

    _guard_diff(diff)

    # Run the LangGraph agent (static analysis + LLM reviewer + aggregate).
    report = run_review_graph(diff=diff, pr_url=None)

    row = Review(
        source=source,
        pr_url=pr_url,
        summary=report.summary,
        issue_count=len(report.issues),
        report=report.model_dump(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_record(row)


def _guard_content(content: str) -> None:
    if len(content.encode("utf-8")) > settings.max_diff_bytes:
        raise APIError(
            413,
            "file_too_large",
            f"file exceeds MAX_DIFF_BYTES ({settings.max_diff_bytes} bytes)",
        )


def debug_file(db: Session, request: DebugFileRequest) -> ReviewRecord:
    """Debug one whole file (repo-scan flow) and persist it as a review.

    Stored with source="file" and no pr_url — the post-comment path only makes
    sense for PR-sourced reviews, so a file debug can never be posted.
    """
    _guard_content(request.content)

    report = run_debug_file(path=request.path, content=request.content)

    row = Review(
        source="file",
        pr_url=None,
        summary=report.summary,
        issue_count=len(report.issues),
        report=report.model_dump(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_record(row)


def scan_repo(request: ScanRepoRequest) -> ScanRepoResponse:
    """Index a repo's Python files for debug context (best-effort RAG).

    No-op (indexed=0, rag_available=false) when chromadb isn't installed, so
    the endpoint always succeeds and the caller can degrade gracefully.
    """
    from rag.indexer import index_files, rag_available

    pairs = [(f.path, f.content) for f in request.files if f.path.endswith(".py")]
    indexed = index_files(pairs)
    return ScanRepoResponse(indexed=indexed, rag_available=rag_available())


def list_reviews(db: Session, limit: int = 50) -> list[ReviewSummary]:
    rows = db.scalars(
        select(Review).order_by(Review.id.desc()).limit(limit)
    ).all()
    return [
        ReviewSummary(
            id=r.id,
            source=r.source,
            summary=r.summary,
            issue_count=r.issue_count,
            created_at=r.created_at,
        )
        for r in rows
    ]


def get_review(db: Session, review_id: int) -> ReviewRecord:
    row = db.get(Review, review_id)
    if row is None:
        raise APIError(404, "not_found", f"review {review_id} not found")
    return _to_record(row)


def post_comment(db: Session, review_id: int, pr_url: str | None) -> str:
    """Explicit, human-triggered: post a stored review to its PR. Outside the graph."""
    from github_client.comment import post_pr_comment

    row = db.get(Review, review_id)
    if row is None:
        raise APIError(404, "not_found", f"review {review_id} not found")
    target = pr_url or row.pr_url
    if not target:
        raise APIError(
            400,
            "no_pr_url",
            "this review has no PR URL; provide 'pr_url' in the request body",
        )
    return post_pr_comment(target, Report.model_validate(row.report))
