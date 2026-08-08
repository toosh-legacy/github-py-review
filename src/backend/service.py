"""Scan/review orchestration + persistence.

Sits between the HTTP routes and the agents: resolves the input, enforces the
size guardrails, runs the graph, and stores the result. The only place that
touches both an agent and the database.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.diff_utils import parse_unified_diff
from agent.graph import run_review_graph
from config import settings
from database.models import Review, SecurityScan
from github_client.diff import fetch_diff_from_url
from schemas import (
    Report,
    ReviewRecord,
    ReviewRequest,
    ReviewSummary,
    SecurityReport,
    SecurityScanRecord,
    SecurityScanRequest,
    SecurityScanSummary,
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


def _guard_scan(request: SecurityScanRequest) -> None:
    """Bound a repo scan before any tool runs.

    The extension posts whole file contents, so an unbounded request is both a
    memory problem and a way to make the backend do a monorepo's worth of
    subprocess work on someone else's behalf.
    """
    if len(request.files) > settings.max_scan_files:
        raise APIError(
            413,
            "too_many_files",
            f"scan submitted {len(request.files)} files "
            f"(MAX_SCAN_FILES={settings.max_scan_files})",
        )
    total = sum(len(f.content.encode("utf-8", "replace")) for f in request.files)
    if total > settings.max_scan_bytes:
        raise APIError(
            413,
            "scan_too_large",
            f"scan payload is {total} bytes (MAX_SCAN_BYTES={settings.max_scan_bytes})",
        )


def _to_scan_record(row: SecurityScan) -> SecurityScanRecord:
    return SecurityScanRecord(
        id=row.id,
        repo=row.repo,
        ref=row.ref,
        summary=row.summary,
        finding_count=row.finding_count,
        created_at=row.created_at,
        report=SecurityReport.model_validate(row.report),
    )


def security_scan(db: Session, request: SecurityScanRequest) -> SecurityScanRecord:
    """Run the three detectors plus LLM triage over a repo's files, and store it."""
    from agent.security_graph import run_security_scan

    _guard_scan(request)

    report = run_security_scan(
        files=[(f.path, f.content) for f in request.files],
        repo=request.repo,
    )

    row = SecurityScan(
        repo=request.repo,
        ref=request.ref,
        summary=report.summary,
        finding_count=len(report.findings),
        report=report.model_dump(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_scan_record(row)


def list_security_scans(db: Session, limit: int = 50) -> list[SecurityScanSummary]:
    rows = db.scalars(
        select(SecurityScan).order_by(SecurityScan.id.desc()).limit(limit)
    ).all()
    return [
        SecurityScanSummary(
            id=r.id,
            repo=r.repo,
            ref=r.ref,
            summary=r.summary,
            finding_count=r.finding_count,
            created_at=r.created_at,
        )
        for r in rows
    ]


def get_security_scan(db: Session, scan_id: int) -> SecurityScanRecord:
    row = db.get(SecurityScan, scan_id)
    if row is None:
        raise APIError(404, "not_found", f"security scan {scan_id} not found")
    return _to_scan_record(row)


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
