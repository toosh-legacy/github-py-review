"""Scan orchestration + persistence.

Sits between the HTTP routes and the agent: enforces the size guardrails, runs
the graph, and stores the result. The only place that touches both the agent and
the database.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from config import settings
from database.models import SecurityScan
from schemas import (
    SecurityReport,
    SecurityScanRecord,
    SecurityScanRequest,
    SecurityScanSummary,
)

from .errors import APIError


def _guard_scan(request: SecurityScanRequest) -> None:
    """Bound a scan before any tool runs.

    The caller posts whole file contents, so an unbounded request is both a
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


def _to_record(row: SecurityScan) -> SecurityScanRecord:
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
    return _to_record(row)


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
    return _to_record(row)
