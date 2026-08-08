"""FastAPI application: routes, CORS, error handlers, DB startup.

    POST /security/scan              scan a repo's files, return the report
    POST /security/scan/full         same, but return the stored record (id + report)
    GET  /security/scans             list past scans
    GET  /security/scans/{id}        full stored report
    GET  /health                     liveness + which backend triage would use

Every route is read-only with respect to the caller's repository: files arrive
in the request body and the server never fetches, writes, or pushes anything.

Run with:  uvicorn backend.main:app --port 8001   (from the repo root)
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from config import settings
from database.session import get_db, init_db
from schemas import (
    SecurityReport,
    SecurityScanRecord,
    SecurityScanRequest,
    SecurityScanSummary,
)

from . import service
from .errors import install_error_handlers


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Repo Security Scanner",
    version="1.0.0",
    summary=(
        "Secrets, vulnerable dependencies and unsafe code — "
        "found by tools, triaged by an LLM."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

install_error_handlers(app)


@app.get("/health")
def health() -> dict[str, object]:
    # Report the backend actually in use, not a guess. "mock" means no model is
    # configured — detection still runs, triage is skipped.
    return {
        "status": "ok",
        "llm_mode": settings.active_backend,
        "security_triage": settings.security_triage,
    }


@app.post("/security/scan", response_model=SecurityReport)
def security_scan(
    request: SecurityScanRequest, db: Session = Depends(get_db)
) -> SecurityReport:
    """Scan a repository's files for secrets, vulnerable deps, and unsafe code."""
    return service.security_scan(db, request).report


@app.post("/security/scan/full", response_model=SecurityScanRecord)
def security_scan_full(
    request: SecurityScanRequest, db: Session = Depends(get_db)
) -> SecurityScanRecord:
    """Same as /security/scan but returns the stored record (id + report)."""
    return service.security_scan(db, request)


@app.get("/security/scans", response_model=list[SecurityScanSummary])
def security_scans(db: Session = Depends(get_db)) -> list[SecurityScanSummary]:
    return service.list_security_scans(db)


@app.get("/security/scans/{scan_id}", response_model=SecurityScanRecord)
def security_scan_by_id(
    scan_id: int, db: Session = Depends(get_db)
) -> SecurityScanRecord:
    return service.get_security_scan(db, scan_id)
