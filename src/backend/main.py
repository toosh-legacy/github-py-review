"""FastAPI application: routes, CORS, error handlers, DB startup.

    POST /security/scan              scan a repo's files for security findings
    POST /security/scan/full         same, but return the stored record (id + report)
    GET  /security/scans             list past security scans
    GET  /security/scans/{id}        full stored security report
    POST /review                     run a review, return the report
    POST /review/full                same, but return the stored record (id + report)
    GET  /health                     liveness + current LLM mode
    GET  /reviews                    list past reviews
    GET  /reviews/{id}               full stored report
    POST /reviews/{id}/post-comment  explicit, human-triggered write path

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
    PostCommentRequest,
    PostCommentResponse,
    Report,
    ReviewRecord,
    ReviewRequest,
    ReviewSummary,
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


app = FastAPI(title="Repo Security Scanner", version="2.0.0", lifespan=lifespan)

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
    # Report the reviewer actually in use (mock | local | openai), not a guess.
    return {
        "status": "ok",
        "llm_mode": settings.active_backend,
        "security_triage": settings.security_triage,
    }


# --------------------------------------------------------------------------- #
# Security scanning — the primary flow. Detection is done by tools (secret
# rules, OSV, bandit, eslint-plugin-security); the LLM only triages.
# --------------------------------------------------------------------------- #
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


@app.post("/review", response_model=Report)
def review(request: ReviewRequest, db: Session = Depends(get_db)) -> Report:
    """Review a PR URL or a pasted diff. Returns the report contract."""
    return service.create_review(db, request).report


@app.post("/review/full", response_model=ReviewRecord)
def review_full(request: ReviewRequest, db: Session = Depends(get_db)) -> ReviewRecord:
    """Same as /review but returns the stored record (id + report).

    Convenience for clients (Streamlit, extension) that need the review id to
    later call the post-comment route.
    """
    return service.create_review(db, request)


@app.get("/reviews", response_model=list[ReviewSummary])
def reviews(db: Session = Depends(get_db)) -> list[ReviewSummary]:
    return service.list_reviews(db)


@app.get("/reviews/{review_id}", response_model=ReviewRecord)
def review_by_id(review_id: int, db: Session = Depends(get_db)) -> ReviewRecord:
    return service.get_review(db, review_id)


@app.post("/reviews/{review_id}/post-comment", response_model=PostCommentResponse)
def post_comment(
    review_id: int,
    body: PostCommentRequest,
    db: Session = Depends(get_db),
) -> PostCommentResponse:
    """Explicit, human-triggered write path. NOT an agent tool — the agent graph
    has no ability to post, merge, or modify anything."""
    url = service.post_comment(db, review_id, body.pr_url)
    return PostCommentResponse(comment_url=url)
