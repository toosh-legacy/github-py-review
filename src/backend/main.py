"""FastAPI application: routes, CORS, error handlers, DB startup.

    POST /review                     run a review, return the report
    POST /review/full                same, but return the stored record (id + report)
    POST /debug/file                 debug one whole file, return the report
    POST /debug/file/full            same, but return the stored record (id + report)
    POST /scan/repo                  index a repo's files for debug context (RAG)
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
    DebugFileRequest,
    PostCommentRequest,
    PostCommentResponse,
    Report,
    ReviewRecord,
    ReviewRequest,
    ReviewSummary,
    ScanRepoRequest,
    ScanRepoResponse,
)

from . import service
from .errors import install_error_handlers


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI Code Review Copilot", version="1.0.0", lifespan=lifespan)

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
    return {"status": "ok", "llm_mode": settings.active_backend}


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


@app.post("/debug/file", response_model=Report)
def debug_file(request: DebugFileRequest, db: Session = Depends(get_db)) -> Report:
    """Debug one whole file (repo-scan → pick-a-file flow). Returns the report."""
    return service.debug_file(db, request).report


@app.post("/debug/file/full", response_model=ReviewRecord)
def debug_file_full(
    request: DebugFileRequest, db: Session = Depends(get_db)
) -> ReviewRecord:
    """Same as /debug/file but returns the stored record (id + report)."""
    return service.debug_file(db, request)


@app.post("/scan/repo", response_model=ScanRepoResponse)
def scan_repo(request: ScanRepoRequest) -> ScanRepoResponse:
    """Index a repo's Python files for debug context (best-effort RAG)."""
    return service.scan_repo(request)


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
