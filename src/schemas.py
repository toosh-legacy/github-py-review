"""The shared data contract. Every package in the repo imports from here.

`Report` is the frozen output shape: the backend returns it, the database
stores it, and Streamlit, the Chrome extension, and the evaluation harness all
parse it. Change it and you change all of them at once — which is the point.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["high", "medium", "low"]


class Issue(BaseModel):
    file: str
    line_start: int
    line_end: int
    severity: Severity
    description: str
    suggested_fix: str = ""


class Report(BaseModel):
    summary: str
    issues: list[Issue] = Field(default_factory=list)
    tokens_used: int = 0
    latency_ms: int = 0


class ReviewRequest(BaseModel):
    """Input to POST /review. Exactly one of pr_url / diff must be provided."""

    pr_url: str | None = None
    diff: str | None = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> ReviewRequest:
        provided = [v for v in (self.pr_url, self.diff) if v]
        if len(provided) != 1:
            raise ValueError("provide exactly one of 'pr_url' or 'diff'")
        return self


class DebugFileRequest(BaseModel):
    """Input to POST /debug/file: one whole file to debug (repo-scan flow).

    Unlike ReviewRequest this is not a diff — `content` is the entire file. The
    optional `repo` is context (e.g. owner/repo) for display/history only.
    """

    path: str
    content: str
    repo: str | None = None


class ScanRepoFile(BaseModel):
    path: str
    content: str


class ScanRepoRequest(BaseModel):
    """Body for POST /scan/repo: whole files to index for debug context."""

    repo: str | None = None
    files: list[ScanRepoFile] = Field(default_factory=list)


class ScanRepoResponse(BaseModel):
    indexed: int
    rag_available: bool


class ReviewSummary(BaseModel):
    """Row returned by GET /reviews (list view)."""

    id: int
    source: str
    summary: str
    issue_count: int
    created_at: datetime


class ReviewRecord(ReviewSummary):
    """Full stored review returned by GET /reviews/{id}."""

    report: Report


class PostCommentRequest(BaseModel):
    """Body for POST /reviews/{id}/post-comment. pr_url is optional when the
    stored review already came from a PR URL."""

    pr_url: str | None = None


class PostCommentResponse(BaseModel):
    comment_url: str
