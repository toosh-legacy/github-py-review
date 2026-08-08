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


# --------------------------------------------------------------------------- #
# Security scanning contract.
#
# Deliberately separate from `Report`/`Issue`: those describe "an LLM read your
# code and had an opinion". A security finding is produced by a *tool* (a
# gitleaks-style rule, the OSV vulnerability database, bandit, eslint), so it
# carries provenance — which detector fired, which rule, what the evidence was —
# and keeps that separate from the LLM's triage of it.
# --------------------------------------------------------------------------- #
FindingCategory = Literal["secret", "dependency", "code"]

# How much has to go right for an attacker before this finding bites.
#   direct      — exploitable as it stands (a live key in a public repo)
#   conditional — needs a precondition (reachable route, attacker-controlled input)
#   theoretical — real weakness, no plausible path in this codebase
Exploitability = Literal["direct", "conditional", "theoretical"]


class SecurityFinding(BaseModel):
    """One security finding, from detection through triage.

    Fields above the divider are what a detector found and are never rewritten
    by the model. Fields below are the LLM's triage and may be empty when no
    reviewer is configured (a deterministic fallback fills in what it can).
    """

    # --- detector output: facts, not opinions ---
    id: str  # stable hash; how triage refers back to a finding
    category: FindingCategory
    detector: str  # "gitleaks-regex" | "entropy" | "osv" | "bandit" | ...
    rule_id: str  # "aws-access-token" | "CVE-2024-1234" | "B608" | ...
    title: str
    file: str
    line_start: int = 0
    line_end: int = 0
    detector_severity: Severity = "medium"
    evidence: str = ""  # redacted — never the raw secret
    references: list[str] = Field(default_factory=list)

    # --- triage output ---
    severity: Severity = "medium"  # re-ranked; starts equal to detector_severity
    exploitability: Exploitability | None = None
    explanation: str = ""
    suggested_fix: str = ""
    # Ids of findings folded into this one (e.g. bandit and a secret rule both
    # firing on the same line). The merged findings are not listed separately.
    merged_from: list[str] = Field(default_factory=list)
    triaged: bool = False


class SecurityReport(BaseModel):
    summary: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    counts_by_category: dict[str, int] = Field(default_factory=dict)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    scanned_files: int = 0
    skipped_files: int = 0
    # Detectors that could not run (bandit missing, OSV unreachable, ...). Shown
    # to the user: a scan with a dead detector is not a clean scan.
    degraded: list[str] = Field(default_factory=list)
    tokens_used: int = 0
    latency_ms: int = 0


class ScanFile(BaseModel):
    path: str
    content: str


class SecurityScanRequest(BaseModel):
    """Body for POST /security/scan: repo files to scan, sent by the extension."""

    repo: str | None = None
    ref: str | None = None
    files: list[ScanFile] = Field(default_factory=list)


class SecurityScanSummary(BaseModel):
    """Row returned by GET /security/scans (list view)."""

    id: int
    repo: str | None
    ref: str | None
    summary: str
    finding_count: int
    created_at: datetime


class SecurityScanRecord(SecurityScanSummary):
    """Full stored scan returned by GET /security/scans/{id}."""

    report: SecurityReport
