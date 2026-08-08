"""The shared data contract. Every package in the repo imports from here.

`SecurityReport` is the frozen output shape: the scan graph returns it, the CLI
renders it, `--format json` serialises it verbatim, and the evaluation harness
scores it. Change it and you change all of them at once — which is the point.

Detector provenance is kept separate from the LLM's triage on purpose: what a
tool found is a fact, and what the model thinks of it is an opinion.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "low"]

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
    # Findings dropped by .secscanignore. Reported so a suppression file that
    # silences everything is visible rather than silent.
    suppressed: int = 0
    # Detectors that could not run (bandit missing, OSV unreachable, ...). Shown
    # to the user: a scan with a dead detector is not a clean scan.
    degraded: list[str] = Field(default_factory=list)
    tokens_used: int = 0
    latency_ms: int = 0
