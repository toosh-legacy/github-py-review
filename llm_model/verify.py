"""The verifier: a second pass that must confirm a finding before it ships.

A single small local model asked to "review this code" over-reports badly — it
will find something to say about every change, which is exactly the failure the
false-positive measurement is designed to catch. Splitting the job into two
roles fixes most of it:

    proposer (base.ChatReviewLLM) — recall: cast a wide net over changed lines
    verifier (here)               — precision: is this candidate really a defect?

The verifier sees one issue at a time against the full file, and is asked a
narrow yes/no question rather than an open-ended one. That is a much easier
judgement for a 7B-class model than open-ended review, and it is where most of
the precision comes from.

A second guard runs alongside it: `validate_fix` discards any `suggested_fix`
that isn't syntactically valid Python, so a hallucinated patch can never reach
the user as something to paste in — enforced mechanically, not trusted to the
model.

Runs as the `verify_findings` node of the agent graph, via
`agent/nodes.py::verify_llm_findings`. Turn it off with `VERIFY_FINDINGS=0`.
"""
from __future__ import annotations

import ast
import re

from agent.diff_utils import DiffFile
from config import settings
from schemas import Issue

from .base import ChatReviewLLM, get_review_llm
from .prompts import VERIFY_SYSTEM_PROMPT, VERIFY_USER_PROMPT

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def passes_severity_floor(issue: Issue) -> bool:
    """True when `issue` is at or above the configured `MIN_SEVERITY`."""
    floor = _SEVERITY_ORDER.get(settings.min_severity, 2)
    return _SEVERITY_ORDER.get(issue.severity, 2) <= floor


# A suggested_fix may legitimately be prose ("close the file in a finally
# block") rather than code. We only syntax-check things that look like code, so
# prose advice isn't thrown away for failing to be Python.
_FENCE_RE = re.compile(r"```(?:python|py|diff)?\n?(.*?)```", re.DOTALL)
_CODE_HINT_RE = re.compile(
    r"^\s*(?:[-+@]|def |class |if |for |while |with |try:|import |from )", re.M
)


def validate_fix(suggested_fix: str) -> str:
    """Return `suggested_fix` if it is safe to show, else "".

    A fix that doesn't parse is worse than no fix: it looks authoritative and
    breaks the file if pasted. Prose advice passes through untouched; anything
    that looks like code must parse as Python before we keep it.
    """
    fix = suggested_fix.strip()
    if not fix:
        return ""

    fenced = _FENCE_RE.search(fix)
    body = fenced.group(1) if fenced else fix

    if not _CODE_HINT_RE.search(body):
        return fix  # prose advice — nothing to syntax-check

    # Diff-style fixes: strip the markers to recover the intended new code.
    lines = body.splitlines()
    if any(ln.startswith(("+", "-", "@@")) for ln in lines):
        kept = [ln[1:] for ln in lines if ln.startswith("+")]
        if not kept:
            return ""
        body = "\n".join(kept)

    # A fix is usually a fragment lifted out of its enclosing block, so it can
    # be legitimately over-indented. Normalise before parsing.
    try:
        body = _dedent_to_zero(body)
        ast.parse(body)
    except (SyntaxError, ValueError):
        return ""
    return fix


def _dedent_to_zero(body: str) -> str:
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty fix")
    indent = min(len(ln) - len(ln.lstrip()) for ln in lines)
    return "\n".join(ln[indent:] for ln in body.splitlines())


def _verify_one(
    llm: ChatReviewLLM, df: DiffFile, issue: Issue
) -> tuple[bool, int]:
    """Ask the model whether `issue` is a real defect. Returns (keep, tokens)."""
    user = VERIFY_USER_PROMPT.format(
        path=issue.file,
        source=llm.annotated_source(df),
        line=issue.line_start,
        severity=issue.severity,
        description=issue.description,
    )
    try:
        data, tokens = llm.chat_json(VERIFY_SYSTEM_PROMPT, user)
    except Exception:  # noqa: BLE001
        # The verifier is a filter, not the product. If it is unavailable we
        # keep the proposal rather than silently dropping real findings.
        return True, 0

    if data is None:
        return True, tokens  # unparseable verdict is not evidence against
    return bool(data.get("verdict") is True), tokens


def verify_issues(files: list[DiffFile], issues: list[Issue]) -> tuple[list[Issue], int]:
    """Filter proposed issues down to the ones that survive audit.

    Applies, in order: the severity floor, the verifier (when enabled and a real
    reviewer is configured), and `validate_fix` on every survivor.
    """
    kept = [i for i in issues if passes_severity_floor(i)]

    llm = get_review_llm() if kept else None
    tokens = 0
    if settings.verify_findings and isinstance(llm, ChatReviewLLM):
        by_path = {df.path: df for df in files}
        audited: list[Issue] = []
        for issue in kept:
            df = by_path.get(issue.file)
            if df is None:  # nothing to show the verifier; keep as-is
                audited.append(issue)
                continue
            keep, used = _verify_one(llm, df, issue)
            tokens += used
            if keep:
                audited.append(issue)
        kept = audited

    for issue in kept:
        issue.suggested_fix = validate_fix(issue.suggested_fix)
    return kept, tokens
