"""The code-review worker nodes: static analysis (ruff), LLM review, aggregation.

Kept as plain functions taking and returning ordinary values, so they are
trivial to unit-test in isolation; `graph.py` wires them into LangGraph.
"""
from __future__ import annotations

import json
import subprocess
import sys

from schemas import Issue

from .diff_utils import DiffFile, parse_unified_diff


def _is_syntax_error(finding: dict) -> bool:
    # Ruff reports syntax errors with a null `code` and a "SyntaxError: ..."
    # message (not the legacy E999 code), so match on that shape.
    return not (finding.get("code") or "") and (
        (finding.get("message") or "").startswith("SyntaxError")
    )


def _severity_for(code: str) -> str:
    if code.startswith("F"):  # pyflakes: unused imports, undefined names, etc.
        return "medium"
    return "low"


def _run_ruff(path: str, content: str) -> list[dict]:
    """Run ruff on `content`, reporting under `path`. Returns raw JSON findings."""
    if not content.strip():
        return []
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--output-format=json",
                "--stdin-filename",
                path,
                "-",
            ],
            input=content,
            capture_output=True,
            # Not `text=True`: that decodes with the platform default (cp1252 on
            # Windows), and one non-ASCII byte in ruff's output kills the reader
            # thread and yields stdout=None with a zero exit code.
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if not (proc.stdout or "").strip():
        return []
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []


def _issues_for_file(df: DiffFile) -> list[Issue]:
    content, real_lines = df.reconstructed_new_content()
    findings = _run_ruff(df.path, content)
    added = df.added_line_numbers
    issues: list[Issue] = []
    for f in findings:
        code = f.get("code") or ""
        # A syntax error here is usually an artifact of reconstructing a partial
        # file from diff hunks, not a real defect in the author's file.
        if _is_syntax_error(f):
            continue
        loc = f.get("location") or {}
        row = loc.get("row")
        if not row or row - 1 >= len(real_lines):
            continue
        real = real_lines[row - 1]
        # Only report on lines the diff actually touched.
        if real not in added:
            continue
        end_loc = f.get("end_location") or {}
        end_row = end_loc.get("row", row)
        end_real = (
            real_lines[end_row - 1]
            if end_row and end_row - 1 < len(real_lines)
            else real
        )
        fix = f.get("fix") or {}
        suggested = fix.get("message", "") if isinstance(fix, dict) else ""
        label = code or "ruff"
        severity = _severity_for(code)
        issues.append(
            Issue(
                file=df.path,
                line_start=real,
                line_end=max(real, end_real),
                severity=severity,
                description=f"{label}: {f.get('message', '').strip()}",
                suggested_fix=suggested,
            )
        )
    return issues


def run_static_analysis(diff: str) -> list[Issue]:
    """Run ruff over the Python files touched by a unified diff."""
    files = [df for df in parse_unified_diff(diff) if df.is_python]
    issues: list[Issue] = []
    for df in files:
        issues.extend(_issues_for_file(df))
    return issues


def llm_review_files(files: list[DiffFile]) -> tuple[list[Issue], int]:
    """Propose issues: run the LLM reviewer over each changed Python file.

    This is the recall half of the review. Its output is *candidate* findings —
    `verify_llm_findings` decides which of them survive. Uses the mock reviewer
    when no backend is configured (so this runs offline), chosen lazily to avoid
    importing the OpenAI SDK in mock mode.
    """
    from llm_model.base import get_review_llm

    llm = get_review_llm()
    issues: list[Issue] = []
    tokens = 0
    for df in files:
        file_issues, file_tokens = llm.review_file(df)
        issues.extend(file_issues)
        tokens += file_tokens
    return issues, tokens


def verify_llm_findings(
    files: list[DiffFile], issues: list[Issue]
) -> tuple[list[Issue], int]:
    """Audit proposed issues: the precision half of the review.

    Only the LLM's proposals go through here. Ruff's findings are deterministic
    and already precise, so putting them in front of a model could only lose
    true positives.
    """
    from llm_model.verify import verify_issues

    return verify_issues(files, issues)


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def aggregate_findings(issues: list[Issue]) -> tuple[list[Issue], str]:
    """De-duplicate, sort by severity, and produce a human summary."""
    seen: set[tuple] = set()
    unique: list[Issue] = []
    for i in issues:
        key = (i.file, i.line_start, i.line_end, i.severity, i.description)
        if key in seen:
            continue
        seen.add(key)
        unique.append(i)

    unique.sort(key=lambda i: (_SEVERITY_ORDER.get(i.severity, 3), i.file, i.line_start))

    if not unique:
        return unique, "No issues found."
    counts = {
        s: sum(1 for i in unique if i.severity == s)
        for s in ("high", "medium", "low")
    }
    files = len({i.file for i in unique})
    summary = (
        f"Found {len(unique)} issue(s) across {files} file(s): "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low."
    )
    return unique, summary
