"""The LangGraph security-scan agent.

    START → collect_files → scan_secrets → scan_dependencies → scan_code
          → redact_findings → triage_findings → aggregate → END

The three scan nodes are the detection layer and contain no model calls at all —
they are regex/entropy rules, manifest parsing against the OSV database, and two
real linters. `triage_findings` is the only node that talks to an LLM, and it
can only narrow, reorder, or annotate what the detectors produced.

**Authorization boundary:** unchanged from the review graph. No node here can
post, merge, write to a repository, or modify anything; the agent returns a
`SecurityReport` and nothing else. Files arrive as request payload — the graph
never fetches them, so it has no network reach into the user's repositories.
"""
from __future__ import annotations

import time
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from schemas import SecurityFinding, SecurityReport
from security.common import is_scannable, looks_binary, snippet


class SecurityState(TypedDict, total=False):
    repo: str | None
    files: list[tuple[str, str]]
    findings: list[SecurityFinding]
    degraded: list[str]
    scanned_files: int
    skipped_files: int
    tokens_used: int
    summary: str
    counts_by_category: dict[str, int]
    counts_by_severity: dict[str, int]


def _collect(state: SecurityState) -> SecurityState:
    """Drop what no detector can use: vendored trees, binaries, junk paths."""
    incoming = state.get("files", [])
    keep = [
        (p, c) for p, c in incoming if is_scannable(p) and not looks_binary(c)
    ]
    return {
        "files": keep,
        "findings": [],
        "degraded": [],
        "tokens_used": 0,
        "scanned_files": len(keep),
        "skipped_files": len(incoming) - len(keep),
    }


def _scan_secrets(state: SecurityState) -> SecurityState:
    from security.secrets_scan import scan_files

    found = scan_files(state.get("files", []))
    return {"findings": state.get("findings", []) + found}


def _scan_dependencies(state: SecurityState) -> SecurityState:
    from config import settings
    from security.deps_scan import scan_dependencies

    found, degraded = scan_dependencies(
        state.get("files", []), offline=settings.security_offline
    )
    return {
        "findings": state.get("findings", []) + found,
        "degraded": state.get("degraded", []) + degraded,
    }


def _scan_code(state: SecurityState) -> SecurityState:
    from security.code_scan import scan_code

    found, degraded = scan_code(state.get("files", []))
    return {
        "findings": state.get("findings", []) + found,
        "degraded": state.get("degraded", []) + degraded,
    }


def _redact(state: SecurityState) -> SecurityState:
    """Mask credentials in every finding before anything leaves the scanner.

    The secret detector redacts its own evidence, but bandit and eslint quote
    raw source lines — and a hardcoded token is exactly the kind of line they
    quote. This node is what makes "the raw secret is never stored and never
    sent to the model" true of the whole pipeline rather than of one detector.
    """
    from security.secrets_scan import scrub

    cleaned = [
        f.model_copy(
            update={
                "evidence": scrub(f.evidence),
                "explanation": scrub(f.explanation),
            }
        )
        for f in state.get("findings", [])
    ]
    return {"findings": cleaned}


def _build_contexts(
    files: list[tuple[str, str]], findings: list[SecurityFinding]
) -> dict[str, str]:
    """A few lines of real source per finding, so triage judges the code.

    Dependency findings point at a manifest line, which tells the model nothing
    it doesn't already have from the package name and version — so they are
    skipped rather than padding every prompt.
    """
    from security.secrets_scan import scrub

    by_path = {p: c for p, c in files}
    contexts: dict[str, str] = {}
    for f in findings:
        if f.category == "dependency" or not f.line_start:
            continue
        content = by_path.get(f.file)
        if content is None:
            continue
        # Scrubbed: the model is being asked to rank a leaked credential, which
        # it can do perfectly well without being shown the credential.
        contexts[f.id] = scrub(
            snippet(content.splitlines(), f.line_start, context=3)
        )
    return contexts


def _triage(state: SecurityState) -> SecurityState:
    from security.triage import triage

    findings = state.get("findings", [])
    contexts = _build_contexts(state.get("files", []), findings)
    ranked, tokens = triage(findings, contexts, repo=state.get("repo"))
    return {
        "findings": ranked,
        "tokens_used": state.get("tokens_used", 0) + tokens,
    }


_CATEGORY_LABEL = {
    "secret": ("exposed secret", "exposed secrets"),
    "dependency": ("vulnerable dependency", "vulnerable dependencies"),
    "code": ("unsafe code pattern", "unsafe code patterns"),
}


def _plural(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def _aggregate(state: SecurityState) -> SecurityState:
    findings = state.get("findings", [])
    by_category = {
        c: sum(1 for f in findings if f.category == c)
        for c in ("secret", "dependency", "code")
    }
    by_severity = {
        s: sum(1 for f in findings if f.severity == s)
        for s in ("high", "medium", "low")
    }

    if not findings:
        summary = "No security findings."
    else:
        parts = [
            _plural(n, *_CATEGORY_LABEL[c]) for c, n in by_category.items() if n
        ]
        summary = (
            f"{_plural(len(findings), 'finding', 'findings')} "
            f"({by_severity['high']} high, {by_severity['medium']} medium, "
            f"{by_severity['low']} low): " + ", ".join(parts) + "."
        )
    return {
        "summary": summary,
        "counts_by_category": by_category,
        "counts_by_severity": by_severity,
    }


def build_security_graph():
    g = StateGraph(SecurityState)
    g.add_node("collect_files", _collect)
    g.add_node("scan_secrets", _scan_secrets)
    g.add_node("scan_dependencies", _scan_dependencies)
    g.add_node("scan_code", _scan_code)
    g.add_node("redact_findings", _redact)
    g.add_node("triage_findings", _triage)
    g.add_node("aggregate", _aggregate)

    g.add_edge(START, "collect_files")
    g.add_edge("collect_files", "scan_secrets")
    g.add_edge("scan_secrets", "scan_dependencies")
    g.add_edge("scan_dependencies", "scan_code")
    g.add_edge("scan_code", "redact_findings")
    g.add_edge("redact_findings", "triage_findings")
    g.add_edge("triage_findings", "aggregate")
    g.add_edge("aggregate", END)
    return g.compile()


_SECURITY_GRAPH = build_security_graph()


def run_security_scan(
    *, files: list[tuple[str, str]], repo: str | None = None
) -> SecurityReport:
    started = time.perf_counter()
    final: SecurityState = _SECURITY_GRAPH.invoke({"files": files, "repo": repo})
    latency_ms = int((time.perf_counter() - started) * 1000)
    return SecurityReport(
        summary=final.get("summary", "No security findings."),
        findings=final.get("findings", []),
        counts_by_category=final.get("counts_by_category", {}),
        counts_by_severity=final.get("counts_by_severity", {}),
        scanned_files=final.get("scanned_files", 0),
        skipped_files=final.get("skipped_files", 0),
        degraded=final.get("degraded", []),
        tokens_used=final.get("tokens_used", 0),
        latency_ms=latency_ms,
    )
