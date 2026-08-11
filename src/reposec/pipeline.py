"""The security-scan pipeline.

    collect_files → scan_secrets → scan_dependencies → scan_code
                  → suppress_findings → redact_findings → triage_findings
                  → aggregate

Eight stages in a straight line. Each takes the accumulated state and returns
only the keys it changed; the runner merges them in order. That is the whole
execution model, and it is deliberately this small — see `_PIPELINE` below for
why it is not a graph framework.

The three scan stages are the detection layer and contain no model calls at all —
they are regex/entropy rules, manifest parsing against the OSV database, and two
real linters. `triage_findings` is the only stage that talks to an LLM, and it
can only narrow, reorder, or annotate what the detectors produced.

**Authorization boundary:** no stage here can post, merge, write to a repository,
or modify anything; the pipeline returns a `SecurityReport` and nothing else.
Files arrive as an argument — the pipeline never fetches them, so it has no
network reach into the user's repositories.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypedDict

from reposec.detectors.common import is_scannable, looks_binary, snippet
from reposec.schemas import SecurityFinding, SecurityReport


class SecurityState(TypedDict, total=False):
    repo: str | None
    files: list[tuple[str, str]]
    # Per-scan overrides for the two settings a command-line flag can change.
    # They travel in the state rather than being written onto the `settings`
    # singleton, because that singleton is process-global and cached: a single
    # `--offline` run would otherwise leave every later scan in the same
    # process offline, including in the test suite and in any long-lived host
    # that imports `run_security_scan` as a library.
    offline: bool | None
    triage: bool | None
    findings: list[SecurityFinding]
    degraded: list[str]
    suppressed: int
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
        "suppressed": 0,
        "tokens_used": 0,
        "scanned_files": len(keep),
        "skipped_files": len(incoming) - len(keep),
    }


def _scan_secrets(state: SecurityState) -> SecurityState:
    from reposec.detectors.secrets import scan_files

    found = scan_files(state.get("files", []))
    return {"findings": state.get("findings", []) + found}


def _resolve(state: SecurityState, key: str, setting: str) -> bool:
    """A per-scan override if one was passed, otherwise the configured default."""
    from reposec.config import settings

    override = state.get(key)
    return getattr(settings, setting) if override is None else override


def _scan_dependencies(state: SecurityState) -> SecurityState:
    from reposec.detectors.deps import scan_dependencies

    found, degraded = scan_dependencies(
        state.get("files", []), offline=_resolve(state, "offline", "security_offline")
    )
    return {
        "findings": state.get("findings", []) + found,
        "degraded": state.get("degraded", []) + degraded,
    }


def _scan_code(state: SecurityState) -> SecurityState:
    from reposec.detectors.code import scan_code

    found, degraded = scan_code(state.get("files", []))
    return {
        "findings": state.get("findings", []) + found,
        "degraded": state.get("degraded", []) + degraded,
    }


def _suppress(state: SecurityState) -> SecurityState:
    """Drop findings the repo's `.secscanignore` marks as known and accepted.

    Runs before triage so the model is never asked to rank findings the user has
    already dismissed — that would be paying tokens to sort noise.
    """
    from reposec.detectors.suppress import apply, load_rules

    rules = load_rules(state.get("files", []))
    kept, dropped = apply(state.get("findings", []), rules)
    return {"findings": kept, "suppressed": dropped}


def _redact(state: SecurityState) -> SecurityState:
    """Mask credentials in every finding before anything leaves the scanner.

    The secret detector redacts its own evidence, but bandit and eslint quote
    raw source lines — and a hardcoded token is exactly the kind of line they
    quote. This stage is what makes "the raw secret is never stored and never
    sent to the model" true of the whole pipeline rather than of one detector.
    """
    from reposec.detectors.secrets import scrub

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
    from reposec.detectors.secrets import scrub

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
    from reposec.triage import triage

    findings = state.get("findings", [])
    contexts = _build_contexts(state.get("files", []), findings)
    ranked, tokens = triage(
        findings,
        contexts,
        repo=state.get("repo"),
        enabled=_resolve(state, "triage", "security_triage"),
    )
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


Stage = Callable[[SecurityState], SecurityState]

# The pipeline, in execution order. This was a compiled LangGraph `StateGraph`
# for most of the project's life, and the graph had exactly this shape: eight
# nodes, eight unconditional edges, no branching, no checkpointing, no
# concurrency, no interrupts, no human-in-the-loop. Nothing about the scan is
# graph-shaped, so the framework bought a straight line at three prices:
#
#   ~25 transitive packages, which is a poor look in a tool that sells
#   dependency hygiene and a real supply-chain surface in a security scanner;
#
#   1.30s of import time on every invocation — measured with `-X importtime`,
#   against 0.17s for this whole module — on a CLI whose end-to-end scan of a
#   small repository is about two seconds;
#
#   and a leak: langgraph inherits langchain-core's global tracer, which
#   activates from an ambient LANGSMITH_TRACING and uploaded the verbatim
#   scanned source, credentials included, to a third party. That had to be
#   pinned off by hand for as long as the dependency existed. A list of
#   functions cannot do it at all.
#
# The ordering *is* the security guarantee — redaction before triage is what
# keeps raw credentials away from the model — so it is declared in one place and
# asserted in tests/test_pipeline_safety.py.
_PIPELINE: tuple[tuple[str, Stage], ...] = (
    ("collect_files", _collect),
    ("scan_secrets", _scan_secrets),
    ("scan_dependencies", _scan_dependencies),
    ("scan_code", _scan_code),
    ("suppress_findings", _suppress),
    ("redact_findings", _redact),
    ("triage_findings", _triage),
    ("aggregate", _aggregate),
)

STAGE_NAMES: tuple[str, ...] = tuple(name for name, _ in _PIPELINE)


def run_pipeline(state: SecurityState) -> SecurityState:
    """Run every stage in order, merging each one's output into the state.

    Last write wins, per key — the same reducer semantics the graph used for
    unannotated state keys, so stages that accumulate (`findings`, `degraded`)
    read the previous value and return the extended list themselves.
    """
    for _name, stage in _PIPELINE:
        state = {**state, **stage(state)}
    return state


def run_security_scan(
    *,
    files: list[tuple[str, str]],
    repo: str | None = None,
    offline: bool | None = None,
    triage: bool | None = None,
) -> SecurityReport:
    """Scan `files` and return the report. Nothing leaves this process."""
    started = time.perf_counter()
    final = run_pipeline(
        {"files": files, "repo": repo, "offline": offline, "triage": triage}
    )
    latency_ms = int((time.perf_counter() - started) * 1000)
    return SecurityReport(
        summary=final.get("summary", "No security findings."),
        findings=final.get("findings", []),
        counts_by_category=final.get("counts_by_category", {}),
        counts_by_severity=final.get("counts_by_severity", {}),
        scanned_files=final.get("scanned_files", 0),
        skipped_files=final.get("skipped_files", 0),
        suppressed=final.get("suppressed", 0),
        degraded=final.get("degraded", []),
        tokens_used=final.get("tokens_used", 0),
        latency_ms=latency_ms,
    )
