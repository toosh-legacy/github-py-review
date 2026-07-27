"""The LangGraph review agent.

    START → fetch_diff → run_static_analysis → llm_review_per_file
          → verify_findings → aggregate_findings → END

`fetch_diff` only reaches out to GitHub when a `pr_url` was given and no diff
is already in hand.

The reviewer is split across two nodes on purpose. `llm_review_per_file`
proposes freely (recall) into its own `llm_issues` state key; `verify_findings`
audits those proposals and merges the survivors into `issues` (precision).
Keeping the proposals separate is what lets the verifier run on them without
touching ruff's deterministic findings.

**Authorization boundary:** none of these nodes can post, merge, or modify
anything. The agent only ever returns a `Report`. Posting a comment is a
separate, explicit HTTP route that lives entirely outside this graph — see
`github_client/comment.py` and `tests/test_agent_safety.py`.
"""
from __future__ import annotations

import time
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from schemas import Issue, Report

from .diff_utils import DiffFile, parse_unified_diff
from .nodes import (
    aggregate_findings,
    llm_debug_files,
    llm_review_files,
    run_static_analysis,
    run_static_analysis_on_file,
    verify_llm_findings,
)


class ReviewState(TypedDict, total=False):
    diff: str
    pr_url: str | None
    files: list[DiffFile]
    issues: list[Issue]
    llm_issues: list[Issue]  # proposals awaiting verification
    tokens_used: int
    summary: str


def _fetch_diff(state: ReviewState) -> ReviewState:
    diff = state.get("diff") or ""
    if not diff and state.get("pr_url"):
        from github_client.diff import fetch_diff_from_url

        diff = fetch_diff_from_url(state["pr_url"])
    files = [df for df in parse_unified_diff(diff) if df.is_python]
    # Best-effort RAG indexing of the touched files (no-op without chromadb).
    from rag.indexer import index_diff_files

    index_diff_files(files)
    return {
        "diff": diff,
        "files": files,
        "issues": [],
        "llm_issues": [],
        "tokens_used": 0,
    }


def _static(state: ReviewState) -> ReviewState:
    issues = run_static_analysis(state.get("diff", ""))
    return {"issues": state.get("issues", []) + issues}


def _llm(state: ReviewState) -> ReviewState:
    """Propose findings — held in `llm_issues` until the verifier clears them."""
    issues, tokens = llm_review_files(state.get("files", []))
    return {
        "llm_issues": issues,
        "tokens_used": state.get("tokens_used", 0) + tokens,
    }


def _verify(state: ReviewState) -> ReviewState:
    """Audit the proposals, then merge the survivors in with ruff's findings."""
    issues, tokens = verify_llm_findings(
        state.get("files", []), state.get("llm_issues", [])
    )
    return {
        "issues": state.get("issues", []) + issues,
        "llm_issues": [],
        "tokens_used": state.get("tokens_used", 0) + tokens,
    }


def _aggregate(state: ReviewState) -> ReviewState:
    issues, summary = aggregate_findings(state.get("issues", []))
    return {"issues": issues, "summary": summary}


def build_graph():
    g = StateGraph(ReviewState)
    g.add_node("fetch_diff", _fetch_diff)
    g.add_node("run_static_analysis", _static)
    g.add_node("llm_review_per_file", _llm)
    g.add_node("verify_findings", _verify)
    g.add_node("aggregate_findings", _aggregate)

    g.add_edge(START, "fetch_diff")
    g.add_edge("fetch_diff", "run_static_analysis")
    g.add_edge("run_static_analysis", "llm_review_per_file")
    g.add_edge("llm_review_per_file", "verify_findings")
    g.add_edge("verify_findings", "aggregate_findings")
    g.add_edge("aggregate_findings", END)
    return g.compile()


# Compiled once at import; nodes are pure so the graph is safe to reuse.
_GRAPH = build_graph()


def run_review_graph(*, diff: str | None = None, pr_url: str | None = None) -> Report:
    started = time.perf_counter()
    final: ReviewState = _GRAPH.invoke({"diff": diff or "", "pr_url": pr_url})
    latency_ms = int((time.perf_counter() - started) * 1000)
    return Report(
        summary=final.get("summary", "No issues found."),
        issues=final.get("issues", []),
        tokens_used=final.get("tokens_used", 0),
        latency_ms=latency_ms,
    )


# --------------------------------------------------------------------------- #
# Debug flow: same shape as the review graph, but over one *whole* file (the
# repo-scan → pick-one-file → debug flow) rather than a diff. It reuses the
# proposer/verifier split and the same read-only boundary — no node here can
# post, merge, or modify anything.
# --------------------------------------------------------------------------- #
class DebugState(TypedDict, total=False):
    path: str
    content: str
    files: list[DiffFile]
    issues: list[Issue]
    llm_issues: list[Issue]  # proposals awaiting verification
    tokens_used: int
    summary: str


def _debug_load(state: DebugState) -> DebugState:
    path, content = state.get("path", ""), state.get("content", "")
    df = DiffFile.from_full_file(path, content)
    files = [df] if df.is_python else []
    # Best-effort RAG indexing of the file (no-op without chromadb).
    from rag.indexer import index_diff_files

    index_diff_files(files)
    return {"files": files, "issues": [], "llm_issues": [], "tokens_used": 0}


def _debug_static(state: DebugState) -> DebugState:
    issues = run_static_analysis_on_file(
        state.get("path", ""), state.get("content", "")
    )
    return {"issues": state.get("issues", []) + issues}


def _debug_llm(state: DebugState) -> DebugState:
    issues, tokens = llm_debug_files(state.get("files", []))
    return {
        "llm_issues": issues,
        "tokens_used": state.get("tokens_used", 0) + tokens,
    }


def build_debug_graph():
    g = StateGraph(DebugState)
    g.add_node("load_file", _debug_load)
    g.add_node("run_static_analysis", _debug_static)
    g.add_node("llm_debug_file", _debug_llm)
    g.add_node("verify_findings", _verify)
    g.add_node("aggregate_findings", _aggregate)

    g.add_edge(START, "load_file")
    g.add_edge("load_file", "run_static_analysis")
    g.add_edge("run_static_analysis", "llm_debug_file")
    g.add_edge("llm_debug_file", "verify_findings")
    g.add_edge("verify_findings", "aggregate_findings")
    g.add_edge("aggregate_findings", END)
    return g.compile()


_DEBUG_GRAPH = build_debug_graph()


def run_debug_file(*, path: str, content: str) -> Report:
    started = time.perf_counter()
    final: DebugState = _DEBUG_GRAPH.invoke({"path": path, "content": content})
    latency_ms = int((time.perf_counter() - started) * 1000)
    return Report(
        summary=final.get("summary", "No issues found."),
        issues=final.get("issues", []),
        tokens_used=final.get("tokens_used", 0),
        latency_ms=latency_ms,
    )
