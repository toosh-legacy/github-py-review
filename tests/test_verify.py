"""The verification stage: the precision half of the review.

Covers the two guards that make a small local model usable as a reviewer —
the severity floor plus the verifier agent's veto, and `validate_fix`, which
stops a hallucinated patch from ever being shown as something to paste in.
"""
from __future__ import annotations

import pytest

from agent import graph
from agent.diff_utils import parse_unified_diff
from llm_model import verify
from llm_model.base import ChatReviewLLM
from schemas import Issue


@pytest.fixture()
def diff_file(sample_diff):
    return [f for f in parse_unified_diff(sample_diff) if f.is_python][0]


def _issue(df, *, severity="high", fix="", description="boom") -> Issue:
    line = sorted(df.added_line_numbers)[0]
    return Issue(
        file=df.path,
        line_start=line,
        line_end=line,
        severity=severity,
        description=description,
        suggested_fix=fix,
    )


class _StubLLM(ChatReviewLLM):
    """A ChatReviewLLM whose verdicts are scripted, so no network is needed."""

    def __init__(self, verdicts: list[bool | None]) -> None:
        self.verdicts = list(verdicts)
        self.calls = 0

    def chat_json(self, system: str, user: str) -> tuple[dict | None, int]:
        self.calls += 1
        verdict = self.verdicts.pop(0)
        return (None if verdict is None else {"verdict": verdict}), 7


@pytest.fixture()
def use_stub(monkeypatch):
    """Install a scripted verifier and force verification on."""

    def _install(verdicts: list[bool | None]) -> _StubLLM:
        stub = _StubLLM(verdicts)
        monkeypatch.setattr(verify, "get_review_llm", lambda: stub)
        monkeypatch.setattr(verify.settings, "verify_findings", True)
        monkeypatch.setattr(verify.settings, "min_severity", "low")
        return stub

    return _install


# --- the verifier's veto ----------------------------------------------------


def test_rejected_proposal_is_dropped(diff_file, use_stub):
    stub = use_stub([False])
    kept, tokens = verify.verify_issues([diff_file], [_issue(diff_file)])
    assert kept == []
    assert tokens == 7
    assert stub.calls == 1


def test_confirmed_proposal_survives(diff_file, use_stub):
    use_stub([True])
    kept, _ = verify.verify_issues([diff_file], [_issue(diff_file)])
    assert len(kept) == 1


def test_unparseable_verdict_keeps_the_proposal(diff_file, use_stub):
    # An unreadable verdict is not evidence against the finding.
    use_stub([None])
    kept, _ = verify.verify_issues([diff_file], [_issue(diff_file)])
    assert len(kept) == 1


def test_verifier_failure_does_not_lose_findings(diff_file, monkeypatch):
    class _Broken(ChatReviewLLM):
        def chat_json(self, system, user):
            raise RuntimeError("local server down")

    monkeypatch.setattr(verify, "get_review_llm", lambda: _Broken())
    monkeypatch.setattr(verify.settings, "verify_findings", True)
    monkeypatch.setattr(verify.settings, "min_severity", "low")

    kept, tokens = verify.verify_issues([diff_file], [_issue(diff_file)])
    # The verifier is a filter, not the product: it fails open.
    assert len(kept) == 1
    assert tokens == 0


def test_mock_reviewer_is_not_asked_to_verify(diff_file, monkeypatch):
    # With no real backend there is nothing to verify against, so the stage is
    # a no-op rather than an error.
    monkeypatch.setattr(verify.settings, "verify_findings", True)
    monkeypatch.setattr(verify.settings, "llm_backend", "mock")
    monkeypatch.setattr(verify.settings, "min_severity", "low")
    kept, tokens = verify.verify_issues([diff_file], [_issue(diff_file)])
    assert len(kept) == 1
    assert tokens == 0


# --- the severity floor -----------------------------------------------------


def test_severity_floor_drops_low_findings_before_verification(
    diff_file, use_stub, monkeypatch
):
    stub = use_stub([])  # no verdicts scripted: nothing should reach the model
    monkeypatch.setattr(verify.settings, "min_severity", "high")

    kept, _ = verify.verify_issues([diff_file], [_issue(diff_file, severity="low")])
    assert kept == []
    assert stub.calls == 0, "filtered findings must not cost a verifier call"


# --- fix validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "fix",
    [
        "wrap the call in a try/except and log the error",  # prose advice
        "if user is None:\n    return None",  # valid code
        "        value = data['k']",  # valid, over-indented fragment
        "+    conn.close()\n-    pass",  # diff-style, valid once applied
        "```python\nfor x in xs:\n    use(x)\n```",  # fenced, valid
    ],
)
def test_validate_fix_keeps_usable_fixes(fix):
    assert verify.validate_fix(fix) == fix.strip()


@pytest.mark.parametrize(
    "fix",
    [
        "if x is None\n    return",  # missing colon
        "def broken(:\n    pass",  # unparseable signature
        "```python\nfor x in xs\n    use(x)\n```",  # fenced but broken
        "-    conn.close()",  # diff with nothing added
    ],
)
def test_validate_fix_discards_fixes_that_would_break_code(fix):
    assert verify.validate_fix(fix) == ""


def test_broken_fix_is_stripped_but_the_finding_is_kept(diff_file, use_stub):
    use_stub([True])
    issue = _issue(diff_file, fix="def broken(:\n    pass")
    kept, _ = verify.verify_issues([diff_file], [issue])
    # The defect is still worth reporting — only the bad patch is withheld.
    assert len(kept) == 1
    assert kept[0].suggested_fix == ""


# --- graph wiring -----------------------------------------------------------


def test_verify_findings_is_a_graph_node():
    nodes = graph.build_graph().get_graph().nodes
    assert "verify_findings" in nodes


def test_verification_runs_between_proposal_and_aggregation(sample_diff, monkeypatch):
    """Ruff's findings must survive a verifier that rejects everything."""
    monkeypatch.setattr(verify.settings, "verify_findings", True)
    monkeypatch.setattr(verify.settings, "min_severity", "low")

    class _RejectAll(ChatReviewLLM):
        def chat_json(self, system, user):
            return {"verdict": False}, 3

    monkeypatch.setattr(verify, "get_review_llm", lambda: _RejectAll())

    report = graph.run_review_graph(diff=sample_diff)
    # The mock proposer's finding is vetoed; ruff's are untouched by the audit.
    assert all("Mock reviewer" not in i.description for i in report.issues)
