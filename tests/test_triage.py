"""Triage: the LLM may narrow, reorder and annotate — never invent.

The trust boundary lives in `_apply`, so most of these tests feed it a
deliberately misbehaving model reply and assert the detector output survives.
"""
from __future__ import annotations

import pytest

from config import settings
from llm_model.base import ChatLLM
from schemas import SecurityFinding
from security.triage import BATCH_SIZE, _apply, deterministic_triage, triage


def make(fid, **kw):
    base = dict(
        id=fid,
        category="code",
        detector="bandit",
        rule_id="B608",
        title="sql injection",
        file="app/db.py",
        line_start=10,
        line_end=10,
        detector_severity="medium",
        severity="medium",
    )
    base.update(kw)
    return SecurityFinding(**base)


# --------------------------------------------------------------------------- #
# Deterministic path
# --------------------------------------------------------------------------- #
def test_same_line_same_category_collapses_to_one_finding():
    a = make("a", detector="bandit", severity="medium")
    b = make("b", detector="eslint-plugin-security", severity="high")
    out = deterministic_triage([a, b])
    assert len(out) == 1
    # The higher-severity finding survives and records what it absorbed.
    assert out[0].id == "b"
    assert out[0].merged_from == ["a"]


def test_different_lines_are_kept_apart():
    out = deterministic_triage([make("a", line_start=10), make("b", line_start=20)])
    assert len(out) == 2


def test_secrets_and_code_findings_on_one_line_are_both_kept():
    # A hardcoded key is both "a secret in git history" and "an unsafe code
    # pattern". They need different fixes, so collapsing them loses information.
    secret = make(
        "s", category="secret", detector="gitleaks-regex", rule_id="aws-access-key-id"
    )
    code = make("c", category="code", rule_id="B105")
    assert len(deterministic_triage([secret, code])) == 2


def test_dependency_dedupe_is_by_vulnerability_not_by_line():
    # OSV returns the same CVE via a GHSA record and a PYSEC record.
    ghsa = make(
        "g", category="dependency", detector="osv", rule_id="CVE-2018-18074",
        evidence="PyPI:requests@2.19.0", severity="high", line_start=1,
    )
    pysec = make(
        "p", category="dependency", detector="osv", rule_id="CVE-2018-18074",
        evidence="PyPI:requests@2.19.0", severity="medium", line_start=1,
    )
    out = deterministic_triage([ghsa, pysec])
    assert len(out) == 1
    assert out[0].severity == "high"


def test_output_is_sorted_by_severity():
    out = deterministic_triage(
        [
            make("a", severity="low", line_start=1),
            make("b", severity="high", line_start=2),
            make("c", severity="medium", line_start=3),
        ]
    )
    assert [f.severity for f in out] == ["high", "medium", "low"]


# --------------------------------------------------------------------------- #
# LLM reply handling — the trust boundary
# --------------------------------------------------------------------------- #
def test_valid_reply_is_applied():
    batch = [make("a"), make("b", line_start=20)]
    out = _apply(
        batch,
        {
            "findings": [
                {
                    "id": "a",
                    "severity": "high",
                    "exploitability": "direct",
                    "explanation": "Reachable from the public route.",
                    "suggested_fix": "Use bound parameters.",
                },
                {"id": "b", "severity": "low", "exploitability": "theoretical",
                 "explanation": "Test fixture only.", "suggested_fix": "None needed."},
            ]
        },
    )
    assert [f.severity for f in out] == ["high", "low"]
    assert out[0].exploitability == "direct"
    assert out[0].explanation == "Reachable from the public route."
    assert all(f.triaged for f in out)


def test_model_may_merge_findings_it_was_given():
    batch = [make("a"), make("b", line_start=20)]
    out = _apply(
        batch,
        {"findings": [{"id": "a", "severity": "high", "duplicate_ids": ["b"]}]},
    )
    assert [f.id for f in out] == ["a"]
    assert out[0].merged_from == ["b"]


def test_invented_findings_are_rejected():
    batch = [make("a")]
    out = _apply(
        batch,
        {
            "findings": [
                {"id": "a", "severity": "high"},
                {"id": "hallucinated", "severity": "high", "explanation": "made up"},
            ]
        },
    )
    assert [f.id for f in out] == ["a"]


def test_skipped_findings_are_kept_untriaged_not_dropped():
    # Small models routinely return fewer findings than they were given. The
    # ones they skipped must survive with the detector's own values — losing an
    # annotation is acceptable, losing a finding is not.
    batch = [make("a"), make("b", line_start=20, detector_severity="medium")]
    out = _apply(batch, {"findings": [{"id": "a", "severity": "high"}]})
    assert {f.id for f in out} == {"a", "b"}
    triaged = {f.id: f.triaged for f in out}
    assert triaged == {"a": True, "b": False}
    skipped = next(f for f in out if f.id == "b")
    assert skipped.severity == "medium"  # untouched detector severity


def test_reciprocal_duplicate_claims_cannot_delete_both_findings():
    # "A duplicates B" and "B duplicates A" in one reply would otherwise remove
    # every finding in the batch.
    batch = [make("a"), make("b", line_start=20)]
    out = _apply(
        batch,
        {
            "findings": [
                {"id": "a", "duplicate_ids": ["b"]},
                {"id": "b", "duplicate_ids": ["a"]},
            ]
        },
    )
    assert [f.id for f in out] == ["a"]
    assert out[0].merged_from == ["b"]


def test_a_model_cannot_merge_away_a_finding_it_also_triaged():
    # If the model triages B on its own line, a later claim that A duplicates B
    # must not delete B.
    batch = [make("a"), make("b", line_start=20)]
    out = _apply(
        batch,
        {
            "findings": [
                {"id": "b", "severity": "high"},
                {"id": "a", "duplicate_ids": ["b"]},
            ]
        },
    )
    assert {f.id for f in out} == {"a", "b"}


def test_severity_casing_from_a_sloppy_model_is_accepted():
    # Small models emit "HIGH" and "High" freely; rejecting the casing would
    # silently discard correct judgements.
    out = _apply([make("a")], {"findings": [{"id": "a", "severity": "HIGH"}]})
    assert out[0].severity == "high"


def test_exploitability_casing_is_normalised():
    out = _apply(
        [make("a")],
        {"findings": [{"id": "a", "exploitability": "Direct"}]},
    )
    assert out[0].exploitability == "direct"


def test_a_reply_with_no_recognisable_ids_is_rejected():
    batch = [make("a")]
    assert _apply(batch, {"findings": [{"id": "nope", "severity": "high"}]}) is None


@pytest.mark.parametrize("reply", [None, {}, {"findings": "nope"}, {"findings": []}])
def test_unusable_replies_are_rejected(reply):
    assert _apply([make("a")], reply) is None


def test_invalid_field_values_fall_back_to_the_detector():
    batch = [make("a", detector_severity="medium")]
    out = _apply(
        batch,
        {
            "findings": [
                {"id": "a", "severity": "catastrophic", "exploitability": "maybe"}
            ]
        },
    )
    assert out[0].severity == "medium"
    assert out[0].exploitability is None


def test_empty_model_text_keeps_the_rule_authored_explanation():
    batch = [make("a", explanation="Rule text.", suggested_fix="Rule fix.")]
    reply = {"findings": [{"id": "a", "explanation": "", "suggested_fix": "  "}]}
    out = _apply(batch, reply)
    assert out[0].explanation == "Rule text."
    assert out[0].suggested_fix == "Rule fix."


def test_the_model_cannot_move_a_finding():
    batch = [make("a", file="app/db.py", line_start=10, rule_id="B608")]
    out = _apply(
        batch,
        {
            "findings": [
                {"id": "a", "file": "other.py", "line_start": 999, "rule_id": "B000"}
            ]
        },
    )
    assert (out[0].file, out[0].line_start, out[0].rule_id) == ("app/db.py", 10, "B608")


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #
def test_triage_without_a_model_still_dedupes_and_ranks(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "mock")
    findings = [make("a", severity="low"), make("b", severity="high")]
    out, tokens = triage(findings)
    assert tokens == 0
    assert len(out) == 1 and out[0].severity == "high"


def test_triage_of_nothing_is_nothing():
    assert triage([]) == ([], 0)


# --------------------------------------------------------------------------- #
# End to end against a scripted stand-in for a small local model.
#
# These reproduce how 3B-class models actually misbehave — skipped ids, wrong
# casing, invented ids, an occasional unparseable reply — and assert that the
# findings survive all of it. Without a local model in CI this is the only place
# the full triage path is exercised.
# --------------------------------------------------------------------------- #
class ScriptedLLM(ChatLLM):
    """A ChatLLM whose replies are supplied, not generated."""

    model = "scripted"

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0

    def chat_json(self, system, user):
        self.calls += 1
        reply = self._replies.pop(0) if self._replies else {}
        if isinstance(reply, Exception):
            raise reply
        return reply, 100


def _run_with(monkeypatch, findings, replies):
    llm = ScriptedLLM(replies)
    monkeypatch.setattr("llm_model.base.get_llm", lambda: llm)
    monkeypatch.setattr(settings, "security_triage", True)
    out, tokens = triage(findings, {}, repo="acme/demo")
    return out, tokens, llm


def test_sloppy_small_model_never_loses_a_finding(monkeypatch):
    findings = [make(str(i), line_start=10 * i) for i in range(1, 6)]
    # Returns three of five, one invented id, and shouty severities.
    reply = {
        "findings": [
            {"id": "1", "severity": "HIGH", "exploitability": "Direct",
             "explanation": "Reachable from the public route."},
            {"id": "3", "severity": "low", "explanation": "Test fixture only."},
            {"id": "hallucinated", "severity": "high", "explanation": "invented"},
            {"id": "5", "severity": "medium"},
        ]
    }
    out, tokens, _ = _run_with(monkeypatch, findings, [reply])

    assert {f.id for f in out} == {"1", "2", "3", "4", "5"}
    assert tokens == 100
    triaged = {f.id: f.triaged for f in out}
    assert triaged == {"1": True, "2": False, "3": True, "4": False, "5": True}
    assert next(f for f in out if f.id == "1").severity == "high"


def test_unparseable_reply_falls_back_to_the_detector_output(monkeypatch):
    findings = [make("1"), make("2", line_start=20)]
    out, _, _ = _run_with(monkeypatch, findings, [None])
    assert {f.id for f in out} == {"1", "2"}
    assert not any(f.triaged for f in out)


def test_a_model_that_errors_does_not_cost_the_user_their_findings(monkeypatch):
    findings = [make("1"), make("2", line_start=20)]
    out, _, _ = _run_with(monkeypatch, findings, [RuntimeError("connection reset")])
    assert {f.id for f in out} == {"1", "2"}


def test_findings_are_batched_so_small_models_stay_coherent(monkeypatch):
    # More findings than BATCH_SIZE must arrive as several calls, not one giant
    # prompt a 3B model will truncate.
    findings = [make(str(i), line_start=10 * i) for i in range(1, BATCH_SIZE * 2 + 1)]
    replies = [{"findings": [{"id": str(i), "severity": "low"}]} for i in range(1, 4)]
    out, _, llm = _run_with(monkeypatch, findings, replies)
    assert llm.calls >= 2
    assert len(out) == len(findings)


def test_triage_is_skipped_entirely_when_disabled(monkeypatch):
    findings = [make("1"), make("2", line_start=20)]
    llm = ScriptedLLM([{"findings": [{"id": "1", "severity": "high"}]}])
    monkeypatch.setattr("llm_model.base.get_llm", lambda: llm)
    monkeypatch.setattr(settings, "security_triage", False)
    out, tokens = triage(findings, {})
    assert llm.calls == 0 and tokens == 0
    assert len(out) == 2
