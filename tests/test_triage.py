"""Triage: the LLM may narrow, reorder and annotate — never invent.

The trust boundary lives in `_apply`, so most of these tests feed it a
deliberately misbehaving model reply and assert the detector output survives.
"""
from __future__ import annotations

import pytest

from schemas import SecurityFinding
from security.triage import _apply, deterministic_triage, triage


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


def test_dropping_findings_without_accounting_for_them_is_rejected():
    # The model silently returned one of two findings. Shipping a short report
    # would hide a real finding, so the whole reply is discarded.
    batch = [make("a"), make("b", line_start=20)]
    assert _apply(batch, {"findings": [{"id": "a", "severity": "high"}]}) is None


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
def test_triage_without_a_reviewer_still_dedupes_and_ranks(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "mock")
    findings = [make("a", severity="low"), make("b", severity="high")]
    out, tokens = triage(findings)
    assert tokens == 0
    assert len(out) == 1 and out[0].severity == "high"


def test_triage_of_nothing_is_nothing():
    assert triage([]) == ([], 0)
