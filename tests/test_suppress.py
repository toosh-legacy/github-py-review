"""Suppression rules: the escape hatch that keeps the scanner usable.

The risk here is a rule that silences more than the user meant, so most of these
assert what does *not* get suppressed.
"""
from __future__ import annotations

import pytest

from reposec.detectors.suppress import apply, load_rules, parse
from reposec.schemas import SecurityFinding


def make(fid="a", file="app/db.py", rule_id="B608"):
    return SecurityFinding(
        id=fid,
        category="code",
        detector="bandit",
        rule_id=rule_id,
        title="t",
        file=file,
        line_start=1,
        line_end=1,
    )


def test_parses_the_three_line_forms():
    rules = parse(
        "\n".join(
            [
                "# a comment",
                "",
                "docs/**",
                "tests/**:github-pat",
                ":B101",
                "   ",
            ]
        )
    )
    assert [(r.path_glob, r.rule_id) for r in rules] == [
        ("docs/**", ""),
        ("tests/**", "github-pat"),
        ("", "B101"),
    ]


def test_trailing_comment_is_stripped():
    assert parse("docs/**  # why")[0].path_glob == "docs/**"


def test_a_line_with_neither_half_is_ignored():
    # ":" alone would otherwise suppress every finding in the repo.
    assert parse(":") == []
    assert apply([make()], parse(":")) == ([make()], 0)


def test_path_glob_suppresses_a_whole_tree():
    rules = parse("docs/**")
    kept, dropped = apply([make(file="docs/a.md"), make(file="docs/x/b.md")], rules)
    assert kept == [] and dropped == 2


def test_path_glob_does_not_leak_to_sibling_prefixes():
    # `docs/**` must not swallow `docs-internal/`.
    kept, dropped = apply([make(file="docs-internal/a.md")], parse("docs/**"))
    assert len(kept) == 1 and dropped == 0


def test_bare_directory_behaves_like_a_tree():
    kept, _ = apply([make(file="tests/fixtures/x.py")], parse("tests"))
    assert kept == []


def test_rule_only_suppresses_that_rule_everywhere():
    findings = [make("a", rule_id="B101"), make("b", rule_id="B608")]
    kept, dropped = apply(findings, parse(":B101"))
    assert [f.id for f in kept] == ["b"] and dropped == 1


def test_path_and_rule_together_must_both_match():
    rules = parse("tests/**:github-pat")
    findings = [
        make("a", file="tests/t.py", rule_id="github-pat"),  # both → dropped
        make("b", file="tests/t.py", rule_id="B608"),  # wrong rule → kept
        make("c", file="src/t.py", rule_id="github-pat"),  # wrong path → kept
    ]
    kept, dropped = apply(findings, rules)
    assert [f.id for f in kept] == ["b", "c"] and dropped == 1


def test_no_rules_is_a_no_op():
    findings = [make()]
    assert apply(findings, []) == (findings, 0)


@pytest.mark.parametrize(
    "path", [".secscanignore", "sub/.secscanignore"]
)
def test_rules_are_loaded_from_the_submitted_files(path):
    assert load_rules([(path, "docs/**")]) == parse("docs/**")


def test_missing_suppression_file_yields_no_rules():
    assert load_rules([("app.py", "x = 1")]) == []


def test_windows_separators_in_finding_paths_still_match():
    kept, dropped = apply([make(file="docs\\a.md")], parse("docs/**"))
    assert kept == [] and dropped == 1


def test_a_dotfile_directory_rule_matches_its_own_tree():
    # `.github/**` is one of the first rules anyone writes, and the leading dot
    # used to be stripped off both sides by `lstrip("./")` — which happened to
    # work, but only because the damage was symmetric.
    kept, dropped = apply([make(file=".github/workflows/ci.yml")], parse(".github/**"))
    assert kept == [] and dropped == 1


def test_a_dotfile_rule_does_not_match_the_undotted_sibling():
    # The symmetric damage above also made `.github/**` suppress a real
    # `github/` directory, because both sides collapsed to `github`.
    kept, dropped = apply([make(file="github/workflows/ci.yml")], parse(".github/**"))
    assert len(kept) == 1 and dropped == 0
