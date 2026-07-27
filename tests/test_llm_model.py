"""Reviewer tests that don't need network access."""
from agent.diff_utils import parse_unified_diff
from llm_model.base import ChatReviewLLM
from llm_model.mock_model import MockReviewLLM
from llm_model.verify import validate_fix


def _sample_file(sample_diff):
    return [f for f in parse_unified_diff(sample_diff) if f.is_python][0]


def test_mock_reviewer_returns_low_severity_finding(sample_diff):
    df = _sample_file(sample_diff)
    issues, tokens = MockReviewLLM().review_file(df)
    assert tokens == 0
    assert len(issues) == 1
    assert issues[0].severity == "low"
    assert issues[0].line_start in df.added_line_numbers


def test_parse_issues_maps_json_and_drops_off_diff_lines(sample_diff):
    df = _sample_file(sample_diff)
    data = {
        "issues": [
            {
                "line_start": 2,
                "line_end": 2,
                "severity": "high",
                "description": "null deref",
                "suggested_fix": "guard it",
            },
            {"line_start": 999, "severity": "low", "description": "off-diff"},
        ]
    }
    issues = ChatReviewLLM().parse_issues(df, data)
    # The line-999 finding is dropped (not a touched line); the line-2 stays.
    assert len(issues) == 1
    assert issues[0].severity == "high"
    assert issues[0].file == df.path


def test_validate_fix_keeps_prose_and_valid_code_but_drops_broken_code():
    assert validate_fix("close the file in a finally block")
    assert validate_fix("if x is None:\n    return")
    assert validate_fix("def broken(:\n    pass") == ""
