"""Deterministic stub reviewer used when no real reviewer is configured.

Keeps the pipeline (and the tests, and the eval harness) runnable offline.
"""
from __future__ import annotations

from agent.diff_utils import DiffFile
from schemas import Issue


class MockReviewLLM:
    def review_file(self, df: DiffFile) -> tuple[list[Issue], int]:
        return self._stub(df, "this change")

    @staticmethod
    def _stub(df: DiffFile, subject: str) -> tuple[list[Issue], int]:
        added = sorted(df.added_line_numbers)
        if not added:
            return [], 0
        line = added[0]
        issue = Issue(
            file=df.path,
            line_start=line,
            line_end=line,
            severity="low",
            description=(
                f"Mock reviewer: verify edge cases and add a test for {subject}. "
                "(Set LOCAL_LLM_BASE_URL or OPENAI_API_KEY to enable a real reviewer.)"
            ),
            suggested_fix="",
        )
        return [issue], 0
