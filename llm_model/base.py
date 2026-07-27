"""The reviewer contract, the shared chat implementation, and the factory.

`ReviewLLM` is the seam: swap implementations, not the contract. Both real
reviewers (local and hosted) speak the OpenAI chat-completions API, so they
share everything except which client they build — that lives in
`ChatReviewLLM` here, and the subclasses are a constructor each.
"""
from __future__ import annotations

import json
from typing import Protocol

from agent.diff_utils import DiffFile
from config import settings
from schemas import Issue

from .prompts import (
    DEBUG_SYSTEM_PROMPT,
    DEBUG_USER_PROMPT,
    REVIEW_SYSTEM_PROMPT,
    REVIEW_USER_PROMPT,
)

VALID_SEVERITY = {"high", "medium", "low"}


class ReviewLLM(Protocol):
    def review_file(self, df: DiffFile) -> tuple[list[Issue], int]:
        """Return (issues, tokens_used) for one changed file (diff path)."""
        ...

    def debug_file(self, df: DiffFile) -> tuple[list[Issue], int]:
        """Return (issues, tokens_used) for one whole file (repo-scan path)."""
        ...


def loads_lenient(raw: str) -> dict | None:
    """Parse a model's JSON reply, tolerating the wrappers small models add.

    Local models honour `response_format` less reliably than the hosted API and
    often fence the object in ```json ... ``` or prepend a sentence. Rather than
    throwing that review away, recover the outermost JSON object.
    """
    raw = raw.strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        start, end = raw.find("{"), raw.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            data = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


class ChatReviewLLM:
    """Shared reviewer logic over an OpenAI-compatible chat client.

    Subclasses only build `self.client` and set `self.model`; the prompt,
    line-number bookkeeping, and response parsing are identical either way.
    """

    client: object
    model: str

    # Low temperature: review should be reproducible, and sampling diversity
    # buys nothing but extra false positives here.
    temperature = 0.0

    def annotated_source(self, df: DiffFile) -> str:
        """Render the changed file with real line numbers and '+' markers."""
        content, real_lines = df.reconstructed_new_content()
        added = df.added_line_numbers
        out = []
        for text, real in zip(content.splitlines() or [content], real_lines):
            marker = "+" if real in added else " "
            out.append(f"{real:>5} {marker} {text}")
        return "\n".join(out)

    def chat_json(self, system: str, user: str) -> tuple[dict | None, int]:
        """One JSON-mode chat round-trip. Returns (parsed, tokens_used)."""
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
            temperature=self.temperature,
        )
        tokens = getattr(resp.usage, "total_tokens", 0) or 0
        return loads_lenient(resp.choices[0].message.content or "{}"), tokens

    def _run(
        self, df: DiffFile, system_prompt: str, user_prompt: str
    ) -> tuple[list[Issue], int]:
        """One system+user round-trip over `df`, parsed into issues."""
        from backend.errors import APIError

        user = user_prompt.format(path=df.path, source=self.annotated_source(df))
        try:
            data, tokens = self.chat_json(system_prompt, user)
        except Exception as exc:  # noqa: BLE001 - surface as a clean 502
            raise APIError(
                502, "llm_error", f"{type(self).__name__} request failed: {exc}"
            ) from exc
        return self.parse_issues(df, data), tokens

    def review_file(self, df: DiffFile) -> tuple[list[Issue], int]:
        return self._run(df, REVIEW_SYSTEM_PROMPT, REVIEW_USER_PROMPT)

    def debug_file(self, df: DiffFile) -> tuple[list[Issue], int]:
        return self._run(df, DEBUG_SYSTEM_PROMPT, DEBUG_USER_PROMPT)

    def parse_issues(self, df: DiffFile, data: dict | None) -> list[Issue]:
        if data is None:
            return []
        added = df.added_line_numbers
        issues: list[Issue] = []
        for item in data.get("issues", []):
            if not isinstance(item, dict):
                continue
            severity = item.get("severity", "low")
            if severity not in VALID_SEVERITY:
                severity = "low"
            try:
                start = int(item.get("line_start", 0) or 0)
                end = int(item.get("line_end", start) or start)
            except (TypeError, ValueError):
                continue
            # Keep the model honest: only report on lines the diff touched.
            if added and start not in added:
                continue
            description = str(item.get("description", "")).strip()
            if not description:
                continue
            issues.append(
                Issue(
                    file=df.path,
                    line_start=start,
                    line_end=max(start, end),
                    severity=severity,
                    description=description,
                    suggested_fix=str(item.get("suggested_fix", "")).strip(),
                )
            )
        return issues


def get_review_llm() -> ReviewLLM:
    """Pick the reviewer named by LLM_BACKEND, falling back to the mock."""
    from .local_model import LocalReviewLLM
    from .mock_model import MockReviewLLM
    from .openai_model import OpenAIReviewLLM

    backend = settings.llm_backend
    if backend == "mock":
        return MockReviewLLM()
    if backend == "local":
        return LocalReviewLLM() if settings.local_llm_available else MockReviewLLM()
    if backend == "openai":
        return OpenAIReviewLLM() if settings.openai_api_key else MockReviewLLM()
    # "auto": prefer the local model, so configuring it is enough to go offline.
    if settings.local_llm_available:
        return LocalReviewLLM()
    if settings.openai_api_key:
        return OpenAIReviewLLM()
    return MockReviewLLM()
