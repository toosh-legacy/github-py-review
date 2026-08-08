"""The LLM seam: one JSON chat round-trip, behind a swappable implementation.

The scanner needs exactly one thing from a model — send a system and a user
prompt, get a JSON object back — so that is the entire contract. Both real
backends (a local OpenAI-compatible server and the hosted API) speak the same
chat-completions protocol, so they share everything except which client they
construct; that lives in `ChatLLM` here, and the subclasses are a constructor
each.

`NoLLM` is the null implementation, and it is deliberately not a stub that
fabricates output. Detection is deterministic and complete without a model, so
when none is configured the scanner skips triage and ships the rule-authored
explanations. Callers detect that with `isinstance(llm, ChatLLM)`.
"""
from __future__ import annotations

import json

from config import settings


def loads_lenient(raw: str) -> dict | None:
    """Parse a model's JSON reply, tolerating the wrappers small models add.

    Local models honour `response_format` less reliably than the hosted API and
    often fence the object in ```json ... ``` or prepend a sentence. Rather than
    throwing the whole reply away, recover the outermost JSON object.
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


class ChatLLM:
    """One JSON-mode chat round-trip over an OpenAI-compatible client.

    Subclasses only build `self.client` and set `self.model`.
    """

    client: object
    model: str

    # Low temperature: triage should be reproducible. Sampling diversity buys
    # nothing here but inconsistent severities between runs of the same scan.
    temperature = 0.0

    def chat_json(self, system: str, user: str) -> tuple[dict | None, int]:
        """Returns (parsed reply, tokens_used). Raises on transport failure."""
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


class NoLLM:
    """No model configured. Triage is skipped; detection is unaffected."""


def get_llm() -> ChatLLM | NoLLM:
    """Pick the backend named by LLM_BACKEND, falling back to no model."""
    from .local_model import LocalLLM
    from .openai_model import OpenAILLM

    backend = settings.llm_backend
    if backend == "mock":
        return NoLLM()
    if backend == "local":
        return LocalLLM() if settings.local_llm_available else NoLLM()
    if backend == "openai":
        return OpenAILLM() if settings.openai_api_key else NoLLM()
    # "auto": prefer the local model, so configuring it is enough to go offline.
    if settings.local_llm_available:
        return LocalLLM()
    if settings.openai_api_key:
        return OpenAILLM()
    return NoLLM()
