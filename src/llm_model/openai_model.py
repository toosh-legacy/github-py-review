"""Backend for the hosted OpenAI API (model from OPENAI_MODEL)."""
from __future__ import annotations

from config import settings

from .base import ChatLLM


class OpenAILLM(ChatLLM):
    def __init__(self) -> None:
        from openai import OpenAI  # lazy: only needed when a key is set

        self.client = OpenAI(api_key=settings.openai_api_key)
        self.model = settings.openai_model
