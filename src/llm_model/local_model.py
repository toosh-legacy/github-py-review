"""Backend for a local OpenAI-compatible server.

Works with Ollama (`http://localhost:11434/v1`), llama.cpp's server, vLLM,
LM Studio — anything speaking the chat-completions API. Nothing leaves the
machine and no API key is needed, which matters here: triage prompts contain
source code, even though credentials are redacted before they are built.
"""
from __future__ import annotations

from config import settings

from .base import ChatLLM


class LocalLLM(ChatLLM):
    def __init__(self) -> None:
        from openai import OpenAI  # lazy: the SDK is only the transport here

        self.client = OpenAI(
            base_url=settings.local_llm_base_url,
            api_key="local",  # ignored by local servers; the SDK requires a value
            timeout=180.0,  # local generation on CPU/consumer GPU is slow
            max_retries=1,
        )
        self.model = settings.local_llm_model
