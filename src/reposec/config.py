"""Central configuration via pydantic-settings.

Everything is read from the environment (or a local `.env`) through a single
`settings` object, so there is no scattered `os.getenv` and no secrets baked
into code. Command-line flags override these where both exist. See
`.env.example` for the full list.

Note what is *not* required: nothing here has to be set. Detection is
deterministic — secret rules, OSV, bandit, eslint-plugin-security — and a model
only affects triage.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- LLM. Optional: it powers triage only, never detection. ---
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    # Exact model string is supplied by the user (e.g. a gpt-5-class id).
    openai_model: str = Field(default="gpt-5-codex", alias="OPENAI_MODEL")

    # --- Local LLM (Ollama / llama.cpp / vLLM — any OpenAI-compatible server).
    #     Nothing leaves the machine, and no API key is needed. Point
    #     LOCAL_LLM_BASE_URL at the server's /v1 endpoint. ---
    local_llm_base_url: str | None = Field(default=None, alias="LOCAL_LLM_BASE_URL")
    # On CPU-only machines prefer a small model (qwen2.5-coder:3b / :1.5b); the
    # 7b default assumes a GPU. Override with LOCAL_LLM_MODEL.
    local_llm_model: str = Field(default="qwen2.5-coder:3b", alias="LOCAL_LLM_MODEL")

    # Which backend to use. "auto" prefers local, then OpenAI, then none — so
    # setting LOCAL_LLM_BASE_URL is all it takes to go fully offline.
    llm_backend: Literal["auto", "local", "openai", "mock"] = Field(
        default="auto", alias="LLM_BACKEND"
    )

    # --- Scanner ------------------------------------------------------------
    # Detection is deterministic (regex/entropy, OSV, bandit, eslint). The LLM
    # only deduplicates, ranks, explains, and suggests fixes — turn it off and
    # the scan still works, with the rule-authored explanations instead.
    security_triage: bool = Field(default=True, alias="SECURITY_TRIAGE")
    # Skip the OSV lookup entirely (air-gapped runs). The dependency detector
    # then reports itself as degraded rather than returning a false all-clear.
    security_offline: bool = Field(default=False, alias="SECURITY_OFFLINE")

    @property
    def local_llm_available(self) -> bool:
        """True when a local OpenAI-compatible server has been configured."""
        return bool(self.local_llm_base_url)

    @property
    def active_backend(self) -> Literal["mock", "local", "openai"]:
        """Which backend `get_llm()` will actually pick, as a label.

        Mirrors the selection in `reposec/llm.py:get_llm` so `--version` and
        the scan header report the real backend instead of guessing. "mock"
        means no model is configured: detection still runs, triage is skipped.
        """
        if self.llm_backend == "mock":
            return "mock"
        if self.llm_backend == "local":
            return "local" if self.local_llm_available else "mock"
        if self.llm_backend == "openai":
            return "openai" if self.openai_api_key else "mock"
        # "auto": prefer local, then OpenAI, then none.
        if self.local_llm_available:
            return "local"
        if self.openai_api_key:
            return "openai"
        return "mock"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
