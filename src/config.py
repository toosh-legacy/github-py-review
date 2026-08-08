"""Central configuration via pydantic-settings.

Everything the project needs is read from the environment (or a local `.env`)
through a single `settings` object, so there is no scattered `os.getenv` and no
secrets baked into code. See `.env.example` for the full list.

Note what is *not* required: nothing here has to be set for the scanner to work.
Detection is deterministic — secret rules, OSV, bandit, eslint — and an LLM only
affects triage.
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

    # --- Database. Defaults to local SQLite for zero-setup dev; docker-compose
    #     and Fly override this with Postgres. ---
    database_url: str = Field(default="sqlite:///./scans.sqlite3", alias="DATABASE_URL")

    # --- CORS: origins allowed to call the API. The extension's service worker
    #     holds an explicit host permission and is not a CORS caller, so this
    #     only has to cover browser-page callers such as the dashboard. ---
    allowed_origins: str = Field(
        default="http://localhost:8501,https://github.com", alias="ALLOWED_ORIGINS"
    )

    # --- Security scanner ---------------------------------------------------
    # Detection is deterministic (regex/entropy, OSV, bandit, eslint). The LLM
    # only deduplicates, ranks, explains, and suggests fixes — turn it off and
    # the scan still works, with the rule-authored explanations instead.
    security_triage: bool = Field(default=True, alias="SECURITY_TRIAGE")
    # Skip the OSV lookup entirely (air-gapped runs). The dependency detector
    # then reports itself as degraded rather than returning a false all-clear.
    security_offline: bool = Field(default=False, alias="SECURITY_OFFLINE")
    # A scan submits whole file contents, so it needs a bound: the extension can
    # otherwise post a monorepo at the server.
    max_scan_files: int = Field(default=2_000, alias="MAX_SCAN_FILES")
    max_scan_bytes: int = Field(default=20_000_000, alias="MAX_SCAN_BYTES")

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def local_llm_available(self) -> bool:
        """True when a local OpenAI-compatible server has been configured."""
        return bool(self.local_llm_base_url)

    @property
    def active_backend(self) -> Literal["mock", "local", "openai"]:
        """Which backend `get_llm()` will actually pick, as a label.

        Mirrors the selection in `llm_model/base.py:get_llm` so `/health` and the
        dashboard report the real backend instead of guessing. "mock" means no
        model is configured: detection still runs, triage is skipped.
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
