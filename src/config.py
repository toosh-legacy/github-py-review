"""Central configuration via pydantic-settings.

Everything the project needs is read from the environment (or a local `.env`)
through a single `settings` object, so there is no scattered `os.getenv` and no
secrets baked into code. See `.env.example` for the full list.
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

    # --- LLM (OpenAI; not required until Phase 3 — mock mode runs without it) ---
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    # Exact model string is supplied by the user (e.g. a gpt-5-codex/gpt-5-class id).
    openai_model: str = Field(default="gpt-5-codex", alias="OPENAI_MODEL")

    # --- Local LLM (Ollama / llama.cpp / vLLM — any OpenAI-compatible server).
    #     Nothing leaves the machine, and no API key is needed. Point
    #     LOCAL_LLM_BASE_URL at the server's /v1 endpoint. ---
    local_llm_base_url: str | None = Field(default=None, alias="LOCAL_LLM_BASE_URL")
    # On CPU-only machines prefer a small model (qwen2.5-coder:3b / :1.5b); the
    # 7b default assumes a GPU. Override with LOCAL_LLM_MODEL.
    local_llm_model: str = Field(
        default="qwen2.5-coder:3b", alias="LOCAL_LLM_MODEL"
    )

    # Which reviewer to use. "auto" prefers local, then OpenAI, then mock —
    # so setting LOCAL_LLM_BASE_URL is all it takes to go fully offline.
    llm_backend: Literal["auto", "local", "openai", "mock"] = Field(
        default="auto", alias="LLM_BACKEND"
    )

    # --- Precision controls. Small local models over-report; these are the
    #     levers that trade a little recall for a lot fewer false positives. ---
    # Second LLM pass that must confirm each candidate issue before it ships.
    verify_findings: bool = Field(default=True, alias="VERIFY_FINDINGS")
    # Drop anything below this severity from the final report.
    min_severity: Literal["high", "medium", "low"] = Field(
        default="low", alias="MIN_SEVERITY"
    )

    # --- GitHub (diff fetch in Phase 3; write scope only for post-comment route) ---
    github_token: str | None = Field(default=None, alias="GITHUB_TOKEN")

    # --- Database. Defaults to local SQLite for zero-setup dev; docker-compose
    #     overrides this with the Postgres `reviewdb` the spec mandates. ---
    database_url: str = Field(
        default="sqlite:///./reviewdb.sqlite3", alias="DATABASE_URL"
    )

    # --- CORS: origins allowed to call the API (Streamlit app + github.com). ---
    allowed_origins: str = Field(
        default="http://localhost:8501,https://github.com", alias="ALLOWED_ORIGINS"
    )

    # --- Guardrails: protect token budget/cost from oversized PRs. ---
    max_diff_bytes: int = Field(default=200_000, alias="MAX_DIFF_BYTES")
    max_files: int = Field(default=50, alias="MAX_FILES")

    # --- Security scanner ---------------------------------------------------
    # Detection is deterministic (regex/entropy, OSV, bandit, eslint). The LLM
    # only deduplicates, ranks, explains, and suggests fixes — turn it off and
    # the scan still works, with the rule-authored explanations instead.
    security_triage: bool = Field(default=True, alias="SECURITY_TRIAGE")
    # Skip the OSV lookup entirely (air-gapped runs). The dependency detector
    # then reports itself as degraded rather than returning a false all-clear.
    security_offline: bool = Field(default=False, alias="SECURITY_OFFLINE")
    # A repo scan submits whole files, so the caps are larger than the diff
    # caps but still bounded — the extension can otherwise post a monorepo.
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
    def llm_available(self) -> bool:
        """True when a real (non-mock) reviewer can be used."""
        return self.active_backend != "mock"

    @property
    def active_backend(self) -> Literal["mock", "local", "openai"]:
        """Which reviewer `get_review_llm()` will actually pick, as a label.

        Mirrors the selection in `llm_model/base.py:get_review_llm` so `/health`
        (and the dashboard) can report the real backend instead of guessing.
        """
        if self.llm_backend == "mock":
            return "mock"
        if self.llm_backend == "local":
            return "local" if self.local_llm_available else "mock"
        if self.llm_backend == "openai":
            return "openai" if self.openai_api_key else "mock"
        # "auto": prefer local, then OpenAI, then mock.
        if self.local_llm_available:
            return "local"
        if self.openai_api_key:
            return "openai"
        return "mock"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
