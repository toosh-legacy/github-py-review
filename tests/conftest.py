"""Shared test fixtures: an isolated SQLite DB and a TestClient per test.

Each test gets a fresh temp database so history assertions are deterministic,
and `LLM_BACKEND=mock` so no test ever reaches for a network model.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Point the app at a throwaway SQLite file BEFORE importing app modules so
    # the cached settings/engine pick it up.
    db_path = tmp_path / "test.sqlite3"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("LLM_BACKEND", "mock")

    # Clear cached settings so the new env vars take effect.
    import config

    config.get_settings.cache_clear()
    config.settings = config.get_settings()

    # Re-bind the engine to the test DB, then rebuild the app on top of it.
    import database.session

    importlib.reload(database.session)

    import backend.main

    importlib.reload(backend.main)

    from fastapi.testclient import TestClient

    with TestClient(backend.main.app) as c:
        yield c
