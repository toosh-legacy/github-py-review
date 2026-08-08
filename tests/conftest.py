"""Shared test defaults.

No test may reach the network. The detector tests stub OSV explicitly; this is
the backstop for anything that forgets, so a CI run cannot start depending on
osv.dev being up.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_network_or_model(monkeypatch):
    from reposec.config import settings

    # Triage off: the LLM is scored separately, and no unit test should spend
    # tokens or wait on a model.
    monkeypatch.setattr(settings, "security_triage", False, raising=False)
    monkeypatch.setattr(settings, "llm_backend", "mock", raising=False)
