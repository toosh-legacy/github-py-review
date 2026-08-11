"""Shared fixtures for the quality suite.

These tests measure the product rather than a unit of it: how noisy the scanner
is on code nobody wrote for it, and how fast it gets through a repository. They
are slower than the rest of the suite by construction — they shell out to bandit
and eslint over hundreds of kLOC — so they carry the `quality` marker and can be
deselected with `-m "not quality"`.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from harness import load_harness

# Enough code for a rate to mean something, small enough to run on every pull
# request. 400 files of installed packages is roughly 110 kLOC.
FP_CORPUS_FILES = 400


@pytest.fixture(scope="session")
def bandit_available() -> bool:
    """Whether the Python analyzer can run at all in this environment.

    Without it the noise measurement is meaningless rather than merely lower, so
    the tests skip instead of quietly passing against a half-scan.
    """
    from reposec.detectors.code import _run_bandit

    with tempfile.TemporaryDirectory() as tmp:
        _, error = _run_bandit(Path(tmp))
    return error is None


@pytest.fixture(scope="session")
def noise():
    """Scan real third-party code once and share the measurement.

    Session-scoped because it costs the better part of a minute; running it per
    test would put that into every suite.
    """
    harness = load_harness("run_fp_eval")
    corpus = harness.collect_corpus(None, FP_CORPUS_FILES)
    if len(corpus) < 100:
        pytest.skip("no third-party packages installed to scan")
    return harness.measure(corpus)
