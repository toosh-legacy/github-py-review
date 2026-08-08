"""Guard the benchmark score so precision regressions fail CI.

The eval harness is the project's claim to credibility; without a test it only
gets run when someone remembers to. These floors are deliberately below the
current score (1.00 across the board) so ordinary rule tuning does not trip
them, but any real loss of precision or recall does.

The benchmark measures the scanner against a fixture written alongside it, so a
perfect score means "no regression", not "solved". Real-world precision is a
separate question that only real repositories can answer.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parents[1] / "src" / "evaluation"
BENCH = EVAL / "security_benchmark"


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "run_security_eval", EVAL / "run_security_eval.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_security_eval"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scored():
    harness = _load_harness()
    harness.install_osv_snapshot()  # never touch the network from a test

    from reposec.config import settings

    settings.security_triage = False  # detection only; the LLM is scored apart

    from reposec.graph import run_security_scan

    truth = harness.load_ground_truth()
    report = run_security_scan(files=harness.load_repo(), repo="benchmark/fixture")

    if any("code(python)" in d for d in report.degraded):
        pytest.skip("bandit is not installed in this environment")

    secrets, code = harness.score_locations(report.findings, truth)
    deps, notes = harness.score_dependencies(report.findings, report, truth)
    return {
        "secrets": secrets,
        "code": code,
        "deps": deps,
        "notes": notes,
        "report": report,
        "eslint": not any("code(js)" in d for d in report.degraded),
    }


def test_secret_detector_holds_its_score(scored):
    s = scored["secrets"]
    assert s.recall >= 0.95, f"missed planted secrets: {s.missed}"
    # Precision is the binding constraint: a secret scanner that cries wolf on
    # .env.example files gets muted within a day.
    assert s.precision == 1.0, f"false positives on decoys: {s.false_positives}"


def test_dependency_detector_holds_its_score(scored):
    d = scored["deps"]
    assert d.recall == 1.0, f"missed vulnerable packages: {d.missed}"
    assert d.precision == 1.0, f"flagged clean packages: {d.false_positives}"
    assert scored["notes"] == []


def test_code_detector_holds_its_score(scored):
    c = scored["code"]
    if not scored["eslint"]:
        pytest.skip("eslint-plugin-security is not installed in this environment")
    assert c.recall >= 0.9, f"missed planted patterns: {c.missed}"
    assert c.precision >= 0.9, f"fired on safe code: {c.false_positives}"


def test_decoy_files_produce_nothing(scored):
    truth = _load_harness().load_ground_truth()
    decoys = {e["file"] for e in truth["decoy_files"]}
    fired = {f.file for f in scored["report"].findings} & decoys
    assert not fired, f"example/vendored files must never produce findings: {fired}"


def test_unpinned_dependency_is_reported_not_guessed(scored):
    # Silently resolving `urllib3>=1.26` to some version would mean reporting
    # advisories for a release the repo may not install.
    assert any("urllib3" in d for d in scored["report"].degraded)


def test_ground_truth_and_fixture_stay_in_sync():
    truth = json.loads((BENCH / "ground_truth.json").read_text(encoding="utf-8"))
    for entry in truth["planted"] + truth["decoys"]:
        path = BENCH / "repo" / entry["file"]
        assert path.is_file(), f"ground truth references a missing file: {entry['file']}"
        lines = path.read_text(encoding="utf-8").splitlines()
        assert entry["line"] <= len(lines), (
            f"{entry['file']}:{entry['line']} is past the end of the file — "
            "the fixture moved but ground_truth.json did not"
        )


def test_osv_snapshot_is_present_and_populated():
    # Without it the dependency score silently becomes a live-network measurement.
    snapshot = json.loads((BENCH / "osv_snapshot.json").read_text(encoding="utf-8"))
    assert snapshot["hits"] and snapshot["vulns"]
