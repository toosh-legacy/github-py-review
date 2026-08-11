"""The `reposec` command: output formats and the exit codes CI depends on.

Exit codes are a contract — a CI pipeline breaks silently if they drift — so
each one is asserted rather than assumed.
"""
from __future__ import annotations

import json

import pytest
from synthetic import GITHUB_PAT as LEAKED

from reposec.cli import EXIT_DEGRADED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    from reposec.config import settings

    # Never let a CLI test reach osv.dev.
    monkeypatch.setattr(settings, "security_offline", True)
    monkeypatch.setattr(settings, "security_triage", False)

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "config.py").write_text(
        f'TOKEN = "{LEAKED}"\n', encoding="utf-8"
    )
    unsafe_sql = (
        "def q(conn, uid):\n"
        '    return conn.execute("SELECT * FROM t WHERE id = " + uid)\n'
    )
    (tmp_path / "app" / "db.py").write_text(unsafe_sql, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def clean_repo(tmp_path, monkeypatch):
    from reposec.config import settings

    monkeypatch.setattr(settings, "security_offline", True)
    monkeypatch.setattr(settings, "security_triage", False)
    (tmp_path / "ok.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    return tmp_path


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_reports_findings_and_exits_zero_without_fail_on(repo, capsys):
    assert main(["scan", str(repo), "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "github-pat" in out
    assert "file(s) scanned" in out


def test_path_defaults_to_the_current_directory(clean_repo, monkeypatch, capsys):
    monkeypatch.chdir(clean_repo)
    assert main(["scan", "--no-color"]) == EXIT_OK
    assert "No findings." in capsys.readouterr().out


def test_secret_is_redacted_in_cli_output(repo, capsys):
    main(["scan", str(repo), "--no-color"])
    assert LEAKED not in capsys.readouterr().out


def test_json_output_is_a_valid_security_report(repo, capsys):
    assert main(["scan", str(repo), "--format", "json"]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert {"summary", "findings", "counts_by_category", "degraded"} <= report.keys()
    assert LEAKED not in json.dumps(report)


def test_no_color_flag_suppresses_escape_sequences(repo, capsys):
    main(["scan", str(repo), "--no-color"])
    assert "\033[" not in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# SARIF — what makes findings show up in GitHub's Security tab
# --------------------------------------------------------------------------- #
def test_sarif_output_is_well_formed(repo, capsys):
    assert main(["scan", str(repo), "--format", "sarif"]) == EXIT_OK
    doc = json.loads(capsys.readouterr().out)

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "reposec"
    assert run["results"], "no results emitted"

    levels = {r["level"] for r in run["results"]}
    assert levels <= {"error", "warning", "note"}, "SARIF has no 'medium' level"

    for result in run["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        # SARIF requires startLine >= 1; a history finding has line 0 internally.
        assert region["startLine"] >= 1
        assert result["ruleId"]
        assert result["partialFingerprints"]["reposecFindingId"]

    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {r["ruleId"] for r in run["results"]}


def test_sarif_never_contains_the_raw_secret(repo, capsys):
    main(["scan", str(repo), "--format", "sarif"])
    assert LEAKED not in capsys.readouterr().out


def test_sarif_carries_degraded_detectors(repo, capsys):
    # A machine-readable report that hid a detector which could not run would be
    # claiming coverage it does not have. The fixture has no manifest, so the
    # dependency detector always has something to say here.
    main(["scan", str(repo), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes, "degraded detectors were dropped from the SARIF output"
    assert any("dependency" in n["message"]["text"] for n in notes)
    assert all(n["level"] == "warning" for n in notes)


# --------------------------------------------------------------------------- #
# Exit codes
# --------------------------------------------------------------------------- #
def test_fail_on_high_exits_nonzero_when_a_high_finding_exists(repo):
    assert main(["scan", str(repo), "--fail-on", "high", "--no-color"]) == EXIT_FINDINGS


def test_fail_on_high_exits_zero_on_a_clean_tree(clean_repo):
    assert (
        main(["scan", str(clean_repo), "--fail-on", "high", "--no-color"]) == EXIT_OK
    )


def test_fail_on_low_catches_what_fail_on_high_lets_through(clean_repo, capsys):
    # A tree with only low findings passes --fail-on high and trips --fail-on low.
    # B311: `random` is fine for a jitter and wrong for a token, so bandit rates
    # it low — exactly the band this test needs.
    (clean_repo / "x.py").write_text(
        "import random\n\n\ndef token():\n    return random.random()\n",
        encoding="utf-8",
    )
    assert main(["scan", str(clean_repo), "--fail-on", "high", "--no-color"]) == EXIT_OK
    assert (
        main(["scan", str(clean_repo), "--fail-on", "low", "--no-color"])
        == EXIT_FINDINGS
    )


def test_strict_exits_three_when_a_detector_could_not_run(repo):
    # --offline degrades the dependency detector on purpose.
    code = main(["scan", str(repo), "--offline", "--strict", "--no-color"])
    assert code == EXIT_DEGRADED


def test_strict_is_separate_from_fail_on(clean_repo):
    # A degraded detector is not a finding: without --strict it stays exit 0.
    assert (
        main(["scan", str(clean_repo), "--offline", "--fail-on", "high", "--no-color"])
        == EXIT_OK
    )


def test_a_missing_directory_is_a_usage_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope"), "--no-color"]) == EXIT_USAGE
    assert "not a directory" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Flags and other commands
# --------------------------------------------------------------------------- #
def test_suppression_file_is_honoured(repo, capsys):
    (repo / ".secscanignore").write_text("app/**:github-pat\n", encoding="utf-8")
    main(["scan", str(repo), "--no-color"])
    out = capsys.readouterr().out
    assert "github-pat" not in out
    assert "suppressed" in out


def test_no_triage_flag_overrides_configuration(repo, monkeypatch, capsys):
    from reposec import triage as triage_module
    from reposec.config import settings

    seen: dict[str, object] = {}
    real = triage_module.triage

    def spy(findings, contexts=None, *, repo=None, enabled=None):
        seen["enabled"] = enabled
        return real(findings, contexts, repo=repo, enabled=enabled)

    monkeypatch.setattr(triage_module, "triage", spy)
    monkeypatch.setattr(settings, "security_triage", True)
    main(["scan", str(repo), "--no-triage", "--no-color"])

    assert seen["enabled"] is False
    # The flag applies to this scan and no other. `settings` is cached for the
    # life of the process, so writing the flag onto it would silently disable
    # triage for every later scan — in a long-lived host, and in the rest of
    # this suite, where it would show up as an order-dependent flake.
    assert settings.security_triage is True


def test_doctor_reports_each_detector(capsys):
    assert main(["doctor", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    for detector in ("secrets", "dependencies", "code (python)", "code (js/ts)"):
        assert detector in out
    assert "triage" in out


def test_version_is_reported(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "reposec" in capsys.readouterr().out


def test_no_subcommand_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == EXIT_USAGE


# --------------------------------------------------------------------------- #
# The exit code is a contract, so nothing may quietly return 1
# --------------------------------------------------------------------------- #
def test_an_unexpected_crash_does_not_look_like_findings(repo, monkeypatch, capsys):
    # Exit 1 means "findings at or above --fail-on" and nothing else. A crash
    # returning 1 is indistinguishable from a blocking scan, and CI treats the
    # two completely differently.
    from reposec import cli

    def boom(*_args, **_kwargs):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(cli, "read_repo", boom)
    assert main(["scan", str(repo), "--fail-on", "high", "--no-color"]) == EXIT_USAGE
    assert "RuntimeError" in capsys.readouterr().err


def test_a_bad_environment_variable_is_reported_not_traced(repo, monkeypatch, capsys):
    from pydantic import ValidationError

    from reposec import cli

    def invalid(*_args, **_kwargs):
        raise ValidationError.from_exception_data("Settings", [])

    monkeypatch.setattr(cli, "read_repo", invalid)
    assert main(["scan", str(repo), "--no-color"]) == EXIT_USAGE
    assert "invalid configuration" in capsys.readouterr().err


def test_non_ascii_source_does_not_kill_the_scan(clean_repo, capsys):
    # On a stock Windows console (cp1252) a single CJK identifier in one file
    # used to end the run in a UnicodeEncodeError, losing the whole scan on most
    # non-US repositories.
    (clean_repo / "unicode.py").write_text(
        'ключ = "значение"\n\n\ndef 处理(数据):\n    return eval(数据)\n',
        encoding="utf-8",
    )
    assert main(["scan", str(clean_repo), "--no-color"]) == EXIT_OK
    assert "unicode.py" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Configuration must not come from the repository being scanned
# --------------------------------------------------------------------------- #
def test_a_dotenv_in_the_scanned_repo_is_ignored(tmp_path, monkeypatch):
    # `reposec scan .` is run from inside the repository under scan, and that
    # repository is untrusted input. A .env there could otherwise point every
    # triage prompt at a server its author chose.
    (tmp_path / ".env").write_text(
        "LOCAL_LLM_BASE_URL=http://attacker.example/v1\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("REPOSEC_ENV_FILE", raising=False)
    monkeypatch.delenv("LOCAL_LLM_BASE_URL", raising=False)

    from reposec.config import Settings

    assert Settings().local_llm_base_url is None


def test_an_explicit_env_file_is_still_honoured(tmp_path, monkeypatch):
    # Contributors working on this repository are who the .env support is for,
    # so it stays available — opted into by name rather than found by accident.
    env = tmp_path / "custom.env"
    env.write_text("LOCAL_LLM_MODEL=qwen2.5-coder:1.5b\n", encoding="utf-8")
    monkeypatch.setenv("REPOSEC_ENV_FILE", str(env))
    monkeypatch.delenv("LOCAL_LLM_MODEL", raising=False)

    import importlib

    from reposec import config

    importlib.reload(config)
    try:
        assert config.Settings().local_llm_model == "qwen2.5-coder:1.5b"
    finally:
        monkeypatch.delenv("REPOSEC_ENV_FILE", raising=False)
        importlib.reload(config)


# --------------------------------------------------------------------------- #
# install-eslint
#
# It exists because the previous instruction was `npm install` inside the
# installed package — which is root-owned on a distro Python and read-only in a
# container image, and where it does work it leaves hundreds of untracked
# directories inside a pip-managed tree.
# --------------------------------------------------------------------------- #
def test_install_eslint_copies_the_assets_and_runs_npm(tmp_path, monkeypatch, capsys):
    import shutil as shutil_module
    import subprocess

    from reposec import cli

    monkeypatch.setattr(cli, "EXIT_OK", EXIT_OK)
    monkeypatch.setattr(shutil_module, "which", lambda name: f"/usr/bin/{name}")

    calls: list[dict] = []

    def fake_npm(cmd, **kwargs):
        calls.append({"cmd": cmd, "cwd": kwargs.get("cwd")})
        # Stand in for what npm would leave behind, so the post-install check
        # has something real to find.
        binary = tmp_path / "node_modules" / "eslint" / "bin" / "eslint.js"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!/usr/bin/env node\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_npm)
    monkeypatch.setenv("REPOSEC_ESLINT_DIR", str(tmp_path))

    assert main(["install-eslint", "--dir", str(tmp_path)]) == EXIT_OK
    assert calls, "npm was never invoked"
    command = calls[0]["cmd"]
    assert command[0].endswith("npm") and "install" in command
    assert calls[0]["cwd"] == str(tmp_path)
    # The config has to travel with the install: it resolves the plugin relative
    # to itself, so an install without it would find no rules.
    assert (tmp_path / "eslint.config.mjs").is_file()
    assert (tmp_path / "package.json").is_file()


def test_install_eslint_says_so_when_node_is_missing(monkeypatch, capsys):
    import shutil as shutil_module

    monkeypatch.setattr(shutil_module, "which", lambda name: None)
    assert main(["install-eslint"]) == EXIT_USAGE
    assert "Node.js and npm are required" in capsys.readouterr().err


def test_an_eslint_install_outside_the_package_is_found(tmp_path, monkeypatch):
    # The whole point of the override: a user-owned directory, not site-packages.
    from reposec.detectors.code import _eslint_binary

    binary = tmp_path / "node_modules" / "eslint" / "bin" / "eslint.js"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/usr/bin/env node\n", encoding="utf-8")

    monkeypatch.setenv("REPOSEC_ESLINT_DIR", str(tmp_path))
    assert _eslint_binary() == binary
