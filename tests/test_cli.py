"""The command-line scanner, including its CI exit codes."""
from __future__ import annotations

import json

import pytest

from security.cli import main

LEAKED = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    # Never let a CLI test reach osv.dev.
    from config import settings

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


def test_reports_findings_and_exits_zero_without_fail_on(repo, capsys):
    assert main([str(repo), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "github-pat" in out
    assert "file(s) scanned" in out


def test_secret_is_redacted_in_cli_output(repo, capsys):
    main([str(repo), "--no-color"])
    assert LEAKED not in capsys.readouterr().out


def test_json_output_is_a_valid_security_report(repo, capsys):
    assert main([str(repo), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {"summary", "findings", "counts_by_category", "degraded"} <= report.keys()
    assert LEAKED not in json.dumps(report)


def test_fail_on_high_exits_nonzero_when_a_high_finding_exists(repo, capsys):
    # The leaked PAT is high severity, so CI should block.
    assert main([str(repo), "--fail-on", "high", "--no-color"]) == 1


def test_fail_on_high_exits_zero_on_a_clean_tree(tmp_path, monkeypatch, capsys):
    from config import settings

    monkeypatch.setattr(settings, "security_offline", True)
    monkeypatch.setattr(settings, "security_triage", False)
    clean = "def add(a, b):\n    return a + b\n"
    (tmp_path / "ok.py").write_text(clean, encoding="utf-8")
    assert main([str(tmp_path), "--fail-on", "high", "--no-color"]) == 0


def test_suppression_file_is_honoured_by_the_cli(repo, capsys):
    (repo / ".secscanignore").write_text("app/**:github-pat\n", encoding="utf-8")
    main([str(repo), "--no-color"])
    out = capsys.readouterr().out
    assert "github-pat" not in out
    assert "suppressed" in out


def test_a_missing_directory_is_a_usage_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope"), "--no-color"]) == 2
    assert "not a directory" in capsys.readouterr().err
