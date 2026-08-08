"""Git-history secret scanning, against a real temporary repository.

The case this exists for: a credential committed and then deleted. It is still
in the repository, still readable by anyone who clones it, and still live unless
someone rotated it — and a working-tree scan cannot see it at all.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from reposec.detectors.history import is_repo, scan_history

LEAKED = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
OTHER = "AKIA4NHQ7ZP2VXK3MTBW"

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not installed"
)


def git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "test@example.invalid")
    git(r, "config", "user.name", "Test")
    git(r, "config", "commit.gpgsign", "false")
    return r


def commit(repo, name, content, message):
    (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def test_finds_a_secret_that_was_committed_then_deleted(repo):
    commit(repo, "config.py", f'TOKEN = "{LEAKED}"\n', "add config")
    commit(repo, "config.py", "TOKEN = os.environ['TOKEN']\n", "remove the secret")

    findings, degraded = scan_history(str(repo))

    assert degraded == []
    assert [f.rule_id for f in findings] == ["github-pat"]
    # The working tree is clean at this point — only history knows.
    assert "config.py" not in (repo / "config.py").read_text(encoding="utf-8")


def test_the_finding_names_the_commit_that_introduced_it(repo):
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "leak it")
    commit(repo, "a.py", "T = None\n", "clean it up")

    finding = scan_history(str(repo))[0][0]
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--max-parents=0", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    assert sha[:12] in finding.explanation
    assert "Test" in finding.explanation
    assert "in git history" in finding.title


def test_the_secret_is_redacted_in_history_findings_too(repo):
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "leak it")
    findings, _ = scan_history(str(repo))
    assert LEAKED not in str([f.model_dump() for f in findings])
    assert "*" in findings[0].evidence


def test_one_credential_across_many_commits_is_one_finding(repo):
    # Committed, reverted, re-added: one thing to rotate, not three.
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "add")
    commit(repo, "a.py", "T = None\n", "remove")
    commit(repo, "b.py", f'T = "{LEAKED}"\n', "add again elsewhere")

    findings, _ = scan_history(str(repo))
    assert len(findings) == 1


def test_the_oldest_introduction_is_the_one_reported(repo):
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "first")
    commit(repo, "b.py", "x = 1\n", "unrelated")
    commit(repo, "c.py", f'T = "{LEAKED}"\n', "again")

    finding = scan_history(str(repo))[0][0]
    # a.py is where it entered the repository; that is how long it was exposed.
    assert finding.file == "a.py"


def test_a_multi_line_private_key_is_still_matched(repo):
    # Scanning line by line would never see the BEGIN/END envelope.
    key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEArandomlookingbase64content\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    commit(repo, "id_rsa", key, "oops")
    findings, _ = scan_history(str(repo))
    assert "private-key" in {f.rule_id for f in findings}


def test_history_findings_carry_no_misleading_line_number(repo):
    # A line number in a historical diff maps to nothing in the checked-out file.
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "leak")
    finding = scan_history(str(repo))[0][0]
    assert finding.line_start == 0 and finding.line_end == 0


def test_vendored_paths_are_skipped_in_history_too(repo):
    (repo / "node_modules").mkdir()
    commit(repo, "node_modules/x.js", f'const t = "{LEAKED}";\n', "vendored")
    findings, _ = scan_history(str(repo))
    assert findings == []


def test_clean_history_produces_nothing(repo):
    commit(repo, "a.py", "def add(a, b):\n    return a + b\n", "clean")
    assert scan_history(str(repo)) == ([], [])


def test_max_commits_is_reported_when_it_truncates(repo):
    for i in range(4):
        commit(repo, f"f{i}.py", f"x = {i}\n", f"commit {i}")
    _, degraded = scan_history(str(repo), max_commits=2)
    assert any("max-commits" in d for d in degraded)


def test_a_non_repository_degrades_instead_of_raising(tmp_path):
    findings, degraded = scan_history(str(tmp_path))
    assert findings == []
    assert any("not a git repository" in d for d in degraded)
    assert not is_repo(str(tmp_path))


def test_two_distinct_secrets_are_two_findings(repo):
    commit(repo, "a.py", f'T = "{LEAKED}"\nA = "{OTHER}"\n', "two leaks")
    findings, _ = scan_history(str(repo))
    assert {f.rule_id for f in findings} == {"github-pat", "aws-access-key-id"}
