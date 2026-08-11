"""Git-history secret scanning, against a real temporary repository.

The case this exists for: a credential committed and then deleted. It is still
in the repository, still readable by anyone who clones it, and still live unless
someone rotated it — and a working-tree scan cannot see it at all.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest
from synthetic import AWS_KEY_ID as OTHER
from synthetic import GITHUB_PAT as LEAKED

from reposec.detectors import history as history_mod
from reposec.detectors.history import Commit, is_repo, scan_history

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


def test_a_multi_commit_history_reports_exactly_what_it_used_to(repo):
    # The scan streams the log instead of collecting it into a list first, so
    # this pins down the whole observable result — which secrets, on which
    # commit, in which order — against a history with enough shape to catch a
    # reordering or a lost deduplication.
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "leak the pat")
    commit(repo, "b.py", "x = 1\n", "unrelated")
    commit(repo, "c.py", f'A = "{OTHER}"\n', "leak the aws key")
    commit(repo, "a.py", "T = None\n", "clean up the pat")
    commit(repo, "d.py", f'T = "{LEAKED}"\n', "re-add the pat elsewhere")

    findings, degraded = scan_history(str(repo))

    assert degraded == []
    # Newest-first walk: the PAT is sighted first (in d.py) so it is reported
    # first, but it is attributed back to a.py, where it entered the repository.
    assert [(f.rule_id, f.file) for f in findings] == [
        ("github-pat", "a.py"),
        ("aws-access-key-id", "c.py"),
    ]


def test_the_log_is_consumed_one_commit_at_a_time(repo, monkeypatch):
    # The reason for streaming is peak memory: `git log --patch` over a repo
    # that vendored its dependencies is gigabytes, and collecting it into a list
    # holds all of it at once. Interleaved yields and scans are the observable
    # proof that only one commit's diff is alive at a time.
    order: list[str] = []

    def fake_blobs(_repo, _max_commits):
        for i in range(3):
            order.append(f"yielded f{i}.py")
            yield Commit(f"{i:040x}", "Test", "2026-01-01"), f"f{i}.py", "x = 1\n"

    real_is_scannable = history_mod.is_scannable

    def spy(path):
        order.append(f"scanned {path}")
        return real_is_scannable(path)

    monkeypatch.setattr(history_mod, "iter_added_blobs", fake_blobs)
    monkeypatch.setattr(history_mod, "is_scannable", spy)

    scan_history(str(repo))

    assert order == [
        "yielded f0.py",
        "scanned f0.py",
        "yielded f1.py",
        "scanned f1.py",
        "yielded f2.py",
        "scanned f2.py",
    ]


def test_a_shallow_clone_says_so_instead_of_reporting_all_clear(repo, tmp_path):
    # `--max-count` never trips on a `fetch-depth: 1` checkout, so without this
    # note an unscanned history is indistinguishable from a clean one. Cloning
    # through a file:// URL because `--depth` is ignored for plain local paths.
    commit(repo, "a.py", f'T = "{LEAKED}"\n', "leak")
    commit(repo, "a.py", "T = None\n", "clean up")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow)],
        check=True, capture_output=True, encoding="utf-8", errors="replace",
    )

    findings, degraded = scan_history(str(shallow))

    assert any("shallow clone" in d for d in degraded)
    # The point of the note: the secret really is invisible from here.
    assert findings == []


def test_a_full_clone_is_not_flagged_as_shallow(repo, tmp_path):
    commit(repo, "a.py", "x = 1\n", "clean")
    full = tmp_path / "full"
    subprocess.run(
        ["git", "clone", "-q", repo.as_uri(), str(full)],
        check=True, capture_output=True, encoding="utf-8", errors="replace",
    )
    assert scan_history(str(full)) == ([], [])
