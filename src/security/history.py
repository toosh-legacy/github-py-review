"""Secret scanning over git history.

A secret deleted in a later commit is still in the repository. Anyone who clones
it can read it, and unless it was rotated it is still live — which is precisely
the case secret scanning exists for. Scanning only the working tree misses every
one of them.

This runs against a local clone rather than the API, because history is the one
thing you cannot fetch cheaply over REST: reconstructing it would take a request
per blob. `git log --patch` gives the whole thing in a single subprocess call,
so the CLI (`security.cli`) owns this and the HTTP server keeps its guarantee of
never reaching into a repository the caller did not send.

Findings carry the commit, author and date, because "this key was live for two
years" and "someone added it yesterday" call for very different responses.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from schemas import SecurityFinding

from .common import finding_id, is_scannable
from .secrets_scan import scan_file

# `git log -p` output, walked line by line. Only added lines are scanned: a
# removed line was already in an earlier commit's added set, so scanning both
# would report every secret twice.
_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{7,40})")
_AUTHOR_RE = re.compile(r"^Author:\s*(.+)$")
_DATE_RE = re.compile(r"^Date:\s*(.+)$")
_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")


@dataclass(frozen=True)
class Commit:
    sha: str
    author: str
    date: str

    @property
    def short(self) -> str:
        return self.sha[:12]


class GitUnavailable(RuntimeError):
    """git is missing, or the path is not a repository."""


def _run_git(repo: str, *args: str, timeout: int = 300) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True,
            # Repositories contain non-UTF-8 bytes in old commits and author
            # names; replace rather than crash the scan.
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise GitUnavailable("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitUnavailable(f"git timed out after {timeout}s") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise GitUnavailable(detail[-1] if detail else f"git exited {proc.returncode}")
    return proc.stdout or ""


def is_repo(path: str) -> bool:
    try:
        return _run_git(path, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitUnavailable:
        return False


def iter_added_blobs(repo: str, max_commits: int):
    """Yield (commit, path, added_text) for each file touched by each commit.

    Added lines are accumulated per (commit, file) and scanned as one blob, so a
    multi-line secret such as a PEM private key is still detectable — scanning
    line by line would never match its BEGIN/END envelope.
    """
    log = _run_git(
        repo,
        "log",
        f"--max-count={max_commits}",
        "--patch",
        "--no-color",
        "--no-merges",
        # Rename detection off: a renamed file re-adds every line, which would
        # report the whole file as newly introduced secrets.
        "--no-renames",
        "--date=short",
    )

    commit: Commit | None = None
    sha = author = date = ""
    path: str | None = None
    added: list[str] = []

    def flush():
        if commit and path and added:
            return (commit, path, "\n".join(added))
        return None

    for line in log.splitlines():
        m = _COMMIT_RE.match(line)
        if m:
            pending = flush()
            if pending:
                yield pending
            path, added = None, []
            sha, author, date = m.group(1), "", ""
            commit = None
            continue
        if not sha:
            continue
        if not commit:
            a = _AUTHOR_RE.match(line)
            if a:
                author = a.group(1).strip()
                continue
            d = _DATE_RE.match(line)
            if d:
                date = d.group(1).strip()
                commit = Commit(sha, author, date)
                continue
        f = _FILE_RE.match(line)
        if f:
            pending = flush()
            if pending:
                yield pending
            path, added = f.group(1), []
            continue
        if path and line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])

    pending = flush()
    if pending:
        yield pending


def scan_history(
    repo: str, *, max_commits: int = 1000
) -> tuple[list[SecurityFinding], list[str]]:
    """Scan added lines across history for secrets. Returns (findings, degraded).

    Deduplicated by (rule, redacted value): one credential committed, reverted
    and re-added is one problem to rotate, not three. The earliest commit that
    introduced it is the one reported, because that is how long it has been
    exposed.
    """
    if not is_repo(repo):
        return [], [f"history: {repo} is not a git repository — history not scanned"]

    degraded: list[str] = []

    try:
        blobs = list(iter_added_blobs(repo, max_commits))
    except GitUnavailable as exc:
        return [], [f"history: {exc} — history not scanned"]

    # Keep the pristine finding next to the oldest commit that introduced it, so
    # the annotation is applied exactly once at the end. Annotating in place
    # would stack a title suffix and an explanation paragraph per commit.
    seen: dict[tuple[str, str], tuple[SecurityFinding, Commit, str]] = {}

    for commit, path, text in blobs:
        if not is_scannable(path):
            continue
        for f in scan_file(path, text):
            # `git log` walks newest first, so each later sighting is an older
            # commit — and the oldest introduction is the one worth reporting,
            # because it is how long the credential has been exposed.
            seen[(f.rule_id, f.evidence)] = (f, commit, path)

    findings = [_with_commit(f, commit, path) for f, commit, path in seen.values()]
    if len(blobs) and max_commits and len({c.sha for c, _, _ in blobs}) >= max_commits:
        degraded.append(
            f"history: stopped at --max-commits={max_commits}; older commits "
            "were not scanned"
        )
    return findings, degraded


def _with_commit(f: SecurityFinding, commit: Commit, path: str) -> SecurityFinding:
    """Re-anchor a finding onto the commit that introduced it."""
    return f.model_copy(
        update={
            "id": finding_id("history", f.rule_id, commit.sha, path, f.line_start),
            "file": path,
            # A line number in a historical diff does not correspond to any line
            # in the checked-out file, so it would only mislead.
            "line_start": 0,
            "line_end": 0,
            "title": f"{f.title} (in git history)",
            "explanation": (
                f"{f.explanation}\n\nIntroduced in commit {commit.short} "
                f"by {commit.author or 'unknown'} on {commit.date or 'unknown date'}, "
                f"in {path}. Deleting the line in a later commit does not remove "
                "it — the blob is still in the repository and readable by anyone "
                "who clones it."
            ).strip(),
        }
    )
