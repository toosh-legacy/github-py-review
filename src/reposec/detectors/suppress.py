"""Suppression: the escape hatch that keeps the scanner usable.

Every real repository has findings that are correct but not actionable — a
documented example token in a README, a credential-shaped fixture in a test, a
deliberately vulnerable file in a security test suite. Without a way to say so,
the first scan produces noise the user cannot clear, and the tool gets ignored.

Rules live in a `.secscanignore` file at the repo root, gitignore-flavoured:

    # comment
    docs/**                     suppress every finding under docs/
    tests/fixtures/*.py         glob on the path
    tests/**:github-pat         only that rule, only under tests/
    :B101                       that rule, anywhere

Suppressed findings are *dropped*, not hidden with a flag, because a report the
user has to mentally filter is the thing this exists to prevent. The count is
reported separately so a suppression file that silences everything is visible
rather than silent.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from reposec.schemas import SecurityFinding

SUPPRESS_FILE = ".secscanignore"


@dataclass(frozen=True)
class SuppressRule:
    """One line of a suppression file: an optional path glob and/or rule id."""

    path_glob: str = ""
    rule_id: str = ""

    def matches(self, finding: SecurityFinding) -> bool:
        if self.rule_id and self.rule_id != finding.rule_id:
            return False
        if self.path_glob and not _path_matches(self.path_glob, finding.file):
            return False
        # A line with neither half would suppress everything; parse() rejects it.
        return bool(self.rule_id or self.path_glob)


def _path_matches(glob: str, path: str) -> bool:
    path = path.replace("\\", "/").lstrip("./")
    glob = glob.replace("\\", "/").lstrip("./")
    if fnmatch(path, glob):
        return True
    # `docs/**` should match `docs/a.md` and `docs/a/b.md`; fnmatch's `*` already
    # crosses separators, but the bare-directory form needs an explicit prefix
    # check so `docs/` and `docs` behave the way a .gitignore reader expects.
    prefix = glob.rstrip("/").removesuffix("/**")
    return path.startswith(prefix + "/") if prefix else False


def parse(text: str) -> list[SuppressRule]:
    """Parse a `.secscanignore`. Unparseable lines are skipped, not fatal."""
    rules: list[SuppressRule] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        path_glob, _, rule_id = line.partition(":")
        path_glob, rule_id = path_glob.strip(), rule_id.strip()
        if not path_glob and not rule_id:
            continue
        rules.append(SuppressRule(path_glob, rule_id))
    return rules


def load_rules(files: list[tuple[str, str]]) -> list[SuppressRule]:
    """Pull suppression rules out of the submitted files, if one is present."""
    for path, content in files:
        if path.replace("\\", "/").rsplit("/", 1)[-1] == SUPPRESS_FILE:
            return parse(content)
    return []


def apply(
    findings: list[SecurityFinding], rules: list[SuppressRule]
) -> tuple[list[SecurityFinding], int]:
    """Drop suppressed findings. Returns (kept, suppressed_count)."""
    if not rules:
        return findings, 0
    kept = [f for f in findings if not any(r.matches(f) for r in rules)]
    return kept, len(findings) - len(kept)
