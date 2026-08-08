"""Detector 1 — exposed secrets, by regex fingerprint and Shannon entropy.

Runs the gitleaks-derived rules in `rules.py` over raw file contents. Two
mechanisms do the work and one does the filtering:

    fingerprint rules  match a provider's distinctive token shape
    entropy gate       stops generic `secret = "..."` rules from firing on
                       every ordinary string assignment in the repo
    placeholder filter drops the documented fakes — `.env.example`, `<your-key>`,
                       `xxxxx`, `changeme` — which are the single largest source
                       of false positives in real repositories

Findings carry a redacted evidence string. The raw secret is never returned,
stored, or sent to the LLM.
"""
from __future__ import annotations

import re

from reposec.schemas import SecurityFinding

from .common import (
    finding_id,
    is_scannable,
    looks_binary,
    redact,
    shannon_entropy,
)
from .rules import ALL_RULES, SecretRule

# Files that exist to *show* a fake credential. Findings here are noise.
_EXAMPLE_FILE_RE = re.compile(
    r"(?i)(^|/)(\.env\.(example|sample|template|dist)"
    r"|.*\.example($|\.)"
    r"|.*\.sample($|\.)"
    r"|.*\.template($|\.))"
)

# Documentation/test markers that mean "this is not a real value".
_PLACEHOLDER_TOKENS = (
    "example", "sample", "placeholder", "changeme", "change_me", "yourkey",
    "your_key", "your-key", "yoursecret", "your_secret", "dummy", "notreal",
    "fake", "insert", "redacted", "xxxxxx", "aaaaaa", "000000", "123456",
    "abcdef", "test-key", "testkey", "mykey", "foobar", "lorem",
)

_PLACEHOLDER_SHAPE_RE = re.compile(
    r"(\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]{2,}>|%\([a-z_]+\)s|\$[A-Z_]{3,})"
)

# Lines that read as documentation of the *format*, not a live value.
_ANNOTATION_RE = re.compile(r"(?i)\b(e\.g\.|for example|replace with|see docs)\b")

# Prose and documentation. A high-entropy string next to `SECRET_KEY` in a
# tutorial is almost always showing you what one looks like — Flask's own docs
# repeat the same 64-character example three times, and every scanner that
# treats it as a leak trains its users to ignore secret findings.
#
# This *downgrades* rather than suppresses, and only for the entropy-gated
# rules. A `ghp_…` or `AKIA…` in documentation is still a live provider
# credential and stays exactly where it was.
_DOC_FILE_RE = re.compile(
    r"(?i)(^|/)(docs?|documentation|examples?|samples?)/|\.(md|rst|adoc|txt)$"
)

_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}


def _is_placeholder(secret: str, line: str) -> bool:
    low = secret.lower()
    if any(tok in low for tok in _PLACEHOLDER_TOKENS):
        return True
    if _PLACEHOLDER_SHAPE_RE.search(secret) or _PLACEHOLDER_SHAPE_RE.search(line):
        return True
    if _ANNOTATION_RE.search(line):
        return True
    # A single repeated character ("AAAAAAAA...", "xxxxxxxx") is never a secret.
    stripped = re.sub(r"[^A-Za-z0-9]", "", secret)
    return len(set(stripped)) <= 2 and len(stripped) >= 6


def _match_secret(rule: SecretRule, match: re.Match[str]) -> str:
    """The captured secret, or the whole match for rules with no group."""
    if match.re.groups:
        return match.group(1)
    return match.group(0)


def scan_file(path: str, content: str) -> list[SecurityFinding]:
    """Run every secret rule over one file."""
    if not is_scannable(path) or looks_binary(content) or not content.strip():
        return []

    normalised = path.replace("\\", "/")
    is_example = bool(_EXAMPLE_FILE_RE.search(normalised))
    is_docs = bool(_DOC_FILE_RE.search(normalised))
    lines = content.splitlines()
    findings: list[SecurityFinding] = []
    # One finding per (rule, line): a rule matching twice on one line is one
    # problem, not two.
    seen: set[tuple[str, int]] = set()

    for rule in ALL_RULES:
        for match in rule.pattern.finditer(content):
            line_no = content.count("\n", 0, match.start()) + 1
            if (rule.id, line_no) in seen:
                continue
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            secret = _match_secret(rule, match)

            if is_example or _is_placeholder(secret, line):
                continue
            if rule.min_entropy and shannon_entropy(secret) < rule.min_entropy:
                continue

            seen.add((rule.id, line_no))

            severity = rule.severity
            explanation = rule.explanation
            # Only the entropy-gated rules are downgraded in documentation. A
            # provider-fingerprinted token is a live credential wherever it sits.
            if is_docs and rule.min_entropy:
                severity = _DOWNGRADE[severity]
                explanation = (
                    explanation
                    + "\n\nRanked lower because this is a documentation file, "
                    "where a high-entropy value next to a secret-looking name "
                    "is usually an illustration. Confirm it is not a real "
                    "credential before dismissing it."
                )

            findings.append(
                SecurityFinding(
                    id=finding_id("secret", rule.id, path, line_no),
                    category="secret",
                    detector=(
                        "regex+entropy" if rule.min_entropy else "gitleaks-regex"
                    ),
                    rule_id=rule.id,
                    title=rule.title,
                    file=path,
                    line_start=line_no,
                    line_end=line_no,
                    detector_severity=rule.severity,  # type: ignore[arg-type]
                    severity=severity,  # type: ignore[arg-type]
                    evidence=redact(secret),
                    references=list(rule.references),
                    explanation=explanation,
                    suggested_fix=rule.remediation,
                )
            )
    return findings


def scan_files(files: list[tuple[str, str]]) -> list[SecurityFinding]:
    """Run the secret detector over (path, content) pairs."""
    out: list[SecurityFinding] = []
    for path, content in files:
        out.extend(scan_file(path, content))
    return out


def scrub(text: str) -> str:
    """Mask anything that looks like a credential anywhere in `text`.

    The secret detector redacts its own evidence, but the other detectors quote
    raw source: bandit's B105 finding for a hardcoded token includes the token,
    and a code snippet handed to the model includes whatever line it came from.
    Every path out of the scanner — the stored report, the browser extension,
    and the triage prompt — runs through here, so a credential is redacted no
    matter which detector surfaced the line it sits on.
    """
    if not text:
        return text
    for rule in ALL_RULES:
        def replace(match: re.Match[str], rule: SecretRule = rule) -> str:
            secret = _match_secret(rule, match)
            if rule.min_entropy and shannon_entropy(secret) < rule.min_entropy:
                return match.group(0)
            return match.group(0).replace(secret, redact(secret))

        text = rule.pattern.sub(replace, text)
    return text
