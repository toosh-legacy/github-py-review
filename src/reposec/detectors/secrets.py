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

# Test trees. Measured on real repositories, this is where credential-shaped
# strings legitimately live, second only to documentation: `password:
# "concurrent-pass"` in an auth test is a fixture, not a leak.
#
# Like the documentation rule, this *downgrades* the entropy-gated rules and
# leaves provider fingerprints alone — an `AKIA…` committed to a test file is a
# live AWS key that someone will find.
_TEST_PATH_RE = re.compile(
    r"(?i)(^|/)(tests?|testing|spec|specs|__tests__|fixtures?|testdata)/"
)

# The one exception to "downgrade, never drop" for test paths: cryptographic key
# *files*. A `.key`/`.pem` under a test tree is a self-signed fixture generated
# for the suite — `psf/requests` ships four and `axios` one, and every one of
# them is reported `high` by the private-key fingerprint, which has no entropy
# gate to catch it. That is five findings that fail `--fail-on high` on two of
# the most-audited repositories in open source, which is how a scanner teaches
# its users to stop reading its output.
#
# Deliberately narrow: it is the conjunction that makes this safe. A production
# key does not live at `tests/certs/server.key`, and a real credential in a test
# file with any other extension is still reported.
_TEST_KEY_FILE_RE = re.compile(
    r"(?i)\.(key|pem|crt|cer|der|p12|pfx|jks|keystore)$"
)

_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}

# --------------------------------------------------------------------------- #
# Connection strings.
#
# `postgres://user:pass@host/db` is the single most-documented URL shape there
# is: every database driver's docstring contains one, and none of them contain
# a credential. Measured on 420 kLOC of installed packages, this rule produced
# 15 findings and all 15 were SQLAlchemy docstrings — `scott:tiger@localhost`,
# `user:password@host`. That is not a tunable threshold, it is a category
# error, so the password and the host are judged separately from the URL.
# --------------------------------------------------------------------------- #
# The host is `*`, not `+`, on purpose. `postgresql+psycopg2://user:password@/db
# ?host=HostA` is a documented libpq form — the host moves into a query
# parameter and the authority's host component is empty. With `+` the pattern
# did not match at all, so the verdict was `keep` and the password was never
# examined: six of psycopg2's and asyncpg's own docstrings were reported as
# leaked credentials. An empty host is not itself a reason to drop, so it just
# falls through to the password check, which is what catches these.
_DB_URL_RE = re.compile(
    r"://(?P<user>[^\s:@/\"']+):(?P<password>[^\s:@/\"']+)@(?P<host>[^\s/:\"'<>]*)"
)

# Passwords that exist to occupy the password slot in an example. `scott/tiger`
# is Oracle's demo account and is repeated verbatim across database docs.
_ILLUSTRATIVE_PASSWORDS = frozenset(
    {
        "password", "passwd", "pass", "pwd", "mypassword", "my_password",
        "secret", "mysecret", "changeme", "change_me", "tiger", "hunter2",
        "root", "admin", "guest", "user", "username", "test", "testing",
        "dbpass", "dbpassword", "db_password", "letmein", "abc123", "qwerty",
        "postgres", "mysql", "redis", "mongo", "example", "sample", "foobar",
    }
)

# Hosts that cannot be a production database: loopback, the reserved example
# domains (RFC 2606), and the generic words drivers use in their docs.
_ILLUSTRATIVE_HOSTS = frozenset(
    {
        "localhost", "127.0.0.1", "0.0.0.0", "::1", "host", "hostname",
        "your-host", "your_host", "yourhost", "dbhost", "db_host", "db",
        "database", "server", "myhost", "somehost", "example.com",
        "example.org", "example.net",
    }
)

# RFC 1918 and link-local. A URL pointing into a private range is a developer's
# own network; it is still worth reporting, but it is not the internet-reachable
# data access the rule's high severity is describing.
_PRIVATE_HOST_RE = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)"
)


def _connection_string_verdict(secret: str) -> str:
    """`drop`, `downgrade`, or `keep` for one database URL.

    Split out from `_is_placeholder` because the whole-string placeholder check
    cannot work here: the URL contains a hostname, a database name and query
    parameters, so the interesting substring is diluted by everything around it.
    """
    match = _DB_URL_RE.search(secret)
    if match is None:
        return "keep"

    password = match.group("password").lower()
    host = match.group("host").lower().split(":")[0]

    if password in _ILLUSTRATIVE_PASSWORDS or password == match.group("user").lower():
        return "drop"
    # `<pw>`, `${DB_PASS}`, `%(password)s` — a template, not a value.
    if _PLACEHOLDER_SHAPE_RE.search(match.group("password")):
        return "drop"
    if host in _ILLUSTRATIVE_HOSTS or host.endswith((".example", ".invalid", ".local")):
        return "drop"
    if _PRIVATE_HOST_RE.match(host):
        return "downgrade"
    return "keep"


# Values built from `.`- or `/`-separated words: `AES/CBC/PKCS5Padding`,
# `django.core.signing.TimestampSigner`, `connect.sid.signed.v2`. Measured over
# the whole string these clear any entropy floor, because the separators and the
# case changes supply the variety — but each segment on its own is a word.
_SEGMENT_RE = re.compile(r"[./]")


# A segment is "wordlike" when it is essentially letters. `PKCS5Padding` is;
# `2O76UMFxFkM` is not. Segments under four characters are exempt because their
# entropy is bounded by their length and says nothing either way — `v2` in
# `connect.sid.signed.v2` cannot be judged, so it is not held against the rest.
_WORDLIKE_MIN_LEN = 4
_WORDLIKE_ALPHA_RATIO = 0.85


def _is_wordlike(segment: str) -> bool:
    if len(segment) < _WORDLIKE_MIN_LEN:
        return True
    alpha = sum(c.isalpha() for c in segment)
    return alpha / len(segment) >= _WORDLIKE_ALPHA_RATIO


def _secret_entropy(secret: str) -> float:
    """Entropy of `secret`, discounting structure that only looks random.

    Whole-string entropy is the wrong measure for a structured name: joining
    ordinary words with dots or slashes produces a number indistinguishable from
    base64, which is how `AES/CBC/PKCS5Padding` and
    `django.core.signing.TimestampSigner` used to be reported as credentials.

    But scoring segments unconditionally is worse, and in the dangerous
    direction. `/` and `+` are in the base64 alphabet, so a real AWS secret key
    contains a slash about 40% of the time — splitting on it leaves segments too
    short for their entropy to clear the gate, and the key stops being reported.
    Measured over 20,000 generated keys, 0.2% were silenced this way.

    So the segment measure is applied only when every segment is *wordlike*:
    essentially letters, which is what distinguishes a dotted identifier from
    random material that happens to contain a separator.
    """
    segments = [s for s in _SEGMENT_RE.split(secret) if s]
    structured = (
        len(segments) >= 2
        # At least one segment long enough for its entropy to mean something.
        # `Kj8.mQ2.pL9.xR4` is all three-character pieces: every one of them
        # scores near zero for being short, not for being a word, so segmenting
        # it would report 1.59 for a string whose real entropy is 3.59.
        and any(len(s) >= _WORDLIKE_MIN_LEN for s in segments)
        and all(_is_wordlike(s) for s in segments)
    )
    if not structured:
        return shannon_entropy(secret)
    return max(shannon_entropy(s) for s in segments)


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
    is_test = bool(_TEST_PATH_RE.search(normalised))
    is_example = bool(_EXAMPLE_FILE_RE.search(normalised)) or (
        is_test and bool(_TEST_KEY_FILE_RE.search(normalised))
    )
    is_docs = bool(_DOC_FILE_RE.search(normalised))
    lines = content.splitlines()
    findings: list[SecurityFinding] = []
    # One finding per (rule, line): a rule matching twice on one line is one
    # problem, not two.
    seen: set[tuple[str, int]] = set()
    # The raw secret behind each finding, so identical values matched by more
    # than one rule can be collapsed below. Kept alongside rather than derived
    # from `evidence`, which is redacted and not injective for short values.
    raw: list[str] = []

    for rule in ALL_RULES:
        for match in rule.pattern.finditer(content):
            line_no = content.count("\n", 0, match.start()) + 1
            if (rule.id, line_no) in seen:
                continue
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            secret = _match_secret(rule, match)

            if is_example or _is_placeholder(secret, line):
                continue
            if rule.min_entropy and _secret_entropy(secret) < rule.min_entropy:
                continue

            verdict = (
                _connection_string_verdict(secret)
                if rule.id == "database-connection-string"
                else "keep"
            )
            if verdict == "drop":
                continue

            seen.add((rule.id, line_no))
            raw.append(secret)

            severity = rule.severity
            explanation = rule.explanation
            if verdict == "downgrade":
                severity = _DOWNGRADE[severity]
                explanation = (
                    explanation
                    + "\n\nRanked lower because the host is on a private "
                    "network, so this is most likely a development database "
                    "rather than internet-reachable data. Rotate it anyway if "
                    "the password is reused."
                )
            # Only the entropy-gated rules are downgraded in documentation and
            # test trees. A provider-fingerprinted token is a live credential
            # wherever it sits.
            if is_test and rule.min_entropy:
                severity = _DOWNGRADE[severity]
                explanation = (
                    explanation
                    + "\n\nRanked lower because this is a test file, where a "
                    "credential-shaped string is usually a fixture. Confirm it "
                    "is not a real credential before dismissing it."
                )
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
    return _one_finding_per_credential(findings, raw)


_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_RULE_ORDER = {rule.id: i for i, rule in enumerate(ALL_RULES)}


def _one_finding_per_credential(
    findings: list[SecurityFinding], raw: list[str]
) -> list[SecurityFinding]:
    """Collapse rules that all matched the same value on the same line.

    One leaked credential is one problem. Several rules legitimately describe
    the same string — `JWT_SECRET = "…"` matches both `hardcoded-crypto-key`
    and `generic-api-key`, and `token = "ghp_…"` matches both `github-pat` and
    the generic rule — and reporting each of them turns one rotation into a
    list of three, at three severities, with three different remediations. It
    also silently inflates every count the tool prints.

    The survivor is the highest-severity match, and among equals the earliest
    rule in `ALL_RULES` — which puts the provider fingerprints first, because a
    rule that knows *which* provider to rotate at is more useful than one that
    only knows the value looked random.
    """
    best: dict[tuple[int, str], int] = {}
    for i, (finding, secret) in enumerate(zip(findings, raw, strict=True)):
        slot = (finding.line_start, secret)
        incumbent = best.get(slot)
        if incumbent is None or _rank(findings[i]) < _rank(findings[incumbent]):
            best[slot] = i
    keep = set(best.values())
    return [f for i, f in enumerate(findings) if i in keep]


def _rank(finding: SecurityFinding) -> tuple[int, int]:
    return (
        _SEVERITY_RANK[finding.severity],
        _RULE_ORDER.get(finding.rule_id, len(_RULE_ORDER)),
    )


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

    **The entropy gate here is `shannon_entropy`, not `_secret_entropy`, and
    that difference is deliberate.** The two functions answer different
    questions. Detection asks "is this worth reporting", where over-reporting
    costs the user's attention. Redaction asks "could this be a credential",
    where under-masking costs the credential — it goes into the report, the
    terminal, and the model prompt. Anything that plausibly looks random gets
    masked, and the segment discount that makes detection quieter has no place
    in that decision.
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
