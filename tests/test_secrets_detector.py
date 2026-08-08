"""Secret detector: it must fire on real credentials and stay quiet otherwise.

Precision is the whole game here. A secret scanner that flags every `.env.example`
and every base64 constant gets muted within a day, so the suppression cases below
matter at least as much as the detection ones.
"""
from __future__ import annotations

import pytest
from synthetic import (
    ANTHROPIC_KEY,
    AWS_DOC_SAMPLE,
    AWS_KEY_ID,
    AWS_SECRET,
    GITHUB_PAT,
    HIGH_ENTROPY,
    POSTGRES_URL,
    PRIVATE_KEY,
    SLACK_TOKEN,
    STRIPE_KEY,
)

from reposec.detectors.common import redact, shannon_entropy
from reposec.detectors.secrets import scan_file, scrub


@pytest.mark.parametrize(
    ("content", "rule_id"),
    [
        (f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"', "aws-access-key-id"),
        (f'aws_secret_access_key = "{AWS_SECRET}"', "aws-secret-access-key"),
        (f'token = "{GITHUB_PAT}"', "github-pat"),
        (f'key = "{ANTHROPIC_KEY}"', "anthropic-api-key"),
        (f't = "{SLACK_TOKEN}"', "slack-token"),
        (f'k = "{STRIPE_KEY}"', "stripe-secret-key"),
        (PRIVATE_KEY, "private-key"),
        (f'DB = "{POSTGRES_URL}"', "database-connection-string"),
    ],
)
def test_detects_known_credential_shapes(content, rule_id):
    findings = scan_file("app/settings.py", content)
    assert rule_id in {f.rule_id for f in findings}


def test_high_entropy_generic_key_is_flagged():
    content = f'CLIENT_SECRET = "{HIGH_ENTROPY}"'
    findings = scan_file("app/config.py", content)
    assert {f.rule_id for f in findings} == {"generic-api-key"}


def test_low_entropy_assignment_is_not_a_secret():
    # A real string constant assigned to a secret-ish name. Entropy is what
    # separates this from a credential; without the gate this is the single
    # biggest source of false positives.
    content = 'api_key_header_name = "x-application-api-key-header"'
    assert scan_file("app/config.py", content) == []


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        ".env.sample",
        "config/settings.example.py",
        "docs/app.template.yml",
    ],
)
def test_example_files_are_skipped(path):
    assert scan_file(path, f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"') == []


@pytest.mark.parametrize(
    "content",
    [
        f'AWS_ACCESS_KEY_ID = "{AWS_DOC_SAMPLE}"',  # AWS's documented sample
        'token = "ghp_" + "your-token-here-replace-with-real-value"',
        'secret = "${VAULT_CLIENT_SECRET}"',
        'secret = "<your-client-secret>"',
        'key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
        'client_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
    ],
)
def test_placeholders_are_suppressed(content):
    assert scan_file("app/config.py", content) == []


def test_vendored_and_binary_content_is_skipped():
    real = f'key = "{AWS_KEY_ID}"'
    assert scan_file("node_modules/pkg/index.js", real) == []
    assert scan_file("app/blob.py", "\x00\x00" + real) == []


def test_evidence_is_redacted_and_never_contains_the_secret():
    findings = scan_file("app/settings.py", f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"')
    assert findings
    for f in findings:
        assert AWS_KEY_ID not in f.evidence
        assert f.evidence.startswith(AWS_KEY_ID[:3])
        assert "*" in f.evidence


def test_finding_ids_are_stable_across_runs():
    content = f'token = "{GITHUB_PAT}"'
    first = scan_file("a.py", content)
    second = scan_file("a.py", content)
    assert [f.id for f in first] == [f.id for f in second]


def test_one_finding_per_rule_per_line():
    content = f'a = "{GITHUB_PAT}"; b = "{GITHUB_PAT}"'
    findings = [f for f in scan_file("a.py", content) if f.rule_id == "github-pat"]
    assert len(findings) == 1


def test_line_numbers_point_at_the_secret():
    content = "\n".join(["import os", "", f'KEY = "{AWS_KEY_ID}"', "x = 1"])
    findings = scan_file("a.py", content)
    assert [f.line_start for f in findings] == [3]


def test_entropy_separates_random_from_prose():
    assert shannon_entropy(HIGH_ENTROPY) > 4.0
    assert shannon_entropy("the quick brown fox") < 4.0
    assert shannon_entropy("") == 0.0


def test_redact_keeps_short_values_fully_hidden():
    assert set(redact("short")) == {"*"}


def test_scrub_masks_credentials_in_text_from_other_detectors():
    # bandit quotes the offending source line verbatim, so its evidence and its
    # message both carry the secret unless this runs.
    text = f"Possible hardcoded password: '{GITHUB_PAT}' at TOKEN = \"{GITHUB_PAT}\""
    cleaned = scrub(text)
    assert GITHUB_PAT not in cleaned
    assert "ghp" in cleaned and "*" in cleaned


def test_scrub_leaves_ordinary_code_alone():
    code = 'def add(a, b):\n    return a + b  # api_key_header = "x-api-key"\n'
    assert scrub(code) == code


# --------------------------------------------------------------------------- #
# Documentation: downgraded, never silenced
#
# Found by scanning Flask, whose docs repeat the same 64-character SECRET_KEY
# example three times. Reporting those as a leak is how a scanner teaches its
# users to ignore secret findings.
# --------------------------------------------------------------------------- #
def test_entropy_findings_in_docs_are_downgraded_not_dropped():
    content = f'SECRET_KEY = "{HIGH_ENTROPY}"'
    findings = scan_file("docs/config.rst", content)
    assert findings, "a docs finding must still be reported"
    assert findings[0].severity == "low"
    # The detector's own opinion is preserved for audit.
    assert findings[0].detector_severity == "medium"
    assert "documentation file" in findings[0].explanation


def test_a_provider_token_in_docs_keeps_its_severity():
    # A real GitHub PAT is a live credential wherever it sits. Only the
    # entropy-gated rules get the documentation discount.
    findings = scan_file("docs/guide.md", f'token = "{GITHUB_PAT}"')
    assert [f.severity for f in findings] == ["high"]
    assert "documentation file" not in findings[0].explanation


@pytest.mark.parametrize(
    "path",
    ["docs/a.rst", "doc/a.md", "documentation/a.txt", "examples/x.md", "README.md"],
)
def test_documentation_paths_are_recognised(path):
    findings = scan_file(path, f'API_KEY = "{HIGH_ENTROPY}"')
    assert findings and findings[0].severity == "low"


def test_ordinary_source_is_not_downgraded():
    findings = scan_file("app/config.py", f'API_KEY = "{HIGH_ENTROPY}"')
    assert findings and findings[0].severity == "medium"
