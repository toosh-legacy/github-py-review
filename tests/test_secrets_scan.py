"""Secret detector: it must fire on real credentials and stay quiet otherwise.

Precision is the whole game here. A secret scanner that flags every `.env.example`
and every base64 constant gets muted within a day, so the suppression cases below
matter at least as much as the detection ones.
"""
from __future__ import annotations

import pytest

from security.common import redact, shannon_entropy
from security.secrets_scan import scan_file, scrub

# Synthetic credentials: correct shape for the rules, not issued by anyone.
AWS_KEY_ID = "AKIA4NHQ7ZP2VXK3MTBW"
AWS_SECRET = "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"
GITHUB_PAT = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.mark.parametrize(
    ("content", "rule_id"),
    [
        (f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"', "aws-access-key-id"),
        (f'aws_secret_access_key = "{AWS_SECRET}"', "aws-secret-access-key"),
        (f'token = "{GITHUB_PAT}"', "github-pat"),
        ('key = "sk-ant-api03-QmFzZTY0RW5jb2RlZFN0cmluZ1hZWjEyMzQ"', "anthropic-api-key"),
        ('t = "xoxb-2847561930-4471829365-Jd83kFmQpZx71LsWnRb2Yh4T"', "slack-token"),
        ('k = "sk_live_51HxQmZ2eZvKYlo2CkL9mNbVc"', "stripe-secret-key"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n", "private-key"),
        (
            'DB = "postgres://admin:Str0ngP4ssw0rd@db.internal:5432/prod"',
            "database-connection-string",
        ),
    ],
)
def test_detects_known_credential_shapes(content, rule_id):
    findings = scan_file("app/settings.py", content)
    assert rule_id in {f.rule_id for f in findings}


def test_high_entropy_generic_key_is_flagged():
    content = 'CLIENT_SECRET = "hQ7zRt3XmW9pLd2VbN6cKfJ8sYaG4uEo"'
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
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',  # AWS's documented sample
        'token = "ghp_your-token-here-replace-with-real-value"',
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
    assert shannon_entropy("hQ7zRt3XmW9pLd2VbN6cKfJ8sYaG4uEo") > 4.0
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
