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


# --------------------------------------------------------------------------- #
# Test trees
#
# Measured on real repositories with `run_live_eval.py`: after documentation,
# test fixtures are where credential-shaped strings legitimately live. The five
# `high` private-key findings this produced on psf/requests and axios — every
# one a self-signed fixture cert — would fail `--fail-on high` on two of the
# most audited repositories in open source.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path",
    [
        "tests/certs/valid/server/server.key",
        "test/fixtures/client.pem",
        "spec/support/ca.crt",
        "__tests__/keys/id_rsa.pem",
    ],
)
def test_fixture_key_files_in_test_trees_are_not_reported(path):
    assert scan_file(path, PRIVATE_KEY) == []


@pytest.mark.parametrize(
    "path",
    [
        "app/keys/production.pem",  # a key file, but not under a test tree
        "tests/test_auth.py",  # a test tree, but not a key file
    ],
)
def test_a_private_key_anywhere_else_is_still_high(path):
    findings = scan_file(path, PRIVATE_KEY)
    assert [f.severity for f in findings] == ["high"]


def test_entropy_findings_in_tests_are_downgraded_not_dropped():
    findings = scan_file("tests/test_client.py", f'API_KEY = "{HIGH_ENTROPY}"')
    assert [f.severity for f in findings] == ["low"]
    assert "test file" in findings[0].explanation


def test_a_provider_token_in_a_test_keeps_its_severity():
    # The same asymmetry as documentation: an `AKIA…` committed to a test file
    # is a live AWS key that someone will find.
    findings = scan_file("tests/test_aws.py", f'key = "{GITHUB_PAT}"')
    assert [f.severity for f in findings] == ["high"]


# --------------------------------------------------------------------------- #
# Generic name coverage
#
# The enumerated name list caught `SECRET_KEY` and `ACCESS_TOKEN` but missed
# names formed from what the secret protects rather than from a vendor. Found by
# planting a 48-character random value in real code: it went unreported at
# entropy 5.33.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name",
    [
        "JWT_SIGNING_SECRET", "WEBHOOK_SECRET", "SESSION_TOKEN",
        "ENCRYPTION_KEY", "MASTER_KEY", "refresh_token", "stripe_api_key",
    ],
)
def test_qualified_secret_names_are_covered(name):
    findings = scan_file("app/config.py", f'{name} = "{HIGH_ENTROPY}"')
    assert findings, f"{name} assigned a high-entropy value went unreported"


@pytest.mark.parametrize(
    "line",
    [
        'token = "IDENTIFIER_NAME"',                    # a lexer token, low entropy
        'token = "application/json;charset=utf-8"',     # a header value
        'SECRET = "${DJANGO_SECRET}"',                  # a template
        'api_key = "<your-api-key-here>"',              # a placeholder
        'SIGNING_KEY = "changeme-please-changeme"',     # a documented fake
    ],
)
def test_widening_the_name_list_did_not_widen_the_noise(line):
    assert scan_file("app/config.py", line) == []


# --------------------------------------------------------------------------- #
# Segment entropy must not silence real credentials
#
# `/` and `+` are in the base64 alphabet, so a real AWS secret key contains a
# slash about 40% of the time. Scoring segments unconditionally left those
# segments too short to clear the gate — and because `scrub()` shares the same
# measure, the key stopped being *redacted* too, which put it in the report,
# the terminal and the model prompt.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("line", "value"),
    [
        # base64 with slashes — the AWS-key shape
        ('SECRET_KEY = "{}"', "2O76UMFxFkM/R5Kjp1vRt+1fjORS/6ilI8ihN5KX"),
        ('SECRET_KEY = "{}"', "a3f9c2/8b1d7e4/06fa2c9/3d5e8b1"),
        # every segment too short for its entropy to mean anything. Named
        # `password` because at 15 characters it is under the generic rule's
        # 16-character floor, which is a length decision, not an entropy one.
        ('password = "{}"', "Kj8.mQ2.pL9.xR4"),
    ],
)
def test_a_separator_inside_random_material_does_not_hide_it(line, value):
    assert scan_file("app/config.py", line.format(value)), (
        f"{value!r} was silenced by segment-wise entropy"
    )


@pytest.mark.parametrize(
    "name", ["DB_PASSWORD", "ADMIN_PASSWORD", "smtp_password", "password"]
)
def test_qualified_password_names_are_covered(name):
    assert scan_file("app/config.py", f'{name} = "{HIGH_ENTROPY}"')


def test_scrub_masks_a_credential_containing_separators():
    # The security-critical half: scrub decides what reaches the model prompt.
    masked = scrub('SECRET_KEY = "a3f9c2/8b1d7e4/06fa2c9/3d5e8b1"')
    assert "a3f9c2/8b1d7e4/06fa2c9/3d5e8b1" not in masked
    assert "***" in masked


def test_a_fingerprinted_token_is_reported_once_not_twice():
    # The generic rule's name list includes `token`, and a real PAT clears the
    # entropy floor — so without the fingerprint taking precedence, one leaked
    # credential is reported as two problems at two severities with two
    # different remediations.
    findings = scan_file("app/gh.py", f'token = "{GITHUB_PAT}"')
    assert [f.rule_id for f in findings] == ["github-pat"]


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


# --------------------------------------------------------------------------- #
# Connection strings
#
# Found by scanning 420 kLOC of installed packages: every one of the 15 secret
# findings was a driver docstring showing the URL format. The password and the
# host carry the signal, not the URL as a whole.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    [
        "postgres://app:password@db.example.com:5432/appdb",
        "mysql://scott:tiger@localhost/test",
        "mysql+pymysql://user:pass@hostname/dbname?charset=utf8mb4",
        "redis://admin:admin@127.0.0.1:6379/0",
        "mongodb://svc:${MONGO_PASSWORD}@warehouse/events",
        "postgres://deploy:deploy@db.internal/orders",
    ],
)
def test_illustrative_connection_strings_are_not_reported(url):
    assert scan_file("app/db.py", f'DSN = "{url}"') == []


@pytest.mark.parametrize(
    "url",
    [
        # libpq's own documented form: the host moves into a query parameter,
        # so the authority's host component is empty. Taken verbatim from
        # psycopg2's and asyncpg's docstrings, which this rule reported as six
        # leaked credentials until the host was allowed to be empty.
        "postgresql+psycopg2://user:password@/dbname?host=HostA",
        "postgresql+asyncpg://user:password@/dbname?host=/var/run/postgresql",
        "postgresql://user:password@/dbname?host=/tmp&port=5433",
    ],
)
def test_a_hostless_connection_string_is_judged_on_its_password(url):
    assert scan_file("app/db.py", f'DSN = "{url}"') == []


def test_a_hostless_connection_string_with_a_real_password_still_fires():
    # The other half: widening the host must not have widened the *drop*. Only
    # the illustrative password made those docstrings quiet.
    findings = scan_file(
        "app/db.py", 'DSN = "postgresql://svc:Hn4pV2xQmL8w@/orders?host=/tmp"'
    )
    assert [f.rule_id for f in findings] == ["database-connection-string"]
    assert findings[0].severity == "high"


def test_a_real_connection_string_is_still_reported():
    findings = scan_file("app/db.py", f'DSN = "{POSTGRES_URL}"')
    assert [f.rule_id for f in findings] == ["database-connection-string"]
    assert findings[0].severity == "high"


def test_a_private_network_connection_string_is_ranked_lower():
    # Still worth reporting — the password may be reused — but it is not the
    # internet-reachable data access the rule's high severity describes.
    findings = scan_file("app/db.py", 'DSN = "postgres://svc:Hn4pV2xQmL8w@10.4.1.9/o"')
    assert [f.severity for f in findings] == ["medium"]
    assert "private network" in findings[0].explanation


# --------------------------------------------------------------------------- #
# Structured names vs. random material
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value",
    [
        "AES/CBC/PKCS5Padding",
        "django.core.signing.TimestampSigner",
        "connect.sid.signed.v2.rolling",
        "com.example.service.AuthTokenProvider",
    ],
)
def test_dotted_and_slashed_names_are_not_secrets(value):
    # Joining ordinary words with separators clears any whole-string entropy
    # floor. Each segment on its own is a word, which is the actual question.
    assert scan_file("app/config.py", f'SECRET_KEY = "{value}"') == []


def test_a_separator_does_not_hide_a_real_secret():
    # The guard scores the most random-looking segment, so padding a credential
    # with dots does not get it past the entropy gate.
    findings = scan_file("app/config.py", f'API_KEY = "{HIGH_ENTROPY}.v2"')
    assert [f.rule_id for f in findings] == ["generic-api-key"]
