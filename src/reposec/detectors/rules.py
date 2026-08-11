"""Secret-detection rules, derived from the gitleaks rule set.

Each rule is a regex with one capture group holding the secret itself, so the
scanner can redact precisely and measure entropy on the secret rather than on
the whole line.

Two kinds of rule live here:

  *fingerprint* rules  — the token has a distinctive prefix and shape
                         (`AKIA...`, `ghp_...`, `sk-ant-...`). These are
                         near-zero-false-positive and need no entropy check.
  *contextual* rules   — the token is generic, so the rule matches an
                         assignment to a suspicious name and then demands high
                         Shannon entropy before it fires. Without the entropy
                         gate these produce the flood of false positives that
                         makes secret scanning useless.

`min_entropy` of 0.0 means "fingerprint rule, no entropy gate".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: str = "high"
    # Entropy floor on the captured secret, in bits/char (max 6 for base64).
    min_entropy: float = 0.0
    # Plain-language risk, used verbatim when no LLM is available to triage.
    explanation: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


_ROTATE = (
    "Revoke this credential at the provider now — assume it is compromised the "
    "moment it lands in git history. Then reissue it and load it from an "
    "environment variable or a secrets manager, and purge it from history "
    "(git filter-repo / BFG); deleting the line in a new commit is not enough."
)

# --------------------------------------------------------------------------- #
# Fingerprint rules: distinctive shapes, no entropy gate needed.
# --------------------------------------------------------------------------- #
FINGERPRINT_RULES: list[SecretRule] = [
    SecretRule(
        "aws-access-key-id",
        "AWS access key ID",
        _r(r"\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b"),
        explanation=(
            "An AWS access key ID identifies a real IAM principal. Paired with "
            "its secret it grants whatever that principal can do — often far "
            "more than intended. Bots scrape public repos for this exact "
            "prefix within minutes of a push."
        ),
        remediation=_ROTATE,
        references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
    ),
    SecretRule(
        "aws-secret-access-key",
        "AWS secret access key",
        _r(
            r"(?i)aws[_.-]?(?:secret[_.-]?)?access[_.-]?key"
            r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"
        ),
        min_entropy=3.5,
        explanation=(
            "This is the half of an AWS credential pair that actually signs "
            "requests. With the matching key ID it is full programmatic access "
            "to the account."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "private-key",
        "Private key material",
        _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        explanation=(
            "A private key in the repository lets anyone who clones it "
            "impersonate the server, user, or signing identity it belongs to. "
            "TLS keys allow traffic decryption; SSH keys allow host access; "
            "signing keys allow forged releases."
        ),
        remediation=(
            "Treat the key as burned: generate a new keypair, redeploy it, and "
            "revoke the old one (remove from authorized_keys, reissue the "
            "certificate, revoke the signing key). Then purge it from git "
            "history."
        ),
    ),
    SecretRule(
        "github-pat",
        "GitHub personal access token",
        _r(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
        explanation=(
            "A GitHub token acts as the account that issued it. Depending on "
            "scopes it can read private repositories, push code, or alter CI "
            "— which turns one leaked token into a supply-chain problem."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "github-fine-grained-pat",
        "GitHub fine-grained personal access token",
        _r(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"),
        explanation=(
            "A fine-grained GitHub token scoped to specific repositories. "
            "Still a live credential for whatever it was granted."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "gitlab-pat",
        "GitLab personal access token",
        _r(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
        explanation="A GitLab token with the issuing user's repository access.",
        remediation=_ROTATE,
    ),
    SecretRule(
        "openai-api-key",
        "OpenAI API key",
        _r(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b"),
        explanation=(
            "An OpenAI key is billed to the owning account. Leaked keys are "
            "drained by scrapers, and the charges land on you."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "anthropic-api-key",
        "Anthropic API key",
        _r(r"\b(sk-ant-[A-Za-z0-9_\-]{24,})\b"),
        explanation=(
            "An Anthropic API key is billed to the owning account and grants "
            "full API access under that organization."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "slack-token",
        "Slack token",
        _r(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"),
        explanation=(
            "A Slack token can read and post messages in whatever workspace "
            "and channels it was installed for — an internal-data exposure and "
            "a convincing phishing vector."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "slack-webhook",
        "Slack incoming webhook URL",
        _r(r"(https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/]{40,})"),
        severity="medium",
        explanation=(
            "Anyone holding this URL can post messages into the channel as "
            "your integration. Useful for phishing employees."
        ),
        remediation=(
            "Delete the webhook in Slack and create a new one; keep the URL in "
            "a secrets store, not in the repository."
        ),
    ),
    SecretRule(
        "stripe-secret-key",
        "Stripe secret key",
        _r(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b"),
        explanation=(
            "A Stripe secret key can move money, read customer records, and "
            "issue refunds. A `live` key is an immediate financial exposure."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "google-api-key",
        "Google API key",
        _r(r"\b(AIza[A-Za-z0-9_\-]{35})\b"),
        severity="medium",
        explanation=(
            "A Google API key is billed to your project. Unless it is "
            "restricted by referrer/IP/API, anyone can spend your quota."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "gcp-service-account",
        "GCP service-account private key",
        _r(r'"type"\s*:\s*"(service_account)"'),
        explanation=(
            "A service-account JSON key authenticates as that service account "
            "non-interactively, with whatever IAM roles it holds."
        ),
        remediation=(
            "Delete the key in IAM, issue a replacement (or move to workload "
            "identity federation, which needs no key file), and purge history."
        ),
    ),
    SecretRule(
        "npm-token",
        "npm access token",
        _r(r"\b(npm_[A-Za-z0-9]{36})\b"),
        explanation=(
            "An npm token can publish packages under your account — a direct "
            "supply-chain compromise route for every downstream consumer."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "pypi-token",
        "PyPI upload token",
        _r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"),
        explanation=(
            "A PyPI token can publish releases of your package, letting an "
            "attacker ship code to everyone who installs it."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "sendgrid-api-key",
        "SendGrid API key",
        _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        severity="medium",
        explanation=(
            "A SendGrid key can send mail as your verified domain — ideal for "
            "phishing that passes SPF/DKIM."
        ),
        remediation=_ROTATE,
    ),
    SecretRule(
        "twilio-api-key",
        "Twilio API key",
        _r(r"\b(SK[0-9a-fA-F]{32})\b"),
        severity="medium",
        explanation="A Twilio key can send SMS and place calls billed to your account.",
        remediation=_ROTATE,
    ),
    SecretRule(
        "mailgun-api-key",
        "Mailgun API key",
        _r(r"\b(key-[0-9a-f]{32})\b"),
        severity="medium",
        explanation="A Mailgun key can send mail as your domain.",
        remediation=_ROTATE,
    ),
    SecretRule(
        "discord-bot-token",
        "Discord bot token",
        _r(r"\b([MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,39})\b"),
        severity="medium",
        explanation="A Discord bot token grants full control of the bot account.",
        remediation=_ROTATE,
    ),
    SecretRule(
        "telegram-bot-token",
        "Telegram bot token",
        _r(r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{32,34})\b"),
        severity="medium",
        explanation="A Telegram bot token grants full control of the bot.",
        remediation=_ROTATE,
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
        severity="medium",
        min_entropy=3.5,
        explanation=(
            "A signed JWT is a bearer credential: whoever holds it is the user "
            "it was issued for, until it expires. Committed tokens are often "
            "long-lived service tokens."
        ),
        remediation=(
            "Revoke the session/token if the issuer supports it, rotate the "
            "signing key if the token was signed by your own service, and stop "
            "committing tokens used for local testing."
        ),
    ),
    SecretRule(
        "database-connection-string",
        "Database URL with embedded password",
        _r(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
            r"(?:\+\w+)?://[^\s:@/\"']+:[^\s:@/\"']+@[^\s\"'<>]+)"
        ),
        explanation=(
            "A connection string with an inline password is a working "
            "credential for the database. If the host is reachable from the "
            "internet this is direct data access."
        ),
        remediation=(
            "Rotate the database password, move the URL into an environment "
            "variable, and confirm the database is not publicly reachable."
        ),
    ),
]

# --------------------------------------------------------------------------- #
# Contextual rules: generic-looking secrets, gated on entropy.
# --------------------------------------------------------------------------- #
_ASSIGN = (
    r"(?i)\b(?:{names})\b[\"']?\s*(?:[:=]|=>|:=)\s*[\"']([A-Za-z0-9+/=_\-.]{{{min_len},}})[\"']"
)

CONTEXTUAL_RULES: list[SecretRule] = [
    SecretRule(
        "generic-api-key",
        "Hardcoded API key or token",
        _r(
            _ASSIGN.format(
                names=(
                    # A leading qualifier is optional and unconstrained, which
                    # is what closes the gap this list had: the enumerated forms
                    # below caught `SECRET_KEY` and `ACCESS_TOKEN` but missed
                    # `JWT_SIGNING_SECRET`, `WEBHOOK_SECRET`, `SESSION_TOKEN`
                    # and `ENCRYPTION_KEY` — names at least as common, and named
                    # after the thing they protect rather than after the vendor.
                    # Measured: a 48-character random value assigned to
                    # `JWT_SIGNING_SECRET` went unreported at entropy 5.33.
                    #
                    # The widening is safe because the name is never the whole
                    # test. Every match still has to clear 16 characters, an
                    # entropy floor of 3.6, and the placeholder filter — which is
                    # what stops `token = "identifier"` in a parser from firing.
                    r"(?:[a-z0-9]+[_-]){0,3}"
                    r"(?:api[_-]?keys?|apikey|api[_-]?secret|access[_-]?token|"
                    r"auth[_-]?token|client[_-]?secret|secret[_-]?key|"
                    r"private[_-]?token|session[_-]?secret|app[_-]?secret|"
                    r"secret|token|passphrase|"
                    r"signing[_-]?key|encryption[_-]?key|master[_-]?key)"
                ),
                min_len=16,
            )
        ),
        severity="medium",
        min_entropy=3.6,
        explanation=(
            "A high-entropy string assigned to a secret-looking name is almost "
            "always a live credential. In source control it is readable by "
            "everyone with repo access and by anyone who ever forks or clones."
        ),
        remediation=(
            "Move the value to an environment variable or secrets manager, "
            "rotate it at the provider, and purge it from git history."
        ),
    ),
    SecretRule(
        "hardcoded-password",
        "Hardcoded password",
        _r(
            _ASSIGN.format(
                # Same optional qualifier as the generic rule above, for the
                # same reason: `DB_PASSWORD`, `ADMIN_PASSWORD` and
                # `SMTP_PASSWORD` were missed while a bare `password` was
                # caught. The entropy floor and the 8-character minimum are what
                # keep the widening quiet.
                names=(
                    r"(?:[a-z0-9]+[_-]){0,3}"
                    r"(?:password|passwd|pwd|pass)"
                ),
                min_len=8,
            )
        ),
        severity="medium",
        min_entropy=3.0,
        explanation=(
            "A password embedded in source cannot be rotated without a code "
            "change, is visible to everyone with repository access, and tends "
            "to be reused across environments."
        ),
        remediation=(
            "Read the password from configuration at runtime and rotate the "
            "existing one — assume it is known."
        ),
    ),
    SecretRule(
        "hardcoded-crypto-key",
        "Hardcoded encryption key or IV",
        _r(
            _ASSIGN.format(
                names=(
                    r"encryption[_-]?key|cipher[_-]?key|aes[_-]?key|hmac[_-]?key|"
                    r"signing[_-]?key|jwt[_-]?secret|secret|iv|salt"
                ),
                min_len=16,
            )
        ),
        severity="high",
        min_entropy=3.6,
        explanation=(
            "A cryptographic key committed to source defeats the cryptography "
            "it protects: anyone with the repository can decrypt the data or "
            "forge signatures/tokens the key authenticates. Hardcoding also "
            "makes rotation a code change, so it never happens."
        ),
        remediation=(
            "Generate a fresh key, load it from a secrets manager or KMS at "
            "runtime, and re-encrypt or invalidate anything the old key "
            "protected (existing JWTs and sessions must be treated as forgeable)."
        ),
    ),
]

ALL_RULES: list[SecretRule] = FINGERPRINT_RULES + CONTEXTUAL_RULES
