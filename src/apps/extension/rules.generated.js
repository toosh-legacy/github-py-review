// GENERATED FILE — do not edit.
//
// Source of truth: src/reposec/detectors/rules.py
// Regenerate:      python deploy/generate_js_rules.py
//
// Two copies of a secret rule set will drift, and a drifted scanner
// misses things exactly where nobody is looking. tests/test_js_rules.py
// fails if this file falls out of step with the Python rules.
export const SECRET_RULES = [
  {
    "id": "aws-access-key-id",
    "title": "AWS access key ID",
    "pattern": "\\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "An AWS access key ID identifies a real IAM principal. Paired with its secret it grants whatever that principal can do — often far more than intended. Bots scrape public repos for this exact prefix within minutes of a push.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": [
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    ]
  },
  {
    "id": "aws-secret-access-key",
    "title": "AWS secret access key",
    "pattern": "aws[_.-]?(?:secret[_.-]?)?access[_.-]?key[\\\"']?\\s*[:=]\\s*[\\\"']([A-Za-z0-9/+=]{40})[\\\"']",
    "flags": "gi",
    "severity": "high",
    "minEntropy": 3.5,
    "group": 1,
    "explanation": "This is the half of an AWS credential pair that actually signs requests. With the matching key ID it is full programmatic access to the account.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "private-key",
    "title": "Private key material",
    "pattern": "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 0,
    "explanation": "A private key in the repository lets anyone who clones it impersonate the server, user, or signing identity it belongs to. TLS keys allow traffic decryption; SSH keys allow host access; signing keys allow forged releases.",
    "remediation": "Treat the key as burned: generate a new keypair, redeploy it, and revoke the old one (remove from authorized_keys, reissue the certificate, revoke the signing key). Then purge it from git history.",
    "references": []
  },
  {
    "id": "github-pat",
    "title": "GitHub personal access token",
    "pattern": "\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A GitHub token acts as the account that issued it. Depending on scopes it can read private repositories, push code, or alter CI — which turns one leaked token into a supply-chain problem.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "github-fine-grained-pat",
    "title": "GitHub fine-grained personal access token",
    "pattern": "\\b(github_pat_[A-Za-z0-9_]{60,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A fine-grained GitHub token scoped to specific repositories. Still a live credential for whatever it was granted.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "gitlab-pat",
    "title": "GitLab personal access token",
    "pattern": "\\b(glpat-[A-Za-z0-9_\\-]{20,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A GitLab token with the issuing user's repository access.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "openai-api-key",
    "title": "OpenAI API key",
    "pattern": "\\b(sk-(?:proj-)?[A-Za-z0-9_\\-]{20,}T3BlbkFJ[A-Za-z0-9_\\-]{20,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "An OpenAI key is billed to the owning account. Leaked keys are drained by scrapers, and the charges land on you.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "anthropic-api-key",
    "title": "Anthropic API key",
    "pattern": "\\b(sk-ant-[A-Za-z0-9_\\-]{24,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "An Anthropic API key is billed to the owning account and grants full API access under that organization.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "slack-token",
    "title": "Slack token",
    "pattern": "\\b(xox[baprs]-[A-Za-z0-9\\-]{10,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Slack token can read and post messages in whatever workspace and channels it was installed for — an internal-data exposure and a convincing phishing vector.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "slack-webhook",
    "title": "Slack incoming webhook URL",
    "pattern": "(https://hooks\\.slack\\.com/(?:services|workflows)/[A-Za-z0-9+/]{40,})",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "Anyone holding this URL can post messages into the channel as your integration. Useful for phishing employees.",
    "remediation": "Delete the webhook in Slack and create a new one; keep the URL in a secrets store, not in the repository.",
    "references": []
  },
  {
    "id": "stripe-secret-key",
    "title": "Stripe secret key",
    "pattern": "\\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Stripe secret key can move money, read customer records, and issue refunds. A `live` key is an immediate financial exposure.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "google-api-key",
    "title": "Google API key",
    "pattern": "\\b(AIza[A-Za-z0-9_\\-]{35})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Google API key is billed to your project. Unless it is restricted by referrer/IP/API, anyone can spend your quota.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "gcp-service-account",
    "title": "GCP service-account private key",
    "pattern": "\"type\"\\s*:\\s*\"(service_account)\"",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A service-account JSON key authenticates as that service account non-interactively, with whatever IAM roles it holds.",
    "remediation": "Delete the key in IAM, issue a replacement (or move to workload identity federation, which needs no key file), and purge history.",
    "references": []
  },
  {
    "id": "npm-token",
    "title": "npm access token",
    "pattern": "\\b(npm_[A-Za-z0-9]{36})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "An npm token can publish packages under your account — a direct supply-chain compromise route for every downstream consumer.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "pypi-token",
    "title": "PyPI upload token",
    "pattern": "\\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\\-]{50,})\\b",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A PyPI token can publish releases of your package, letting an attacker ship code to everyone who installs it.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "sendgrid-api-key",
    "title": "SendGrid API key",
    "pattern": "\\b(SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A SendGrid key can send mail as your verified domain — ideal for phishing that passes SPF/DKIM.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "twilio-api-key",
    "title": "Twilio API key",
    "pattern": "\\b(SK[0-9a-fA-F]{32})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Twilio key can send SMS and place calls billed to your account.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "mailgun-api-key",
    "title": "Mailgun API key",
    "pattern": "\\b(key-[0-9a-f]{32})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Mailgun key can send mail as your domain.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "discord-bot-token",
    "title": "Discord bot token",
    "pattern": "\\b([MNO][A-Za-z0-9_\\-]{23,25}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,39})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Discord bot token grants full control of the bot account.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "telegram-bot-token",
    "title": "Telegram bot token",
    "pattern": "\\b([0-9]{8,10}:AA[A-Za-z0-9_\\-]{32,34})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A Telegram bot token grants full control of the bot.",
    "remediation": "Revoke this credential at the provider now — assume it is compromised the moment it lands in git history. Then reissue it and load it from an environment variable or a secrets manager, and purge it from history (git filter-repo / BFG); deleting the line in a new commit is not enough.",
    "references": []
  },
  {
    "id": "jwt",
    "title": "JSON Web Token",
    "pattern": "\\b(eyJ[A-Za-z0-9_\\-]{10,}\\.eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,})\\b",
    "flags": "g",
    "severity": "medium",
    "minEntropy": 3.5,
    "group": 1,
    "explanation": "A signed JWT is a bearer credential: whoever holds it is the user it was issued for, until it expires. Committed tokens are often long-lived service tokens.",
    "remediation": "Revoke the session/token if the issuer supports it, rotate the signing key if the token was signed by your own service, and stop committing tokens used for local testing.",
    "references": []
  },
  {
    "id": "database-connection-string",
    "title": "Database URL with embedded password",
    "pattern": "\\b((?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp)(?:\\+\\w+)?://[^\\s:@/\\\"']+:[^\\s:@/\\\"']+@[^\\s\\\"'<>]+)",
    "flags": "g",
    "severity": "high",
    "minEntropy": 0.0,
    "group": 1,
    "explanation": "A connection string with an inline password is a working credential for the database. If the host is reachable from the internet this is direct data access.",
    "remediation": "Rotate the database password, move the URL into an environment variable, and confirm the database is not publicly reachable.",
    "references": []
  },
  {
    "id": "generic-api-key",
    "title": "Hardcoded API key or token",
    "pattern": "\\b(?:(?:[a-z0-9]+[_-]){0,3}(?:api[_-]?keys?|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?token|session[_-]?secret|app[_-]?secret|secret|token|passphrase|signing[_-]?key|encryption[_-]?key|master[_-]?key))\\b[\\\"']?\\s*(?:[:=]|=>|:=)\\s*[\\\"']([A-Za-z0-9+/=_\\-.]{16,})[\\\"']",
    "flags": "gi",
    "severity": "medium",
    "minEntropy": 3.6,
    "group": 1,
    "explanation": "A high-entropy string assigned to a secret-looking name is almost always a live credential. In source control it is readable by everyone with repo access and by anyone who ever forks or clones.",
    "remediation": "Move the value to an environment variable or secrets manager, rotate it at the provider, and purge it from git history.",
    "references": []
  },
  {
    "id": "hardcoded-password",
    "title": "Hardcoded password",
    "pattern": "\\b(?:(?:[a-z0-9]+[_-]){0,3}(?:password|passwd|pwd|pass))\\b[\\\"']?\\s*(?:[:=]|=>|:=)\\s*[\\\"']([A-Za-z0-9+/=_\\-.]{8,})[\\\"']",
    "flags": "gi",
    "severity": "medium",
    "minEntropy": 3.0,
    "group": 1,
    "explanation": "A password embedded in source cannot be rotated without a code change, is visible to everyone with repository access, and tends to be reused across environments.",
    "remediation": "Read the password from configuration at runtime and rotate the existing one — assume it is known.",
    "references": []
  },
  {
    "id": "hardcoded-crypto-key",
    "title": "Hardcoded encryption key or IV",
    "pattern": "\\b(?:encryption[_-]?key|cipher[_-]?key|aes[_-]?key|hmac[_-]?key|signing[_-]?key|jwt[_-]?secret|secret|iv|salt)\\b[\\\"']?\\s*(?:[:=]|=>|:=)\\s*[\\\"']([A-Za-z0-9+/=_\\-.]{16,})[\\\"']",
    "flags": "gi",
    "severity": "high",
    "minEntropy": 3.6,
    "group": 1,
    "explanation": "A cryptographic key committed to source defeats the cryptography it protects: anyone with the repository can decrypt the data or forge signatures/tokens the key authenticates. Hardcoding also makes rotation a code change, so it never happens.",
    "remediation": "Generate a fresh key, load it from a secrets manager or KMS at runtime, and re-encrypt or invalidate anything the old key protected (existing JWTs and sessions must be treated as forgeable).",
    "references": []
  }
];
