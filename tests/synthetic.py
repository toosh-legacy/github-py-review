"""Synthetic credentials for the detector tests.

Every value here is invented and was never issued by anyone — but they are
*shaped* correctly on purpose, because that is what makes them useful inputs for
a secret detector.

They are assembled at import time rather than written as literals. A
credential-shaped string sitting in a source file is indistinguishable from a
real leak to any scanner that reads the file as text — GitHub's push protection,
this project's own detector, and anyone else's. Splitting them means the repo
contains no plaintext credential while the tests still receive the exact value
they need at runtime.

The same reasoning applies to the benchmark corpus, which is stored encoded for
the same reason; see `src/evaluation/security_benchmark/corpus.json`.
"""
from __future__ import annotations

AWS_KEY_ID = "AKIA" + "4NHQ7ZP2VXK3MTBW"
AWS_SECRET = "kJ7xQm2LpR9tVbN4wZ8s" + "Yc1EgH6dFa0UjO3iPnXr"
GITHUB_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
ANTHROPIC_KEY = "sk-ant-" + "api03-QmFzZTY0RW5jb2RlZFN0cmluZ1hZWjEyMzQ"
SLACK_TOKEN = "xoxb-" + "2847561930-4471829365-Jd83kFmQpZx71LsWnRb2Yh4T"
STRIPE_KEY = "sk_live_" + "51HxQmZ2eZvKYlo2CkL9mNbVc"
POSTGRES_URL = "postgres://admin:" + "Str0ngP4ssw0rd" + "@db.internal:5432/prod"
HIGH_ENTROPY = "hQ7zRt3XmW9pLd2Vb" + "N6cKfJ8sYaG4uEo"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEow" + "IBAAKCAQEArandomlookingbase64content\n"
    "-----END RSA PRIVATE KEY-----\n"
)

# AWS's own documented sample key. It appears verbatim in their docs, so the
# detector must never report it — this is a decoy, not a credential.
AWS_DOC_SAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
