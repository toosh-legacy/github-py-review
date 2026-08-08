"""Configuration for the benchmark fixture app.

BENCHMARK FIXTURE — every credential below is synthetic and was never issued.
This file exists to be scanned; see ground_truth.json for what should fire.
"""
import os

# --- planted: must be detected -------------------------------------------- #
AWS_ACCESS_KEY_ID = "AKIA4NHQ7ZP2VXK3MTBW"
aws_secret_access_key = "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"
GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
STRIPE_KEY = "sk_live_51HxQmZ2eZvKYlo2CkL9mNbVc"
DATABASE_URL = "postgres://svc_app:Hn4pV2xQmL8w@db.prod.internal:5432/orders"
JWT_SECRET = "zR7mK2pQ8xW4vN6bY1cJ5tH3gF9dS0aL"

# --- decoys: must NOT be detected ------------------------------------------ #
# Documented AWS sample key — appears verbatim in AWS's own docs.
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
# Templated, not a value.
VAULT_SECRET = "${VAULT_CLIENT_SECRET}"
# A placeholder for the reader to replace.
API_KEY = "<your-api-key-here>"
# Low-entropy: a header name, not a credential, despite the variable name.
api_key_header = "x-application-api-key-header"
# Repeated filler.
PLACEHOLDER_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
# The real credential is read from the environment, as it should be.
SESSION_SECRET = os.environ["SESSION_SECRET"]
# A URL with a username but no password is not a credential leak.
METRICS_URL = "postgres://readonly@metrics.internal:5432/stats"
