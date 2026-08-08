"""Load test for the scan API.

    locust -f deploy/locustfile.py --host http://localhost:8001

A scan is far heavier than a typical HTTP request — it forks bandit and eslint
over a temp copy of every submitted file — so the point of this is to find where
concurrency starts queueing, not to chase a big requests-per-second number.
"""
from locust import HttpUser, between, task

# Small but representative: one planted secret, one unsafe pattern, one manifest
# so all three detectors do work.
#
# The token is assembled at runtime rather than written as a literal. It is
# synthetic either way, but a security scanner should not ship credential-shaped
# strings in its own source — our own CI scan flags them, correctly, and the fix
# for a finding is to remove the pattern rather than to silence the rule.
_FAKE_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

_FILES = [
    {
        "path": "app/config.py",
        "content": f'TOKEN = "{_FAKE_PAT}"\n',
    },
    {
        "path": "app/db.py",
        "content": (
            "def get(conn, uid):\n"
            '    return conn.execute("SELECT * FROM t WHERE id = " + uid)\n'
        ),
    },
    {"path": "requirements.txt", "content": "requests==2.19.0\n"},
]


class ScannerUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def scan(self):
        self.client.post(
            "/security/scan",
            json={"repo": "loadtest/repo", "files": _FILES},
            name="POST /security/scan",
        )

    @task(1)
    def health(self):
        self.client.get("/health", name="GET /health")

    @task(1)
    def history(self):
        self.client.get("/security/scans", name="GET /security/scans")
