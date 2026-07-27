"""Load test for the backend.

Run against a live backend, from the repo root:
    locust -f locustfile.py --host http://localhost:8001

Then open http://localhost:8089, set users/spawn-rate, and read p95 latency +
throughput from the Locust UI (or use --headless --run-time 1m --csv results).
"""
from locust import HttpUser, between, task

_SAMPLE_DIFF = (
    "diff --git a/example.py b/example.py\n"
    "--- a/example.py\n+++ b/example.py\n"
    "@@ -1,2 +1,4 @@\n import os\n+import sys\n+\n def foo():\n"
    "+    x = 1\n     return 1\n"
)


class ReviewUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def review_diff(self):
        self.client.post("/review", json={"diff": _SAMPLE_DIFF}, name="POST /review")

    @task(1)
    def health(self):
        self.client.get("/health", name="GET /health")

    @task(1)
    def history(self):
        self.client.get("/reviews", name="GET /reviews")
