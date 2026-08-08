# Repo Security Scanner

A Chrome extension and **LangGraph** backend that scan a GitHub repository for
three concrete classes of security problem — and use an LLM for judgement, not
for detection.

**Detection is done by tools, deterministically:**

| Category | How it is found |
|---|---|
| **Exposed secrets** | ~25 gitleaks-derived regex fingerprints (AWS keys, private keys, GitHub/Stripe/Slack/OpenAI tokens, DB URLs with passwords) plus Shannon-entropy checks for generic `secret = "..."` assignments |
| **Vulnerable dependencies** | `requirements.txt` / `pyproject.toml` / `Pipfile.lock` / `package.json` / `package-lock.json` / `yarn.lock` parsed for resolved versions, checked against the **OSV** database (GHSA + PySec + CVE) |
| **Unsafe code patterns** | **bandit** on Python (unsafe `eval`, SQL string concatenation, hardcoded credentials, `pickle`/`yaml.load` deserialization, weak hashes) and **eslint-plugin-security** on JS/TS, plus pattern rules for the XSS sinks and insecure ciphers eslint has no rules for |

**The LLM's job is what tools are bad at:** deduplicating overlapping findings,
re-ranking them by real-world exploitability against the surrounding code,
explaining in plain language what an attacker actually gets, and proposing a
concrete fix. It cannot create a finding, move one, or change which rule fired —
replies are matched back to detector output by id and anything unrecognised is
discarded. Turn it off (`SECURITY_TRIAGE=false`) and the scan still works with
the rule-authored explanations.

Runs against the **OpenAI API**, a **local model** (Ollama / llama.cpp / vLLM),
or with no model at all. Also retains the original PR code-review flow, scan
history, an evaluation harness, a Streamlit web app, and a **LoRA fine-tuning**
pipeline.

> **New here?** Read [`docs/GUIDE.md`](docs/GUIDE.md) — a guided, in-order tour of
> the codebase and the stack (detectors, LangGraph, the LLM seam, LoRA, deployment).

## Layout

Grouped by concern, so the top level stays small.

```
src/            all Python service code — the import root
  security/       the three detectors + LLM triage
    rules.py        gitleaks-derived secret rules (regex + entropy floors)
    secrets_scan.py detector 1 — secrets, and the redaction used everywhere
    deps_scan.py    detector 2 — manifest parsing + OSV lookup
    osv.py            the OSV API client
    code_scan.py    detector 3 — bandit + eslint-plugin-security
    eslint/           isolated eslint install + its flat config
    triage.py       the LLM stage: dedupe, rank, explain, fix
  backend/        FastAPI: routes, orchestration, error contract
  agent/          the LangGraph agents: security_graph.py, graph.py, diff parsing
  llm_model/      the LLM seam: mock, local, OpenAI + prompts + verifier
  database/       SQLAlchemy models and session wiring
  github_client/  GitHub I/O — diff.py reads, comment.py writes
  config.py       every setting, read from the environment
  schemas.py      the shared data contract — SecurityReport, Report, requests
  apps/
    extension/      Chrome extension (MV3): security scan + PR review
    dashboard/      Streamlit web app
  ml/             LoRA/QLoRA fine-tuning: curate → train → export → serve
    evaluation/     benchmark dataset + eval harness
deploy/         Dockerfile, docker-compose.yml, locustfile.py, setup helpers
tests/          the whole test suite
docs/           the project spec + the codebase guide
```

`src/` is the single import root (`pyproject.toml` sets `pythonpath`), so code
does `from agent.graph import ...`, `from schemas import Report`. Run everything
from the repo root; set `PYTHONPATH=src` when launching the app directly.

## Architecture

```
Chrome ext / Dashboard ─▶ FastAPI (:8001)
                           └─ LangGraph agents (read-only, return a report):
                                security: files → secrets → deps(OSV) → code(bandit,
                                          eslint) → redact → triage(LLM) → aggregate
                                review:   diff  → ruff → llm_review → verify → aggregate
                           └─ Postgres/SQLite: scan + review history

Explicit human action only ─▶ POST /reviews/{id}/post-comment (outside the agent)
```

The extension collects the repo's files itself (GitHub tree API + raw contents)
and posts them; the backend never reaches into a repository the caller did not
send. Vendored trees, binaries, and minified bundles are dropped before any
detector runs.

**Secrets never leave the scanner in the clear.** The secret detector redacts
its own evidence, and a `redact_findings` graph node scrubs every other
detector's output too — bandit's `B105` finding quotes the offending source line
verbatim, so without it a token would reach the database, the browser, and the
triage prompt. The model is asked to rank a leaked credential without being
shown it.

**Safety boundary:** the agent has no tool that can post, merge, or modify
anything — it only returns a report. The single write path lives in
`src/github_client/comment.py` and is reachable only through an authenticated
route a human triggers. `tests/test_agent_safety.py` fails if anything under
`src/agent/` so much as references it.

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

PYTHONPATH=src .venv/Scripts/python.exe -m uvicorn backend.main:app --port 8001
```

Then load `src/apps/extension/` at `chrome://extensions` (Developer mode → *Load
unpacked*), open any GitHub repository, and click **🛡️ Security scan**.

With no configuration this runs the detectors and skips LLM triage: no keys
needed, SQLite on disk. Secrets and unsafe-code detection are fully offline; the
dependency detector needs network access to reach OSV. Copy `.env.example` to
`.env` to change any of that.

### Enabling the JS/TS linter

`bandit` ships in `requirements.txt`, so Python is covered out of the box.
`eslint-plugin-security` needs Node:

```bash
cd src/security/eslint && npm install
```

Without it, JS/TS falls back to a narrower set of regex checks and every scan
says so in its `degraded` list — a detector that could not run is never reported
as a clean result.

### Suppressing known findings

Real repositories contain credential-shaped strings that exist on purpose —
documented example tokens, test fixtures, deliberately vulnerable sample code. A
`.secscanignore` at the repo root drops them, gitignore-style:

```
docs/**                   # every finding under docs/
tests/**:github-pat       # one rule, only under tests/
:B101                     # one rule, anywhere
deploy/docker-compose.yml:database-connection-string
```

Suppressed findings are dropped rather than flagged — a report you have to
mentally filter is the thing this exists to prevent — but the count is reported
in `report.suppressed`, so a file that silences everything is visible. This repo
ships one: the secret detector's own test fixtures would otherwise dominate its
self-scan.

### Picking a reviewer

`LLM_BACKEND` selects one (`openai` | `local` | `mock` | `auto`).

| Mode | Set this |
|---|---|
| **OpenAI (production default)** | `LLM_BACKEND=openai`, `OPENAI_API_KEY=sk-...`, `OPENAI_MODEL=...` |
| Local, fully offline | `LLM_BACKEND=local`, `LOCAL_LLM_BASE_URL=http://localhost:11434/v1`, `LOCAL_LLM_MODEL=qwen2.5-coder:3b` |
| No model (dev/CI) | `LLM_BACKEND=mock` |

`GITHUB_TOKEN` is needed for the PR-URL path and for posting comments. `GET
/health` reports the backend actually in use.

The security scanner's own knobs: `SECURITY_TRIAGE` (turn the LLM stage off
entirely), `SECURITY_OFFLINE` (skip the OSV lookup for air-gapped runs), and
`MAX_SCAN_FILES` / `MAX_SCAN_BYTES` (payload caps). For the PR review flow,
`VERIFY_FINDINGS` and `MIN_SEVERITY` still apply — see `src/llm_model/verify.py`.

### Routes
| Method | Path | Purpose |
|---|---|---|
| POST | `/security/scan` | Scan `{"repo": ..., "ref": ..., "files": [{path, content}]}`. Returns the security report. |
| POST | `/security/scan/full` | Same, but returns the stored record (`id` + report). |
| GET | `/security/scans` | List past security scans. |
| GET | `/security/scans/{id}` | Full stored security report. |
| POST | `/review` | Review `{"pr_url": ...}` **or** `{"diff": ...}`. Returns the report. |
| POST | `/review/full` | Same, but returns the stored record (`id` + report). |
| GET | `/health` | Liveness + active LLM backend (`mock` \| `local` \| `openai`). |
| GET | `/reviews` | List past reviews. |
| GET | `/reviews/{id}` | Full stored report. |
| POST | `/reviews/{id}/post-comment` | **Explicit, human-triggered.** Posts to the PR. |

## Tests and lint (same as CI)

```bash
.venv/Scripts/python.exe -m pytest          # pyproject puts src/ on the path
.venv/Scripts/python.exe -m ruff check .
```

## Web app (Streamlit)

```bash
BACKEND_URL=http://localhost:8001 streamlit run src/apps/dashboard/app.py
```
Tab 1: review a PR URL or diff + recent history. Tab 2: evaluation results.

## Chrome extension (MV3)

Load `src/apps/extension/` via `chrome://extensions` → Developer mode → *Load
unpacked*. Two flows, both rendering findings in the toolbar popup:

- **Security scan** (primary) — on any repo page, **"🛡️ Security scan"** walks
  the repository tree, fetches the scannable files (source, manifests, CI and
  infra configs — not `node_modules`, binaries, or minified bundles), and posts
  them to `/security/scan/full`. Findings are grouped by category with the
  redacted evidence, the plain-language reason, and the fix; each links to the
  exact line on GitHub.
- **Review a PR** — on any `github.com/<o>/<r>/pull/<n>` page a **"Review this
  PR"** button sends the PR's diff to `/review/full`.

Selection is capped (600 files / 12 MB) and prioritised so manifests and config
files are sent first — if a monorepo is truncated, the dependency detector still
gets its inputs and the popup says the scan was partial.

Set the backend URL (default `http://localhost:8001`) and an optional GitHub
token (raises the API rate limit, needed for any sizeable repo) in the popup.

## Evaluation harness

```bash
python src/ml/evaluation/run_eval.py
```
Runs the agent over `src/ml/evaluation/benchmark_dataset.json`, prints a table (bugs
caught/missed, false positives, F1, avg tokens, p95 latency), and writes
`src/ml/evaluation/results.json`. The mock reviewer fires on every change, so the
false-positive rate only means something with a real reviewer configured; the
ruff findings are real either way.

## Fine-tuning a local model (LoRA)

Sharpen a local reviewer on your own code, then serve it on CPU. Training needs a
GPU (Colab/RunPod); serving does not. See [`src/ml/README.md`](src/ml/README.md).

```bash
python src/ml/curate_dataset.py --src <good-code-dir> --out src/ml/data     # CPU
python src/ml/iterate.py --data src/ml/data --out src/ml/adapters               # GPU
#   fine-tunes in rounds and stops at the improvement plateau
python src/ml/export_to_gguf.py --base Qwen/Qwen2.5-Coder-3B-Instruct \
    --adapter src/ml/adapters/round3 --out src/ml/merged --llama-cpp <path>
ollama create codereview-qwen -f src/ml/Modelfile      # then LOCAL_LLM_MODEL=codereview-qwen
```

## Docker & load test

```bash
docker compose -f deploy/docker-compose.yml up --build     # API + Postgres reviewdb
locust -f deploy/locustfile.py --host http://localhost:8001
```

## Deploy

Production runs the **OpenAI** reviewer (no local model server in the cloud).

- **Fly.io:** `fly deploy` from the repo root (uses `fly.toml` →
  `deploy/Dockerfile`). `fly secrets set OPENAI_API_KEY=... OPENAI_MODEL=...
  GITHUB_TOKEN=...`; `LLM_BACKEND=openai` is set in `fly.toml`. Attach Postgres
  with `fly postgres attach`.
- **Railway/Heroku:** the root `Procfile` runs `uvicorn` with `PYTHONPATH=src`.
  Set the same env vars; add a Postgres addon for `DATABASE_URL`.
- **Web app:** deploy `src/apps/dashboard/app.py` to Streamlit Community Cloud; set
  `BACKEND_URL` to your deployed API.
- **Extension:** ship `src/apps/extension/` (set the backend URL in the popup).
- **CI (`.github/workflows/ci.yml`):** lint → compile → tests → Docker build, with
  a `main`-gated deploy step to wire up.
