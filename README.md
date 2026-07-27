# AI Code Review & Debug Copilot

An agentic code reviewer **and** whole-file debugger. A **LangGraph** agent runs
**ruff** + an **LLM** over a pull-request diff *or* a single whole file, verifies
each finding, and returns a structured report. Runs against the **OpenAI API**
(the production default), a **local model** (Ollama / llama.cpp / vLLM), or a mock
with no keys at all — and ships a **LoRA fine-tuning** pipeline to sharpen a local
model on your own code.

Ships with a FastAPI backend, an MCP server, a Chroma RAG index, review history,
an evaluation harness, a Streamlit web app, a Chrome extension, and a training
pipeline.

> **New here?** Read [`docs/GUIDE.md`](docs/GUIDE.md) — a guided, in-order tour of
> the codebase and the stack (LangGraph, the LLM seam, RAG, LoRA, deployment).

## Layout

Grouped by concern, so the top level stays small.

```
src/            all Python service code — the import root
  backend/        FastAPI: routes, orchestration, error contract
  agent/          the LangGraph agents: graphs, nodes, diff parsing
  llm_model/      the reviewers: mock, local, OpenAI + prompts + verifier
  database/       SQLAlchemy models and session wiring
  github_client/  GitHub I/O — diff.py reads, comment.py writes
  mcp_server/     the two MCP tools, exposed over the protocol
  rag/            Chroma index over files (diff-touched or a scanned repo)
  config.py       every setting, read from the environment
  schemas.py      the shared data contract — Report, Issue, requests
apps/
  extension/      Chrome extension (MV3): review PRs + scan & debug files
  dashboard/      Streamlit web app
ml/             LoRA/QLoRA fine-tuning: curate → train → export → serve
evaluation/     benchmark dataset + eval harness
infra/          Dockerfile, docker-compose.yml, locustfile.py
scripts/        setup helpers (e.g. local Ollama model)
tests/          the whole test suite
docs/           the project spec + the codebase guide
```

`src/` is the single import root (`pyproject.toml` sets `pythonpath`), so code
does `from agent.graph import ...`, `from schemas import Report`. Run everything
from the repo root; set `PYTHONPATH=src` when launching the app directly.

## Architecture

```
Dashboard / Chrome ext ─▶ FastAPI (:8001)
                           └─ LangGraph agents (read-only, return a Report):
                                review: diff → ruff → llm_review → verify → aggregate
                                debug:  file → ruff → llm_debug  → verify → aggregate
                           └─ MCP tools: fetch_diff, repo_context
                           └─ RAG: Chroma index of touched files / a scanned repo
                           └─ Postgres/SQLite: review history

Explicit human action only ─▶ POST /reviews/{id}/post-comment (outside the agent)
```

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

With no configuration this runs in **mock mode**: no keys, no network, SQLite on
disk. Copy `.env.example` to `.env` to change that.

### Picking a reviewer

`LLM_BACKEND` selects one (`openai` | `local` | `mock` | `auto`).

| Mode | Set this |
|---|---|
| **OpenAI (production default)** | `LLM_BACKEND=openai`, `OPENAI_API_KEY=sk-...`, `OPENAI_MODEL=...` |
| Local, fully offline | `LLM_BACKEND=local`, `LOCAL_LLM_BASE_URL=http://localhost:11434/v1`, `LOCAL_LLM_MODEL=qwen2.5-coder:3b` |
| No model (dev/CI) | `LLM_BACKEND=mock` |

`GITHUB_TOKEN` is needed for the PR-URL path and for posting comments. `GET
/health` reports the backend actually in use.

Small models over-report. Two levers push precision up: `VERIFY_FINDINGS` (a
second pass that must confirm each finding — wired in as the `verify_findings`
graph node) and `MIN_SEVERITY` (a floor on what ships). See
`src/llm_model/verify.py`.

### Routes
| Method | Path | Purpose |
|---|---|---|
| POST | `/review` | Review `{"pr_url": ...}` **or** `{"diff": ...}`. Returns the report. |
| POST | `/review/full` | Same, but returns the stored record (`id` + report). |
| POST | `/debug/file` | Debug one whole file `{"path": ..., "content": ...}`. Returns the report. |
| POST | `/debug/file/full` | Same, but returns the stored record (`id` + report). |
| POST | `/scan/repo` | Index a repo's files for debug context (RAG; no-op without chromadb). |
| GET | `/health` | Liveness + active LLM backend (`mock` \| `local` \| `openai`). |
| GET | `/reviews` | List past reviews. |
| GET | `/reviews/{id}` | Full stored report. |
| POST | `/reviews/{id}/post-comment` | **Explicit, human-triggered.** Posts to the PR. |

## Tests and lint (same as CI)

```bash
.venv/Scripts/python.exe -m pytest          # pyproject puts src/ + . on the path
.venv/Scripts/python.exe -m ruff check .
```

## Web app (Streamlit)

```bash
BACKEND_URL=http://localhost:8001 streamlit run apps/dashboard/app.py
```
Tab 1: review a PR URL or diff + recent history. Tab 2: evaluation results.

## Chrome extension (MV3)

Load `apps/extension/` via `chrome://extensions` → Developer mode → *Load
unpacked*. Two flows, both rendering findings in the toolbar popup:

- **Review a PR** — on any `github.com/<o>/<r>/pull/<n>` page a **"Review this
  PR"** button sends the PR's diff to `/review/full`.
- **Scan & debug a file** — on any repo page a **"🔎 Scan & Debug file"** button
  lists the repo's `.py` files; pick one and its content goes to `/debug/file`.

Set the backend URL (default `http://localhost:8001`) and an optional GitHub
token (raises the API rate limit for scanning) in the popup.

## MCP server

```bash
pip install mcp
PYTHONPATH=src python -m mcp_server.server    # exposes fetch_diff + repo_context
```

## Evaluation harness

```bash
PYTHONPATH=src python evaluation/run_eval.py
```
Runs the agent over `evaluation/benchmark_dataset.json`, prints a table (bugs
caught/missed, false positives, F1, avg tokens, p95 latency), and writes
`evaluation/results.json`. The mock reviewer fires on every change, so the
false-positive rate only means something with a real reviewer configured; the
ruff findings are real either way.

## Fine-tuning a local model (LoRA)

Sharpen a local reviewer on your own code, then serve it on CPU. Training needs a
GPU (Colab/RunPod); serving does not. See [`ml/README.md`](ml/README.md).

```bash
python ml/curate_dataset.py --src <good-code-dir> --out ml/data     # CPU
python ml/iterate.py --data ml/data --out ml/adapters               # GPU
#   fine-tunes in rounds and stops at the improvement plateau
python ml/export_to_gguf.py --base Qwen/Qwen2.5-Coder-3B-Instruct \
    --adapter ml/adapters/round3 --out ml/merged --llama-cpp <path>
ollama create codereview-qwen -f ml/Modelfile      # then LOCAL_LLM_MODEL=codereview-qwen
```

## Docker & load test

```bash
docker compose -f infra/docker-compose.yml up --build     # API + Postgres reviewdb
locust -f infra/locustfile.py --host http://localhost:8001
```

## Deploy

Production runs the **OpenAI** reviewer (no local model server in the cloud).

- **Fly.io:** `fly deploy` from the repo root (uses `fly.toml` →
  `infra/Dockerfile`). `fly secrets set OPENAI_API_KEY=... OPENAI_MODEL=...
  GITHUB_TOKEN=...`; `LLM_BACKEND=openai` is set in `fly.toml`. Attach Postgres
  with `fly postgres attach`.
- **Railway/Heroku:** the root `Procfile` runs `uvicorn` with `PYTHONPATH=src`.
  Set the same env vars; add a Postgres addon for `DATABASE_URL`.
- **Web app:** deploy `apps/dashboard/app.py` to Streamlit Community Cloud; set
  `BACKEND_URL` to your deployed API.
- **Extension:** ship `apps/extension/` (set the backend URL in the popup).
- **CI (`.github/workflows/ci.yml`):** lint → compile → tests → Docker build, with
  a `main`-gated deploy step to wire up.
