# AI Code Review & Debug Copilot

An agentic code reviewer **and** whole-file debugger. A **LangGraph** agent runs
**ruff** + an **LLM** over a pull-request diff *or* a single whole file, verifies
each finding, and returns a structured report. Runs fully offline against a
**local model** (Ollama / llama.cpp / vLLM) — or OpenAI, or no model at all — and
ships a **LoRA fine-tuning** pipeline to sharpen the local model on your own code.

Ships with a FastAPI backend, an MCP server, a Chroma RAG index, review history,
an evaluation harness, a Streamlit demo, a Chrome extension, and a training
pipeline.

> **New here?** Read [`docs/GUIDE.md`](docs/GUIDE.md) — a guided, in-order tour of
> the codebase and the stack (LangGraph, the LLM seam, RAG, LoRA, deployment).

## Layout

One folder per thing. The folder name is what's in it.

```
backend/         FastAPI: routes, orchestration, error contract
agent/           the LangGraph agent: graph, nodes, diff parsing
llm_model/       the reviewers: mock, local, OpenAI + prompts + verifier
database/        SQLAlchemy models and session wiring
github_client/   GitHub I/O — diff.py reads, comment.py writes
mcp_server/      the two MCP tools, exposed over the protocol
rag/             Chroma index over files (diff-touched or a scanned repo)
training/        LoRA/QLoRA fine-tuning: curate → train → export → serve
streamlit_app/   the demo UI
extension/       Chrome extension (MV3): review PRs + scan & debug files
evaluation/      benchmark dataset + eval harness
scripts/         setup helpers (e.g. local Ollama model)
tests/           the whole test suite
docs/            the project spec + the codebase guide

config.py        every setting, read from the environment
schemas.py       the shared data contract — Report, Issue, requests
```

Everything imports from the repo root: `from agent.graph import ...`,
`from schemas import Report`. Run all commands from the repo root.

## Architecture

```
Streamlit / Chrome ext ─▶ FastAPI (:8001)
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
`github_client/comment.py` and is reachable only through an authenticated route
a human triggers. `tests/test_agent_safety.py` fails if anything under `agent/`
so much as references it.

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

.venv/Scripts/python.exe -m uvicorn backend.main:app --port 8001
```

With no configuration this runs in **mock mode**: no keys, no network, SQLite on
disk. Copy `.env.example` to `.env` to change that.

### Picking a reviewer

`LLM_BACKEND` selects one (default `auto`: local, then OpenAI, then mock).

| Mode | Set this |
|---|---|
| Local, fully offline | `LOCAL_LLM_BASE_URL=http://localhost:11434/v1`, `LOCAL_LLM_MODEL=qwen2.5-coder:7b` |
| Hosted OpenAI | `OPENAI_API_KEY=sk-...`, `OPENAI_MODEL=...` |
| No model | `LLM_BACKEND=mock` |

`GITHUB_TOKEN` is needed for the PR-URL path and for posting comments.

Small local models over-report. Two levers push precision back up:
`VERIFY_FINDINGS` (a second pass that must confirm each finding — wired in as the
`verify_findings` graph node) and `MIN_SEVERITY` (a floor on what ships). See
`llm_model/verify.py`.

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
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m ruff check .
```

## MCP server

```bash
pip install mcp
python -m mcp_server.server        # exposes fetch_diff + repo_context
```

## Docker (with Postgres `reviewdb`)

```bash
docker compose up --build
```

## Evaluation harness

```bash
python evaluation/run_eval.py
```

Runs the agent over `evaluation/benchmark_dataset.json`, prints a table (bugs
caught/missed, false positives, avg tokens, p95 latency), and writes
`evaluation/results.json`. The mock reviewer fires on every change, so the
false-positive rate only means something with a real reviewer configured; the
ruff findings are real either way.

## Streamlit demo

```bash
BACKEND_URL=http://localhost:8001 streamlit run streamlit_app/app.py
```

Tab 1: review a PR URL or diff, plus recent history. Tab 2: evaluation results.

## Chrome extension (MV3)

Load `extension/` via `chrome://extensions` → Developer mode → *Load unpacked*.
Two flows, both rendering findings in the toolbar popup:

- **Review a PR** — on any `github.com/<o>/<r>/pull/<n>` page a **"Review this
  PR"** button appears; it sends the PR's diff to `/review/full`.
- **Scan & debug a file** — on any repo page a **"🔎 Scan & Debug file"** button
  lists the repo's `.py` files; pick one and its content goes to `/debug/file`.

Set the backend URL (default `http://localhost:8001`) and an optional GitHub
token (raises the API rate limit for scanning) in the popup.

## Fine-tuning the local model (LoRA)

Sharpen the local reviewer on your own code, then serve it on CPU. Training needs
a GPU (Colab/RunPod); serving does not. See [`training/README.md`](training/README.md).

```bash
python training/curate_dataset.py --src <good-code-dir> --out training/data   # CPU
python training/iterate.py --data training/data --out training/adapters       # GPU
#   fine-tunes in rounds and stops at the improvement plateau
python training/export_to_gguf.py --base Qwen/Qwen2.5-Coder-3B-Instruct \
    --adapter training/adapters/round3 --out training/merged --llama-cpp <path>
ollama create codereview-qwen -f training/Modelfile
#   then set LOCAL_LLM_MODEL=codereview-qwen in .env
```

## Load test

```bash
locust -f locustfile.py --host http://localhost:8001
```

## Deploy

- **Backend:** `fly.toml` (Fly.io) or `Procfile` (Railway). Set `OPENAI_API_KEY`,
  `OPENAI_MODEL`, `GITHUB_TOKEN`, and attach Postgres.
- **CI:** `.github/workflows/ci.yml` runs lint → compile → tests → Docker build,
  with a `main`-gated deploy step to wire up.
