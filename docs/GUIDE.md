# Codebase guide — read this in order

A guided tour of the AI Code Review & Debug Copilot, meant to be read top to
bottom with the files open beside it. It explains **what each part does, why it
exists, and the pattern worth stealing** — so you finish understanding not just
this repo but the ideas (agents, RAG, LLM seams, LoRA fine-tuning, deployment)
behind it.

## 1. The 60-second picture

```
Streamlit dashboard ─┐
Chrome extension    ─┼─▶ FastAPI backend (:8001)
  • PR → Review      │      ├─ review graph:  diff → ruff → LLM → verify → aggregate → Report
  • repo → Debug file│      ├─ debug graph:   file → ruff → LLM → verify → aggregate → Report
                     │      ├─ LLM seam (llm_model/): mock | local (Ollama) | OpenAI
                     │      ├─ RAG (Chroma, optional): repo context
                     │      └─ SQLite/Postgres: review history
Explicit human click ─▶ POST /reviews/{id}/post-comment   (the ONLY write path)

training/  ── curate → QLoRA fine-tune (GPU) → export GGUF → serve on CPU (Ollama)
```

Two ideas hold the whole thing together:

1. **A frozen data contract** (`schemas.py`): every component speaks `Report`.
2. **A swappable LLM seam** (`llm_model/`): the reviewer's *implementation*
   changes (mock ↔ local ↔ hosted) but the *interface* never does.

## 2. Reading order

Follow this path; each stop lists the file and the one thing to take away.

| # | File | What it is | Take away |
|---|------|-----------|-----------|
| 1 | `schemas.py` | Pydantic `Issue`/`Report` + request models | One shared contract everything imports; change it → change everything on purpose |
| 2 | `config.py` | pydantic-settings; all env in one `settings` | No scattered `os.getenv`; `active_backend`/`llm_available` derive behaviour from config |
| 3 | `agent/diff_utils.py` | tiny unified-diff parser; `DiffFile` | `from_full_file` reuses the diff machinery for whole-file debug (every line "added") |
| 4 | `llm_model/prompts.py` | every prompt string | Tight bug taxonomy + "stay silent" is what stops a small model over-reporting |
| 5 | `llm_model/base.py` | `ReviewLLM` protocol, `ChatReviewLLM`, `get_review_llm()` | **The seam.** Subclasses only build a client; `_run` does prompt→JSON→`Issue` |
| 6 | `llm_model/{mock,local,openai}_model.py` | the three backends | local & OpenAI differ by *one constructor*; mock keeps everything offline |
| 7 | `llm_model/verify.py` | second-pass auditor + `validate_fix` | Precision layer: proposer casts wide, verifier confirms, fixes must `ast.parse` |
| 8 | `agent/nodes.py` | ruff runner + LLM call wrappers | Pure functions → trivially unit-testable; findings mapped to real line numbers |
| 9 | `agent/graph.py` | the two LangGraph graphs + entry points | `run_review_graph` (diff) and `run_debug_file` (whole file) share nodes |
| 10 | `backend/service.py` | orchestration + persistence + guards | The only place that touches both the agent and the DB |
| 11 | `backend/main.py` | routes, CORS, error handlers | Thin HTTP layer; `/debug/file`, `/scan/repo`, and the human-only post-comment route |
| 12 | `github_client/` | diff fetch + comment post | `comment.py` is the single write path, outside the agent by design |
| 13 | `rag/indexer.py` | Chroma index, degrades to no-op | Optional context; `index_files` stores whole files for the debug flow |
| 14 | `mcp_server/` | the two tools exposed over MCP | Same tool logic FastAPI calls, also available to MCP clients |
| 15 | `tests/` | unit + contract + safety | `test_agent_safety.py` mechanically proves the agent can't write |
| 16 | `extension/` | MV3 Chrome extension | `content_script.js` (PR) + `repo_script.js` (scan & debug) → backend |
| 17 | `streamlit_app/app.py` | the dashboard | Reads the same `Report`; nothing UI-specific leaks into the backend |
| 18 | `evaluation/run_eval.py` | labeled benchmark harness | Credibility: bugs caught/missed, FP rate, tokens, p95 latency |
| 19 | `training/` | LoRA fine-tuning pipeline | Curate → train (GPU) → export → serve (CPU); iterate to a plateau |

## 3. The tech stack, and how we actually use it

### LangGraph (agent orchestration)
`agent/graph.py` builds a `StateGraph` over a `TypedDict` state. Each node is a
plain function that takes and returns a slice of state; edges wire them into a
fixed line: `fetch/load → static analysis → LLM → verify → aggregate`. We use
LangGraph for **structure and a safety boundary**, not for a swarm of autonomous
agents — the graph can only ever return a `Report`, and a test enforces that no
node name (or import) touches the write path. That "an agent is a state machine
whose transitions you control" is the whole lesson.

> **LangChain vs LangGraph:** this project uses *LangGraph* (the graph runtime)
> and talks to models through the **OpenAI SDK** directly (`llm_model/`). It does
> not use LangChain's chains/agents abstractions — deliberately, because the seam
> is small and explicit. If you came here to learn "LangChain," the transferable
> idea is the graph + the typed contract, not a specific import.

### The swappable LLM seam (`llm_model/`)
`ReviewLLM` is a `Protocol` with two methods (`review_file`, `debug_file`). Real
backends inherit `ChatReviewLLM`, which owns prompt formatting, the single
JSON-mode chat call, lenient JSON parsing (small models fence their output), and
mapping replies to `Issue`s. `LocalReviewLLM` and `OpenAIReviewLLM` differ only in
which client they build. `get_review_llm()` picks one from `LLM_BACKEND`. **This
is the pattern to internalize:** program to an interface, make the swap a config
value, keep the mock in the same shape so the whole system runs offline.

### Static analysis (`ruff`)
Deterministic, precise, free. `agent/nodes.py` shells out to `ruff --stdin` and
maps findings back to real line numbers. On the diff path it drops syntax errors
(artifacts of a partial file); on the whole-file debug path it keeps them (real
`E999`). ruff findings bypass the LLM verifier — they're already trustworthy.

### RAG (Chroma)
`rag/indexer.py` embeds file contents into a local Chroma store and answers
similarity queries for "related code." It's entirely optional: without `chromadb`
installed every function no-ops, so the app never depends on it. Lesson:
**make heavy/optional dependencies degrade to nothing**, not to an error.

### Precision by design (proposer → verifier)
A single small model told to "review this code" flags something on every change.
The fix is two roles: the proposer (recall) casts a wide net; the verifier
(precision) answers one narrow yes/no per candidate; and `validate_fix` throws
away any suggested fix that isn't valid Python. Precision is the binding
constraint, so the architecture spends its complexity there.

### LoRA / QLoRA fine-tuning (`training/`)
- **LoRA** freezes the base model and trains small low-rank adapter matrices on
  top — a few million parameters instead of billions, so it fits one GPU and
  produces a tiny artifact. **QLoRA** adds 4-bit quantization of the frozen base,
  cutting VRAM further (~12-16 GB for a 3-7B model).
- **What you train on matters more than how.** Fine-tuning on clean "good code"
  makes a *generator*, not a *detector*. `curate_dataset.py` instead builds a
  **labeled** set: clean negatives + buggy positives (one injected taxonomy bug
  per example, original line as the fix), rendered with the exact runtime prompts.
- **You can't train on CPU.** `train_lora.py` needs CUDA; run it on Colab/RunPod.
  `iterate.py` fine-tunes in rounds of increasing effort, scores F1 on a held-out
  split each round, and **stops when improvement flattens** — the empirical way to
  find "as good as this data/base will get."
- **Serve the result on CPU.** `export_to_gguf.py` merges the adapter, converts to
  GGUF (llama.cpp), and `ollama create`s it. Point `LOCAL_LLM_MODEL` at it — no
  backend code changes, because of the seam.

### Serving locally via Ollama/GGUF
Ollama exposes an OpenAI-compatible `/v1` endpoint, so `LocalReviewLLM` talks to it
with the same SDK it would use for OpenAI — only `base_url` differs. GGUF is the
quantized on-disk format llama.cpp/Ollama run efficiently on CPU.

### The Chrome extension (MV3)
`content_script.js` adds a "Review this PR" button on PR pages and fetches the
public `<pr>.diff`. `repo_script.js` adds "Scan & Debug file" on repo pages: it
lists `.py` files via the GitHub API, fetches one raw file, and posts it to
`/debug/file`. `background.js` (a service worker) is the one place that calls the
backend; the popup renders the shared `Report`. Note the security posture: minimal
permissions, and the backend still can't write anything.

### Persistence, deployment, CI
- **DB:** SQLAlchemy over SQLite by default (zero setup), Postgres in Docker.
- **Docker:** `Dockerfile` + `docker-compose.yml` at the repo root — one image,
  `uvicorn backend.main:app`, with Postgres in compose.
- **Deploy:** `fly.toml` (Fly.io) or `Procfile` (Railway); cloud runs the hosted
  model, local runs Ollama.
- **CI (`.github/workflows/ci.yml`):** ruff → compile → pytest (mock backend) →
  docker build → gated deploy. Everything runs from the repo root — the single
  import root (`pyproject.toml pythonpath=["."]`).

## 4. Try the whole thing

```bash
# backend (mock — zero setup)
./backend/.venv/Scripts/python.exe -m uvicorn backend.main:app --port 8001
curl -X POST localhost:8001/debug/file -H "Content-Type: application/json" \
     -d '{"path":"x.py","content":"import os\ndef f():\n    try:\n        pass\n    except:\n        pass\n"}'

# real local model (CPU)
./scripts/setup_local_model.ps1            # pulls qwen2.5-coder:3b in Ollama
#   .env:  LLM_BACKEND=local

# dashboard
BACKEND_URL=http://localhost:8001 streamlit run streamlit_app/app.py

# extension: load extension/ unpacked at chrome://extensions

# fine-tune (GPU box) then serve on CPU
python training/curate_dataset.py --src . --out training/data
python training/iterate.py --data training/data --out training/adapters
```

## 5. Patterns worth keeping

1. **One typed contract at the center.** `Report` decouples every component.
2. **Program to an interface; make the swap config.** The LLM seam.
3. **Optional deps degrade to no-ops**, never to crashes (RAG, MCP).
4. **Split recall and precision** into separate, testable roles.
5. **Mechanical guarantees over trust.** `validate_fix` parses; the safety test
   proves the agent can't write; training targets are always valid JSON.
6. **Measure before you believe.** The eval harness and the plateau loop exist so
   "it got better" is a number, not a vibe.
