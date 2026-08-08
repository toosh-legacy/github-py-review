# Codebase guide — read this in order

A guided tour of the Repo Security Scanner, meant to be read top to bottom with
the files open beside it. It explains **what each part does, why it exists, and
the pattern worth stealing** — so you finish understanding not just this repo but
the ideas (tool-driven detection, agents, LLM seams, LoRA fine-tuning,
deployment) behind it.

## 1. The 60-second picture

```
Chrome extension    ─┐
Streamlit dashboard ─┼─▶ FastAPI backend (:8001)
  • repo → Security   │      ├─ security graph: files → secrets → deps(OSV)
    scan             │      │                       → code(bandit, eslint)
  • PR → Review      │      │                       → redact → triage(LLM)
                     │      │                       → aggregate → SecurityReport
                     │      ├─ review graph:  diff → ruff → LLM → verify → Report
                     │      ├─ LLM seam (llm_model/): mock | local (Ollama) | OpenAI
                     │      └─ SQLite/Postgres: scan + review history
Explicit human click ─▶ POST /reviews/{id}/post-comment   (the ONLY write path)

src/ml/        ── curate → QLoRA fine-tune (GPU) → export GGUF → serve on CPU (Ollama)
```

Three ideas hold the whole thing together:

1. **Tools detect, the model judges.** Whether a string is an AWS key, whether
   `flask==0.12.2` has a CVE, whether a line is a SQL-injection sink — these are
   decidable, so a rule decides them. The model does the part rules cannot:
   collapsing duplicates, judging exploitability *in this codebase*, explaining
   the risk, and writing the fix. An LLM asked to *find* vulnerabilities
   hallucinates some and misses others; an LLM asked to *rank and explain* a
   list it cannot extend is doing something it is reliably good at.
2. **A frozen data contract** (`schemas.py`): every component speaks
   `SecurityReport` (or `Report` for the older PR-review flow).
3. **A swappable LLM seam** (`llm_model/`): the implementation changes
   (mock ↔ local ↔ hosted) but the interface never does.

## 2. Reading order

Follow this path; each stop lists the file and the one thing to take away.

| # | File | What it is | Take away |
|---|------|-----------|-----------|
| 1 | `src/schemas.py` | Pydantic `SecurityFinding`/`SecurityReport`, `Issue`/`Report` | One shared contract everything imports; detector provenance is kept separate from LLM triage |
| 2 | `src/config.py` | pydantic-settings; all env in one `settings` | No scattered `os.getenv`; `active_backend`/`llm_available` derive behaviour from config |
| 2a | `src/security/rules.py` | gitleaks-derived secret rules | Fingerprint rules need no entropy gate; generic ones are useless without it |
| 2b | `src/security/secrets_scan.py` | detector 1 + `scrub()` | Placeholder suppression is why the scanner stays usable; `scrub` is the redaction every path out uses |
| 2c | `src/security/deps_scan.py` | detector 2: manifests → OSV | Lockfiles beat manifests: an unresolved range is reported, never guessed |
| 2d | `src/security/code_scan.py` | detector 3: bandit + eslint | A missing analyzer degrades loudly; it never reads as a clean result |
| 2e | `src/security/triage.py` | the LLM stage | `_apply` is the trust boundary: unknown ids dropped, lost findings → reject the whole reply |
| 2f | `src/agent/security_graph.py` | the security LangGraph | Detection nodes call no model at all; `redact_findings` runs before triage sees anything |
| 3 | `src/agent/diff_utils.py` | tiny unified-diff parser; `DiffFile` | Findings map back to real file line numbers, not hunk offsets |
| 4 | `src/llm_model/prompts.py` | the review + triage prompts | The triage prompt states the finding list is closed — and `_apply` enforces it |
| 5 | `src/llm_model/base.py` | `ReviewLLM` protocol, `ChatReviewLLM`, `get_review_llm()` | **The seam.** Subclasses only build a client; `_run` does prompt→JSON→`Issue` |
| 6 | `src/llm_model/{mock,local,openai}_model.py` | the three backends | local & OpenAI differ by *one constructor*; mock keeps everything offline |
| 7 | `src/llm_model/verify.py` | second-pass auditor + `validate_fix` | Precision layer: proposer casts wide, verifier confirms, fixes must `ast.parse` |
| 8 | `src/agent/nodes.py` | ruff runner + LLM call wrappers | Pure functions → trivially unit-testable; findings mapped to real line numbers |
| 9 | `src/agent/graph.py` | the PR-review LangGraph | Same shape as the security graph, different nodes — worth comparing the two |
| 10 | `src/backend/service.py` | orchestration + persistence + guards | The only place that touches both the agent and the DB |
| 11 | `src/backend/main.py` | routes, CORS, error handlers | Thin HTTP layer; `/security/scan` and the human-only post-comment route |
| 12 | `src/github_client/` | diff fetch + comment post | `comment.py` is the single write path, outside the agent by design |
| 13 | `tests/` | unit + contract + safety | `test_agent_safety.py` mechanically proves the agent can't write |
| 14 | `src/apps/extension/` | MV3 Chrome extension | `security_script.js` (repo scan) + `content_script.js` (PR) → backend |
| 15 | `src/apps/dashboard/app.py` | the Streamlit web app | Reads the same `Report`; nothing UI-specific leaks into the backend |
| 16 | `src/ml/evaluation/run_eval.py` | labeled benchmark harness | Credibility: bugs caught/missed, FP rate, tokens, p95 latency |
| 17 | `src/ml/` | LoRA fine-tuning pipeline | Curate → train (GPU) → export → serve (CPU); iterate to a plateau |

## 3. The tech stack, and how we actually use it

### LangGraph (agent orchestration)
`agent/security_graph.py` builds a `StateGraph` over a `TypedDict` state. Each
node is a plain function that takes and returns a slice of state; edges wire them
into a fixed line: `collect → secrets → dependencies → code → redact → triage
→ aggregate` (and `agent/graph.py` does the same for the PR-review flow). We use
LangGraph for **structure and a safety boundary**, not for a swarm of autonomous
agents — the graph can only ever return a report, and a test enforces that no
node name (or import) touches the write path. That "an agent is a state machine
whose transitions you control" is the whole lesson.

Note what the node *order* buys: detection nodes are independent and could run in
any order, but `redact_findings` must sit between them and `triage_findings`. It
is the graph that makes "no raw credential reaches the model" a structural
property rather than a rule each detector has to remember.

> **LangChain vs LangGraph:** this project uses *LangGraph* (the graph runtime)
> and talks to models through the **OpenAI SDK** directly (`llm_model/`). It does
> not use LangChain's chains/agents abstractions — deliberately, because the seam
> is small and explicit. If you came here to learn "LangChain," the transferable
> idea is the graph + the typed contract, not a specific import.

### The swappable LLM seam (`llm_model/`)
`ReviewLLM` is a `Protocol` with one method (`review_file`). Real
backends inherit `ChatReviewLLM`, which owns prompt formatting, the single
JSON-mode chat call, lenient JSON parsing (small models fence their output), and
mapping replies to `Issue`s. `LocalReviewLLM` and `OpenAIReviewLLM` differ only in
which client they build. `get_review_llm()` picks one from `LLM_BACKEND`. **This
is the pattern to internalize:** program to an interface, make the swap a config
value, keep the mock in the same shape so the whole system runs offline.

### The three detectors (`src/security/`)
Deterministic, precise, free — and the reason the product is trustworthy.

- **Secrets** (`secrets_scan.py` + `rules.py`). Two rule kinds. *Fingerprint*
  rules match a provider's distinctive shape (`AKIA…`, `ghp_…`, `sk-ant-…`) and
  need no further evidence. *Contextual* rules match `secret = "…"` and then
  demand high Shannon entropy, because without that gate they fire on every
  string constant in the repo. A third layer suppresses placeholders —
  `.env.example` files, `<your-key>`, `${VAR}`, AWS's own documented sample key.
  Detection is easy; **staying quiet is the hard part**, and it is what decides
  whether anyone keeps the tool installed.
- **Dependencies** (`deps_scan.py` + `osv.py`). Parse manifests for *resolved*
  versions, batch them to OSV, fetch the details for the hits. `package.json`'s
  `^1.2.3` is deliberately *not* resolved — checking the wrong version is worse
  than reporting that a lockfile is missing.
- **Unsafe code** (`code_scan.py`). bandit and eslint-plugin-security want a
  directory, so files are materialized into a temp tree — through
  `_safe_relpath`, because the payload came from a browser and `../../etc/passwd`
  must never become a real write. Findings are mapped back to the caller's paths.

### Degrading loudly
Every detector can fail: bandit may not be installed, eslint needs Node, OSV
needs network. Each failure appends to `report.degraded` and the popup shows it.
The rule worth stealing: **a check that could not run must never be presented as
a check that passed.** Silence is the one thing a security tool may not do.

### Bounding the model (`security/triage.py`)
The model is given a closed list of findings and asked to dedupe, rank, explain
and fix. That authority is enforced in code, not requested in the prompt:
`_apply` matches replies back by id, drops ids it does not recognise, refuses to
let the model change a finding's file/line/rule, and — if the reply loses
findings without accounting for them as duplicates — **rejects the whole batch**
and falls back to the deterministic result. A hallucinating model degrades the
output to "no triage"; it can never degrade it to "wrong findings".

The deterministic path is not a stub, either: it dedupes on location (and on
vulnerability id for dependencies, since OSV returns the same CVE via GHSA and
PySec records) and ships the rule-authored explanations. With `SECURITY_TRIAGE=false`
you still get a working scanner.

### Precision by design, in the PR-review flow (proposer → verifier)
A single small model told to "review this code" flags something on every change.
The fix is two roles: the proposer (recall) casts a wide net; the verifier
(precision) answers one narrow yes/no per candidate; and `validate_fix` throws
away any suggested fix that isn't valid Python. Precision is the binding
constraint, so the architecture spends its complexity there.

### LoRA / QLoRA fine-tuning (`src/ml/`)
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
`security_script.js` adds "🛡️ Security scan" on repo pages: it walks the tree via
the GitHub API, selects the scannable files (manifests and configs first, so a
truncated monorepo still yields a dependency check), fetches their contents
through a bounded worker pool, and posts them to `/security/scan/full`.
`content_script.js` adds "Review this PR" on PR pages and fetches the public
`<pr>.diff`. `background.js` (a service worker) is the one place that calls the
backend; the popup renders the shared `Report`. Note the security posture: minimal
permissions, and the backend still can't write anything.

### Persistence, deployment, CI
- **DB:** SQLAlchemy over SQLite by default (zero setup), Postgres in Docker.
- **Docker:** `deploy/Dockerfile` + `deploy/docker-compose.yml` (build context is
  the repo root) — one image, `uvicorn backend.main:app`, Postgres in compose.
- **Deploy:** `fly.toml` (Fly.io) or `Procfile` (Railway); cloud runs the hosted
  model, local runs Ollama.
- **CI (`.github/workflows/ci.yml`):** ruff → compile → pytest (mock backend) →
  docker build → gated deploy. Everything runs from the repo root; `src/` is the
  single import root (`pyproject.toml pythonpath=["src", "."]`).

## 4. Try the whole thing

```bash
# backend (mock — zero setup); OpenAI in production (LLM_BACKEND=openai + key)
PYTHONPATH=src ./.venv/Scripts/python.exe -m uvicorn backend.main:app --port 8001
curl -X POST localhost:8001/security/scan -H "Content-Type: application/json" \
     -d '{"repo":"acme/demo","files":[{"path":"app.py","content":"TOKEN = \"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\"\nq = \"SELECT * FROM t WHERE id = \" + uid\n"}]}'

# real local model (CPU) instead of OpenAI
./deploy/setup_local_model.ps1            # pulls qwen2.5-coder:3b in Ollama
#   .env:  LLM_BACKEND=local

# web app
BACKEND_URL=http://localhost:8001 streamlit run src/apps/dashboard/app.py

# extension: load src/apps/extension/ unpacked at chrome://extensions

# fine-tune (GPU box) then serve on CPU
python src/ml/curate_dataset.py --src src --out src/ml/data
python src/ml/iterate.py --data src/ml/data --out src/ml/adapters
```

## 5. Patterns worth keeping

1. **One typed contract at the center.** `SecurityReport` decouples every component.
2. **Program to an interface; make the swap config.** The LLM seam.
3. **A check that could not run is never reported as a check that passed.**
4. **Let tools decide what is decidable**, and give the model only the
   judgement call — inside a boundary enforced in code, not in the prompt.
5. **Mechanical guarantees over trust.** `validate_fix` parses; the safety test
   proves the agent can't write; training targets are always valid JSON.
6. **Measure before you believe.** The eval harness and the plateau loop exist so
   "it got better" is a number, not a vibe.
