# Codebase guide — read this in order

A guided tour of the Repo Security Scanner, meant to be read top to bottom with
the files open beside it. It explains **what each part does, why it exists, and
the pattern worth stealing** — so you finish understanding not just this repo
but the ideas behind it.

## 1. The 60-second picture

```
Chrome extension ─┐
CLI              ─┼─▶ FastAPI backend (:8001)
Dashboard        ─┘      ├─ scan graph:  files → secrets → deps(OSV)
                         │                     → code(bandit, eslint)
                         │                     → suppress → redact
                         │                     → triage(LLM) → aggregate
                         ├─ LLM seam (llm_model/): local | OpenAI | none
                         └─ SQLite/Postgres: scan history
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
   `SecurityReport`, and detector provenance stays separate from LLM opinion.
3. **A swappable LLM seam** (`llm_model/`): the implementation changes
   (none ↔ local ↔ hosted) but the interface never does — and "none" is a
   first-class option, not a degraded mode.

## 2. Reading order

| # | File | What it is | Take away |
|---|------|-----------|-----------|
| 1 | `src/schemas.py` | `SecurityFinding` / `SecurityReport` | One shared contract; detector facts kept apart from model opinion |
| 2 | `src/config.py` | pydantic-settings; all env in one `settings` | Nothing is required — a model only affects triage |
| 3 | `src/security/rules.py` | gitleaks-derived secret rules | Fingerprint rules need no entropy gate; generic ones are useless without it |
| 4 | `src/security/secrets_scan.py` | detector 1 + `scrub()` | Placeholder suppression is why the scanner stays usable; `scrub` is the redaction every path out uses |
| 5 | `src/security/deps_scan.py` | detector 2: manifests → OSV | Lockfiles beat manifests: an unresolved range is reported, never guessed |
| 6 | `src/security/code_scan.py` | detector 3: bandit + eslint | A missing analyzer degrades loudly; it never reads as a clean result |
| 7 | `src/security/history.py` | git-history secret scanning | The case scanning exists for: a credential deleted later is still in the repo |
| 8 | `src/security/suppress.py` | `.secscanignore` | Without an escape hatch, the first noisy scan gets the tool muted |
| 9 | `src/llm_model/prompts.py` | the triage prompts | The prompt says the finding list is closed — and `_apply` enforces it |
| 10 | `src/llm_model/base.py` | `ChatLLM`, `NoLLM`, `get_llm()` | **The seam.** `NoLLM` is a real answer, not a stub that fabricates output |
| 11 | `src/security/triage.py` | the LLM stage | `_apply` is the trust boundary: unknown ids dropped, skipped ids kept untriaged |
| 12 | `src/agent/security_graph.py` | the LangGraph agent | Detection nodes call no model at all; `redact_findings` runs before triage sees anything |
| 13 | `src/backend/service.py` | orchestration + persistence + guards | The only place that touches both the agent and the DB |
| 14 | `src/backend/main.py` | routes, CORS, error handlers | Thin HTTP layer; every route is read-only w.r.t. the caller's repo |
| 15 | `src/security/cli.py` | the command-line scanner | Where history scanning lives, and the CI gate |
| 16 | `tests/` | unit + contract + safety | `test_agent_safety.py` proves the agent can't write *or* fetch |
| 17 | `src/apps/extension/` | MV3 Chrome extension | Collects the files itself; the server never fetches |
| 18 | `src/apps/dashboard/app.py` | the Streamlit web app | Reads the same `SecurityReport` |
| 19 | `src/evaluation/` | the labelled benchmark | Half decoys, because precision is the binding constraint |

## 3. The tech stack, and how we actually use it

### LangGraph (agent orchestration)
`agent/security_graph.py` builds a `StateGraph` over a `TypedDict` state. Each
node is a plain function taking and returning a slice of state; edges wire them
into a fixed line. We use LangGraph for **structure and a safety boundary**, not
for a swarm of autonomous agents — the graph can only ever return a report, and
tests enforce that no node can write or fetch.

Note what the node *order* buys: the detection nodes are independent and could
run in any order, but `redact_findings` must sit between them and
`triage_findings`. It is the graph that makes "no raw credential reaches the
model" a structural property rather than a rule each detector has to remember —
and `test_agent_safety.py` asserts those two edges directly.

> **LangChain vs LangGraph:** this project uses *LangGraph* (the graph runtime)
> and talks to models through the **OpenAI SDK** directly (`llm_model/`). It does
> not use LangChain's chains/agents abstractions — deliberately, because the seam
> is small and explicit.

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
  versions, batch them to OSV, fetch the details for the hits concurrently.
  `package.json`'s `^1.2.3` is deliberately *not* resolved — checking the wrong
  version is worse than reporting that a lockfile is missing.
- **Unsafe code** (`code_scan.py`). bandit and eslint-plugin-security want a
  directory, so files are materialized into a temp tree — through
  `_safe_relpath`, because the payload came from a browser and `../../etc/passwd`
  must never become a real write. Findings map back to the caller's paths.

### Degrading loudly
Every detector can fail: bandit may not be installed, eslint needs Node, OSV
needs network. Each failure appends to `report.degraded` and every UI shows it.
The rule worth stealing: **a check that could not run must never be presented as
a check that passed.** Silence is the one thing a security tool may not do.

### Bounding the model (`security/triage.py`)
The model is given a closed list of findings and asked to dedupe, rank, explain
and fix. That authority is enforced in code, not requested in the prompt.
`_apply` matches replies back by id, drops ids it does not recognise, and
refuses to let the model change a finding's file/line/rule.

Crucially the boundary is enforced **per finding, not per batch**. An id the
model simply skipped is kept untriaged rather than dropped — a 3B model handed a
dozen findings routinely returns eleven, and an all-or-nothing contract would
throw away good triage for the other ten every single time. Losing a finding is
unacceptable; losing an annotation is not, and `triaged=False` records which
happened.

The deterministic path is not a stub either: it dedupes on location (and on
vulnerability id for dependencies, since OSV returns the same CVE via GHSA and
PySec records) and ships the rule-authored explanations. With no model at all
you still get a working scanner.

### Measuring it (`src/evaluation/`)
Half the fixture is decoys, and that half is the point. Precision is the binding
constraint, so the benchmark is built to catch over-reporting rather than to
flatter recall. Dependencies score against a frozen OSV snapshot, because
otherwise a new advisory upstream is indistinguishable from a regression here.

### Persistence, deployment, CI
- **DB:** SQLAlchemy over SQLite by default (zero setup), Postgres in Docker.
- **Docker:** `deploy/Dockerfile` builds in two stages — a Node stage installs
  eslint-plugin-security, then the Python image copies in both the plugin and
  the Node runtime. Without that the deployed scanner would report its JS/TS
  detector as degraded on every scan. The build *asserts* the detectors are
  present rather than shipping an image that silently degrades.
- **CI (`.github/workflows/ci.yml`):** ruff → compile → pytest → **self-scan**
  → docker build → gated deploy. The self-scan runs this scanner on this
  repository with `--fail-on high`, so a leaked credential or a newly published
  CVE in our own dependencies breaks the build. It needs `fetch-depth: 0`,
  because a depth-1 clone has no history to scan.

The dogfooding is not decorative: it caught three high-severity CVEs in this
project's own dependencies, which is why the pins moved.

## 4. Try the whole thing

```bash
PYTHONPATH=src ./.venv/Scripts/python.exe -m uvicorn backend.main:app --port 8001
curl -X POST localhost:8001/security/scan -H "Content-Type: application/json" \
     -d '{"repo":"acme/demo","files":[{"path":"app.py","content":"TOKEN = \"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\"\nq = \"SELECT * FROM t WHERE id = \" + uid\n"}]}'

# the CLI, including git history
PYTHONPATH=src python -m security.cli . --history

# a real local model for triage (optional)
./deploy/setup_local_model.ps1            # pulls qwen2.5-coder:3b in Ollama
#   .env:  LLM_BACKEND=local

# web app
BACKEND_URL=http://localhost:8001 streamlit run src/apps/dashboard/app.py

# extension: load src/apps/extension/ unpacked at chrome://extensions

# the benchmark
python src/evaluation/run_security_eval.py
```

## 5. Patterns worth keeping

1. **One typed contract at the center.** `SecurityReport` decouples every component.
2. **Program to an interface; make the swap config.** The LLM seam — where
   "no model" is a first-class implementation, not an error path.
3. **A check that could not run is never reported as a check that passed.**
4. **Let tools decide what is decidable**, and give the model only the judgement
   call — inside a boundary enforced in code, not in the prompt.
5. **Mechanical guarantees over trust.** Redaction is a graph node whose position
   is asserted by a test; path traversal is rejected before anything is written.
6. **Measure before you believe.** The benchmark exists so "it got better" is a
   number — and building it immediately found three noisy bandit rules.
7. **Dogfood in CI.** The scanner scans itself on every push and blocks on a high
   finding. That is what caught three real CVEs in its own dependencies.
