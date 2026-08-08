# Repo Security Scanner

A Chrome extension, a CLI, and a **LangGraph** backend that scan a GitHub
repository for three concrete classes of security problem — and use an LLM for
judgement, not for detection.

**Detection is done by tools, deterministically:**

| Category | How it is found |
|---|---|
| **Exposed secrets** | ~25 gitleaks-derived regex fingerprints (AWS keys, private keys, GitHub/Stripe/Slack/OpenAI tokens, DB URLs with passwords) plus Shannon-entropy checks for generic `secret = "..."` assignments — in the working tree **and in git history** |
| **Vulnerable dependencies** | `requirements.txt` / `pyproject.toml` / `Pipfile.lock` / `package.json` / `package-lock.json` / `yarn.lock` parsed for resolved versions, checked against the **OSV** database (GHSA + PySec + CVE) |
| **Unsafe code patterns** | **bandit** on Python (unsafe `eval`, SQL string concatenation, hardcoded credentials, `pickle`/`yaml.load` deserialization, weak hashes) and **eslint-plugin-security** on JS/TS, plus pattern rules for the XSS sinks and insecure ciphers eslint has no rules for |

**The LLM's job is what tools are bad at:** deduplicating overlapping findings,
re-ranking them by real-world exploitability against the surrounding code,
explaining in plain language what an attacker actually gets, and proposing a
concrete fix.

It cannot create a finding, move one, or change which rule fired. Replies are
matched back to detector output by id and anything unrecognised is discarded —
enforced in code, not requested in the prompt. **No model is required:** run it
with none and detection is unchanged; you get the rule-authored explanations
instead of model-written ones.

> **New here?** Read [`docs/GUIDE.md`](docs/GUIDE.md) — a guided, in-order tour
> of the codebase and the ideas behind it.

## Layout

```
src/            all Python service code — the import root
  security/       the three detectors + LLM triage
    rules.py        gitleaks-derived secret rules (regex + entropy floors)
    secrets_scan.py detector 1 — secrets, and the redaction used everywhere
    deps_scan.py    detector 2 — manifest parsing + OSV lookup
    osv.py            the OSV API client
    code_scan.py    detector 3 — bandit + eslint-plugin-security
    eslint/           isolated eslint install + its flat config
    history.py      git-history secret scanning
    suppress.py     .secscanignore rules
    triage.py       the LLM stage: dedupe, rank, explain, fix
    cli.py          the command-line scanner
  agent/          the LangGraph scan agent
  backend/        FastAPI: routes, orchestration, error contract
  llm_model/      the LLM seam: local, OpenAI, or none
  database/       SQLAlchemy model and session wiring
  evaluation/     the labelled benchmark and its runner
  config.py       every setting, read from the environment
  schemas.py      the shared data contract — SecurityFinding, SecurityReport
  apps/
    extension/      Chrome extension (MV3)
    dashboard/      Streamlit web app
deploy/         Dockerfile, docker-compose.yml, locustfile.py, setup helpers
tests/          the whole test suite
docs/           the codebase guide
```

`src/` is the single import root (`pyproject.toml` sets `pythonpath`), so code
does `from security.triage import ...`, `from schemas import SecurityReport`.
Run everything from the repo root.

## Architecture

```
Chrome ext / CLI / Dashboard ─▶ FastAPI (:8001)
                                 └─ LangGraph agent (read-only):
                                      files → secrets → deps(OSV)
                                            → code(bandit, eslint)
                                            → suppress → redact
                                            → triage(LLM) → aggregate
                                 └─ Postgres/SQLite: scan history
```

The caller collects the repo's files and posts them; **the backend never fetches
from a repository the caller did not send**, and has no route that can post,
push, or modify anything. `tests/test_agent_safety.py` enforces both
structurally.

**Secrets never leave the scanner in the clear.** The secret detector redacts
its own evidence, and a `redact_findings` graph node scrubs every other
detector's output too — bandit's `B105` finding quotes the offending source line
verbatim, so without it a token would reach the database, the browser, and the
triage prompt. The model is asked to rank a leaked credential without being
shown it. The node order is itself asserted by a test.

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

PYTHONPATH=src .venv/Scripts/python.exe -m uvicorn backend.main:app --port 8001
```

Then load `src/apps/extension/` at `chrome://extensions` (Developer mode → *Load
unpacked*), open any GitHub repository, and click **🛡️ Security scan**.

No keys needed. Secrets and unsafe-code detection are fully offline; the
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
as a clean result. The Docker image installs it for you.

## Command line

```bash
PYTHONPATH=src python -m security.cli .                 # working tree
PYTHONPATH=src python -m security.cli . --history       # + git history
PYTHONPATH=src python -m security.cli . --format json   # machine-readable
PYTHONPATH=src python -m security.cli . --fail-on high  # exit 1 for CI
```

**Why `--history` matters:** a credential committed and later deleted is still
in the repository. Anyone who clones it can read it, and unless it was rotated
it is still live — which is exactly the situation secret scanning exists for. A
working-tree scan cannot see any of them.

Findings name the commit, author and date that introduced the secret, because
"live for two years" and "added yesterday" call for different responses. One
credential committed, reverted, and re-added is reported once, anchored to the
earliest commit — that is how long it has been exposed. History findings carry
no line number: a line in an old diff maps to nothing in the checked-out file.

### Suppressing known findings

Real repositories contain credential-shaped strings that exist on purpose —
documented example tokens, test fixtures, deliberately vulnerable sample code. A
`.secscanignore` at the repo root drops them, gitignore-style:

```
docs/**                   # every finding under docs/
tests/**:github-pat       # one rule, only under tests/
:B101                     # one rule, anywhere
```

Suppressed findings are dropped rather than flagged — a report you have to
mentally filter is the thing this exists to prevent — but the count is reported
in `report.suppressed`, so a file that silences everything is visible. This repo
ships one: the secret detector's own test fixtures would otherwise dominate its
self-scan.

### Choosing a model for triage

`LLM_BACKEND` selects one (`openai` | `local` | `mock` | `auto`).

| Mode | Set this |
|---|---|
| No model (default) | nothing — detection runs, triage is skipped |
| Local, fully offline | `LLM_BACKEND=local`, `LOCAL_LLM_BASE_URL=http://localhost:11434/v1`, `LOCAL_LLM_MODEL=qwen2.5-coder:3b` |
| Hosted | `LLM_BACKEND=openai`, `OPENAI_API_KEY=sk-...`, `OPENAI_MODEL=...` |

Other knobs: `SECURITY_TRIAGE` (turn the LLM stage off), `SECURITY_OFFLINE`
(skip the OSV lookup for air-gapped runs), `MAX_SCAN_FILES` / `MAX_SCAN_BYTES`
(payload caps). `GET /health` reports the backend actually in use.

### Routes

| Method | Path | Purpose |
|---|---|---|
| POST | `/security/scan` | Scan `{"repo": ..., "ref": ..., "files": [{path, content}]}`. Returns the report. |
| POST | `/security/scan/full` | Same, but returns the stored record (`id` + report). |
| GET | `/security/scans` | List past scans. |
| GET | `/security/scans/{id}` | Full stored report. |
| GET | `/health` | Liveness + the backend triage would use. |

## Tests and lint (same as CI)

```bash
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m ruff check .
```

## Web app (Streamlit)

```bash
BACKEND_URL=http://localhost:8001 streamlit run src/apps/dashboard/app.py
```

Tab 1: browse scans, filter findings by category and severity. Tab 2: the
benchmark numbers.

## Chrome extension (MV3)

Load `src/apps/extension/` via `chrome://extensions` → Developer mode → *Load
unpacked*. On any repository page, **"🛡️ Security scan"** walks the repository
tree, fetches the scannable files (source, manifests, CI and infra configs — not
`node_modules`, binaries, or minified bundles), and posts them to
`/security/scan/full`. Findings are grouped by category with the redacted
evidence, the plain-language reason, and the fix; each links to the exact line
on GitHub.

Selection is capped (600 files / 12 MB) and prioritised so manifests and config
files are sent first — if a monorepo is truncated, the dependency detector still
gets its inputs and the popup says the scan was partial.

Set the backend URL and an optional GitHub token (raises the API rate limit,
needed for any sizeable repo) in the popup. A non-localhost backend must be
`https://` and triggers a one-time permission prompt for that host.

## Benchmark

```bash
python src/evaluation/run_security_eval.py            # detectors only
python src/evaluation/run_security_eval.py --triage   # + the LLM stage
```

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| Secrets | 1.00 | 1.00 | 1.00 |
| Dependencies | 1.00 | 1.00 | 1.00 |
| Code | 1.00 | 1.00 | 1.00 |
| **Overall** | **1.00** | **1.00** | **1.00** |

**Precision is the number that matters.** Half the fixture is decoys — AWS's own
documented sample key, `${TEMPLATE}` values, parameter-bound SQL that looks like
concatenation, `yaml.safe_load`, `execFile` with an argument array, the word
`eval` inside a string literal, an `.env.example`, a vendored `node_modules`
tree. A scanner that fires on everything scores perfect recall and is worthless,
so recall alone proves nothing.

Dependencies are scored against a frozen OSV snapshot
(`security_benchmark/snapshot_osv.py` regenerates it), because scoring against
live OSV means a new advisory upstream is indistinguishable from a regression here.

**What this does and does not prove.** The fixture was written alongside the
scanner, so a perfect score means "no regression", not "solved" — real-world
precision is a question only real repositories can answer. It has already earned
its keep: building it surfaced three bandit rules (`B101`, `B603`, `B607`) that
fire on ubiquitous *correct* code, and dropping them is why the code detector
reaches 1.00. `tests/test_security_benchmark.py` enforces the floors in CI.

### Triage lift is not yet measured

`--triage` reports what the LLM stage changed — findings merged beyond the
deterministic pass, severities moved, precision@5 before and after, token cost.
**Those numbers do not exist yet**, because no model has been configured here;
with no backend the run honestly reports zeroes and says so.

To get the real number:

```bash
./deploy/setup_local_model.ps1        # or: export OPENAI_API_KEY=...
LLM_BACKEND=local python src/evaluation/run_security_eval.py --triage
```

The triage path itself *is* tested, against a scripted stand-in that reproduces
how small models actually fail — skipped ids, shouty `"HIGH"` severities,
invented ids, reciprocal duplicate claims, outright errors. See
`tests/test_triage.py`.

## Docker & load test

```bash
docker compose -f deploy/docker-compose.yml up --build   # API + Postgres
locust -f deploy/locustfile.py --host http://localhost:8001
```

## Deploy

**Fly.io** (config is in `fly.toml`, pointing at `deploy/Dockerfile`):

```bash
fly launch --no-deploy            # create the app
fly postgres create && fly postgres attach <db>   # injects DATABASE_URL
fly secrets set OPENAI_API_KEY=...  # optional: enables triage
fly deploy
```

**Railway/Heroku:** the root `Procfile` runs `uvicorn` with `PYTHONPATH=src`.
Add a Postgres addon for `DATABASE_URL`. Note that these buildpacks give you
Python only — without Node the JS/TS detector falls back to its pattern rules
and says so on every scan. Use the Docker image if you want eslint in production.

**The image ships its own detectors.** A Node stage installs
eslint-plugin-security from `package.json`, `bandit` comes from
`requirements.txt`, and the build fails rather than producing an image whose
detectors are missing. `git` is included so `docker run ... -m security.cli
/repo --history` works against a mounted clone.

**Dashboard:** deploy `src/apps/dashboard/app.py` to Streamlit Community Cloud
and set `BACKEND_URL`. Add its origin to `ALLOWED_ORIGINS` on the API; the
extension does not need to be listed, because its service worker holds an
explicit host permission and is not a CORS caller.

### Sizing

A scan holds every submitted file in memory and forks bandit and eslint over a
temp copy of the tree, so `fly.toml` asks for 1 GB — the 256 MB default is not
enough for a large repository. Throughput is fine on a shared CPU: 330 files
takes about 3 seconds, because each analyzer runs once over the whole tree
rather than per file. The slowest part of a scan is usually OSV, which needs one
request per vulnerability; those are fetched concurrently.

### CI

`.github/workflows/ci.yml` runs lint → compile → tests, then **scans this
repository with its own scanner** (`--history --fail-on high`) and builds and
verifies the Docker image. Deployment is gated on both. The self-scan needs
`fetch-depth: 0`, since a depth-1 clone has no history to scan.

You can gate your own repositories the same way:

```yaml
- run: python -m security.cli . --history --fail-on high
  env:
    PYTHONPATH: src
```

## License

MIT — see [`LICENSE`](LICENSE).
