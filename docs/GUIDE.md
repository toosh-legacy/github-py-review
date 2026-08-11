# Codebase guide — read this in order

A guided tour of reposec, meant to be read top to bottom with the files open
beside it. It explains **what each part does, why it exists, and the pattern
worth stealing** — so you finish understanding not just this repo but the ideas
behind it.

## 1. The 60-second picture

```
reposec scan  ─▶  collect → secrets → deps(OSV) → code(bandit, eslint)
                          → suppress → redact → triage(LLM) → aggregate
                                                            ─▶ SecurityReport
```

One command, one pipeline, no server. A browser extension re-implements the
first two detectors client-side for repositories you have not cloned.

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
3. **A swappable LLM seam** (`llm.py`): the implementation changes
   (none ↔ local ↔ hosted) but the interface never does — and "none" is a
   first-class option, not a degraded mode.

## 2. Reading order

| # | File | What it is | Take away |
|---|------|-----------|-----------|
| 1 | `reposec/schemas.py` | `SecurityFinding` / `SecurityReport` | One shared contract; detector facts kept apart from model opinion |
| 2 | `reposec/config.py` | pydantic-settings; all env in one `settings` | Nothing is required — a model only affects triage; the scanned directory is never read for config |
| 3 | `reposec/detectors/rules.py` | gitleaks-derived secret rules | Fingerprint rules need no entropy gate; generic ones are useless without it |
| 4 | `reposec/detectors/secrets.py` | detector 1 + `scrub()` | Placeholder suppression is why the scanner stays usable; `scrub` is the redaction every path out uses |
| 5 | `reposec/detectors/deps.py` | detector 2: manifests → OSV | Lockfiles beat manifests: an unresolved range is reported, never guessed |
| 6 | `reposec/detectors/code.py` | detector 3: bandit + eslint | A missing analyzer degrades loudly; it never reads as a clean result |
| 7 | `reposec/detectors/history.py` | git-history secret scanning | The case scanning exists for: a credential deleted later is still in the repo |
| 8 | `reposec/detectors/suppress.py` | `.secscanignore` | Without an escape hatch, the first noisy scan gets the tool muted |
| 9 | `reposec/prompts.py` | the triage prompts | The prompt says the finding list is closed — and `_apply` enforces it |
| 10 | `reposec/llm.py` | `ChatLLM`, `NoLLM`, `get_llm()` | **The seam.** `NoLLM` is a real answer, not a stub that fabricates output |
| 11 | `reposec/triage.py` | the LLM stage | `_apply` is the trust boundary: unknown ids dropped, skipped ids kept untriaged |
| 12 | `reposec/pipeline.py` | the eight-stage scan pipeline | Detection stages call no model at all; `redact_findings` runs before triage sees anything |
| 13 | `reposec/cli.py` | the command | Exit codes are the CI contract; `doctor` answers "what can actually run here" |
| 14 | `tests/` | unit + contract + safety | `test_pipeline_safety.py` proves the pipeline can't write, fetch, or shell out |
| 15 | `src/apps/extension/scanner.js` | the browser detector | Two detectors, no backend; rules generated from `rules.py` |
| 16 | `src/evaluation/` | the labelled benchmark | Half decoys, because precision is the binding constraint |

## 3. The tech stack, and how we actually use it

### The pipeline (`reposec/pipeline.py`)
Eight stages in a tuple. Each is a plain function taking the accumulated state
— a `TypedDict` — and returning only the keys it changed; the runner merges them
in order. The whole orchestration layer is a four-line `for` loop.

Note what the stage *order* buys: the detection stages are independent and could
run in any order, but `redact_findings` must sit between them and
`triage_findings`. That ordering is what makes "no raw credential reaches the
model" a structural property rather than a rule each detector has to remember —
and `test_pipeline_safety.py` asserts it directly, along with the property that
nothing here can write, fetch, or shell out.

> **Why there is no framework here.** This was a LangGraph `StateGraph` until
> 2026-08-11, and the graph had exactly the shape above: eight nodes, eight
> unconditional edges, no branching, no checkpointing, no concurrency, no
> interrupts. It bought a straight line for ~25 transitive packages and 1.30s of
> import time per invocation (measured with `-X importtime`, against 0.17s for
> the module that replaced it) — on a CLI that scans a small repository in about
> two seconds. It also carried a leak: langgraph inherits langchain-core's global
> tracer, which switches itself on from an ambient `LANGSMITH_TRACING` and
> uploaded the verbatim scanned source, credentials included, to a third party.
> That had to be suppressed by hand for as long as the dependency existed.
>
> Reach for an orchestration framework when you need what it does — conditional
> edges, resumable state, fan-out. Paying for it to run a list is how a security
> tool ends up with a supply chain it cannot vouch for. Models are reached
> through the **OpenAI SDK** directly (`llm.py`), for the same reason.

### The three detectors (`reposec/detectors/`)
Deterministic, precise, free — and the reason the product is trustworthy.

- **Secrets** (`secrets.py` + `rules.py`). Two rule kinds. *Fingerprint* rules
  match a provider's distinctive shape (`AKIA…`, `ghp_…`, `sk-ant-…`) and need
  no further evidence. *Contextual* rules match `secret = "…"` and then demand
  high Shannon entropy, because without that gate they fire on every string
  constant in the repo. A third layer suppresses placeholders — `.env.example`
  files, `<your-key>`, `${VAR}`, AWS's own documented sample key. Detection is
  easy; **staying quiet is the hard part**, and it is what decides whether
  anyone keeps the tool installed.
- **Dependencies** (`deps.py` + `osv.py`). Parse manifests for *resolved*
  versions, batch them to OSV, fetch the details for the hits concurrently.
  `package.json`'s `^1.2.3` is deliberately *not* resolved — checking the wrong
  version is worse than reporting that a lockfile is missing.
- **Unsafe code** (`code.py`). bandit and eslint-plugin-security want a
  directory, so files are materialized into a temp tree — through
  `_safe_relpath`, because paths can come from a browser payload and
  `../../etc/passwd` must never become a real write.

### Degrading loudly
Every detector can fail: bandit may not be installed, eslint needs Node, OSV
needs network. Each failure appends to `report.degraded`, every output surface
shows it, `reposec doctor` reports it up front, and `--strict` turns it into a
non-zero exit. The rule worth stealing: **a check that could not run must never
be presented as a check that passed.** Silence is the one thing a security tool
may not do.

### Bounding the model (`reposec/triage.py`)
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
PySec records) and ships the rule-authored explanations. With no model at all you
still get a working scanner.

### Two implementations, one rule set
The browser extension re-implements the secret and dependency detectors in
JavaScript, because a browser cannot fork bandit or eslint but *can* run regex,
entropy, and a fetch to OSV. That buys a scan with no backend at all — your
source is never uploaded.

The risk is drift: two hand-maintained copies of a rule set diverge, and a
diverged scanner misses things exactly where nobody is looking. So the JS rules
are **generated** from `rules.py` (`deploy/generate_js_rules.py`, which also
compiles every pattern in Node so an untranslatable rule fails at generation),
CI fails if the generated file is stale, and `tests/js/parity.test.mjs` scores
the JS detector against the same labelled benchmark the Python one uses.

### Measuring it (`src/evaluation/`)
Half the fixture is decoys, and that half is the point. Precision is the binding
constraint, so the benchmark is built to catch over-reporting rather than to
flatter recall. Dependencies score against a frozen OSV snapshot, because
otherwise a new advisory upstream is indistinguishable from a regression here.

The fixture is stored base64-encoded and decoded in memory. It is a repository
full of planted credentials — which every scanner in the world flags, including
GitHub's push protection and this one — so keeping it encoded means the repo
contains no plaintext credential while the detector still sees the exact bytes.

Three harnesses, answering three different questions:

| Run | Question |
|---|---|
| `python src/evaluation/run_security_eval.py` | does it catch the planted bug, and stay off the decoy? |
| `python src/evaluation/run_fp_eval.py` | how noisy is it on code nobody wrote for it? |
| `python src/evaluation/run_perf_bench.py` | how fast is it, and which stage owns the time? |

The labelled benchmark is 111 cases (47 planted, 51 decoys, 3 severity-ceiling
cases, 4 decoy files, 6 dependency packages) and scores P 0.96 / R 1.00 / F 0.98
overall. It is deliberately not 1.00: two code decoys fire from
eslint-plugin-security's own conservatism, and they are recorded in the results
as known failures rather than suppressed, because suppressing them means
suppressing the upstream rule everywhere.

That benchmark cannot answer the second question, because it was written
alongside the rules it scores — a rule tuned to the fixture looks perfect on the
fixture. `run_fp_eval.py` scores the detectors against the third-party packages
installed in the current interpreter instead: real, published, reviewed code, no
network and no vendored corpus. Currently **0 secret false positives over 424
kLOC** and 0.23 code findings per kLOC, down from 0.50. Any secret hit counts
against us, because a published package does not contain a live credential.

`run_perf_bench.py` separates tree-walk throughput, a per-stage breakdown of one
scan, and a linear-scaling check: ~3,000 files/s walking, ~70 kLOC/s on the pure
Python path, growth factor 1.02 across 250→4,000 files. The number that decides
where optimisation is worth anything: the analyzers are ~97% of a scan's wall
time, so the interesting costs are all subprocess costs.

Both are held in place by `tests/quality/`, a pytest suite marked `quality` that
asserts budgets rather than printing numbers. It shells out to bandit and eslint
over hundreds of kLOC, so it is slow and split out — `pytest -m quality` runs
it, `pytest -m "not quality"` is the fast suite everyone runs before pushing.

### Packaging and CI
- **Install:** `pip install repo-security-scanner` gives a `reposec` console
  script. Everything lives under one `reposec` package; installing top-level
  `config` or `schemas` modules into site-packages would be a namespace
  land-grab that collides with other distributions.
- **Docker:** `deploy/Dockerfile` builds in two stages — a Node stage installs
  eslint-plugin-security, then the Python image copies in both the plugin and
  the Node runtime. The build then *scans a fixture repository with `--strict`*,
  so an image whose bandit, eslint, OSV or git path cannot run fails to build.
  `reposec doctor` cannot be that gate: it always exits 0 by design. It runs the
  scanner, not a server.
- **CI:** ruff → pytest (3.12 and 3.13) → quality budgets → JS parity →
  generated-rules freshness → **self-scan** → docker build and image smoke test.
  The self-scan runs this scanner on this repository with `--fail-on high` and
  uploads SARIF. It needs `fetch-depth: 0`, because a depth-1 clone has no
  history to scan. The image smoke test scans a bind-mounted fixture repository
  with `--history --strict`, because the container runs as an unprivileged uid
  the mounted files do not belong to and git refuses to read a repository it
  thinks belongs to someone else — a refusal that degrades `--history` to
  silence unless something makes it loud.

The dogfooding is not decorative: it caught three high-severity CVEs in this
project's own dependencies, and a ReDoS in its own `requirements.txt` parser.

## 4. Try the whole thing

```bash
pip install -r requirements-dev.txt && pip install -e .
cd src/reposec/detectors/eslint && npm install && cd -

reposec doctor                     # which detectors can run here, and why not
reposec scan .                     # the working tree
reposec scan . --history           # + git history
reposec scan . --format sarif      # for GitHub code scanning

# a real local model for triage (optional)
./deploy/setup_local_model.ps1     # pulls qwen2.5-coder:3b in Ollama
export LLM_BACKEND=local

# the extension: load src/apps/extension/ unpacked at chrome://extensions

# the three harnesses
python src/evaluation/run_security_eval.py   # labelled benchmark
python src/evaluation/run_fp_eval.py         # noise on real third-party code
python src/evaluation/run_perf_bench.py      # throughput and stage breakdown

# the test suites
pytest -m "not quality" && node --test tests/js/parity.test.mjs
pytest -m quality                            # the budgets, slow
```

Settings can live in a file instead of the environment, but the file is opt-in
and named explicitly:

```bash
cp .env.example ~/.config/reposec/env
export REPOSEC_ENV_FILE=~/.config/reposec/env
```

It is deliberately not a `.env` in the working directory. The working directory
during a scan is a repository you may not trust, and a config file read out of
it would let the thing being scanned choose the backend its own scan runs
against.

## 5. Patterns worth keeping

1. **One typed contract at the center.** `SecurityReport` decouples every component.
2. **Program to an interface; make the swap config.** The LLM seam — where
   "no model" is a first-class implementation, not an error path.
3. **A check that could not run is never reported as a check that passed.**
4. **Let tools decide what is decidable**, and give the model only the judgement
   call — inside a boundary enforced in code, not in the prompt.
5. **Mechanical guarantees over trust.** Redaction is a graph node whose position
   is asserted by a test; path traversal is rejected before anything is written;
   the second implementation is generated, not transcribed.
6. **Measure before you believe.** The benchmark exists so "it got better" is a
   number — and building it immediately found three noisy bandit rules.
7. **Dogfood in CI.** The scanner scans itself on every push and blocks on a high
   finding. That is what caught three real CVEs and a ReDoS in its own code.
