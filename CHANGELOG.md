# Changelog

Notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-08-11

A production-readiness pass. The theme is the same one the tool sells: a scan
that quietly covers less than you think is worse than one that refuses to run.
Most of what follows is a silent partial answer being made loud.

### Removed

- **LangGraph.** The pipeline was a `StateGraph` with eight nodes, eight
  unconditional edges, and no branching, checkpointing, concurrency or
  interrupts — a straight line, bought for ~25 transitive packages and 1.30s of
  import time per invocation (measured with `-X importtime`; the module that
  replaced it costs 0.17s) on a CLI that scans a small repository in about two
  seconds. `reposec/graph.py` is now `reposec/pipeline.py`: a tuple of eight
  functions and a `for` loop that merges their output.

  This also deletes a vulnerability class rather than suppressing it. LangGraph
  inherits langchain-core's global tracer, which switches itself on from an
  ambient `LANGSMITH_TRACING` and uploaded the verbatim scanned source,
  credentials included, to a third party; a three-file scan produced a 46 KB
  ingest. It had to be pinned off by hand at the call site for as long as the
  dependency existed. `test_pipeline_safety.py` now fails the build if anything
  in the package imports langgraph, langsmith or langchain again.

### Fixed

- **A leaked credential containing a `/` stopped being redacted.** Segment-wise
  entropy was shared by detection and by `scrub()`. `/` and `+` are in the
  base64 alphabet, so a real AWS secret key contains a slash about 40% of the
  time, and splitting on it left segments too short to clear the entropy gate —
  which meant the key was neither reported *nor masked*, and would have reached
  the report, the terminal and the model prompt. Measured on 20,000 generated
  keys, 0.2% were affected. The segment discount now applies only when every
  segment is wordlike, and redaction uses whole-string entropy: over-masking is
  free, under-masking is the credential.
- **Self-signed test certificates were reported as leaked private keys.** Five
  `high` findings across `psf/requests` and `axios` — enough to fail
  `--fail-on high` on two of the most audited repositories in open source. Key
  and certificate *files* under a test tree are now treated as fixtures, and
  test trees downgrade entropy-gated rules the way documentation already did.
  Provider fingerprints are unaffected in both cases: an `AKIA…` in a test file
  is still a live AWS key.
- **One credential could be reported as three findings.** `JWT_SECRET = "…"`
  matched both `hardcoded-crypto-key` and `generic-api-key`; `token = "ghp_…"`
  matched both `github-pat` and the generic rule. One value on one line is now
  one finding — the highest-severity match, fingerprints first, so the
  remediation names the provider to rotate at.
- **An eslint noise rule could suppress a real finding.** The JavaScript dedup
  keyed on `(file, line)` alone, so `el.innerHTML = data[key]` reported
  `detect-object-injection` and dropped the XSS sink entirely, and two pattern
  rules on one line collapsed into one. Only the single genuinely overlapping
  rule pair is deduplicated now.
- **`reposec install-eslint --dir` failed on success.** It installed correctly,
  validated through a search path that never includes `--dir`, printed an error,
  and exited 2 — while the install it had just made was fine but invisible to
  the scanner. It now verifies the real location and prints the
  `REPOSEC_ESLINT_DIR` line that makes it usable.
- **A prerelease could never be tagged.** `release.yml` compared versions as
  strings, so `v1.1.0-rc1` could not match `pyproject.toml` under PEP 440
  normalisation, and could never match the Chrome manifest, which cannot express
  a prerelease at all. Versions are compared as versions, and the extension
  tracks the release core.
- **A schema change at osv.dev reported a clean bill of health.** If `vulns`
  were renamed, every result slot parsed as "no vulnerabilities" and the scan
  reported a lockfile full of CVEs as clean — with no degraded note, so it was
  indistinguishable from a genuinely healthy repository. Every branch of the
  batch parser now raises rather than returning empty, and `results` arriving as
  an object instead of a list degrades the dependency detector instead of
  killing the scan with an `AttributeError`. A short `results` list is counted
  and reported as unchecked instead of being silently dropped.
- **Six of psycopg2's and asyncpg's own docstrings were reported as leaked
  credentials.** `postgresql+psycopg2://user:password@/dbname?host=HostA` is a
  documented libpq form with an empty host component, which the connection-string
  pattern did not match at all — so the illustrative-password check never ran.
  Fixed in the Python detector and the browser extension together.
- **The browser extension had drifted from the scanner.** The connection-string
  verdict and segment-wise entropy landed on the Python side and never reached
  `scanner.js`, so the extension still reported the SQLAlchemy-shaped false
  positives the CLI was fixed to stop reporting. Both are ported, and
  `tests/js/parity.test.mjs` now scores the extension against the same labelled
  benchmark the Python detector is scored against, rather than diffing the rule
  table — which is why the drift was invisible.
- **The Docker image never contained its own verification gate.**
  `.dockerignore` excluded `deploy/`, so `COPY deploy/verify_image.py` could not
  resolve. Found by building the image, which had not been done.
- **One eslint timeout lost every JavaScript finding in the repository.** The
  JS analyzer is now chunked like the Python one, so a timeout costs one chunk
  and says how many files were in it. A timeout is also reported as a timeout
  rather than as a generic "could not run".

### Added

- **`--max-total-bytes`** — an aggregate read budget (default 256 MB). The
  per-file cap bounded one file; the whole tree was held in memory with no
  ceiling, and the code detector builds a second copy of it. Reaching the budget
  now truncates the read and reports how many files went unscanned, which
  `--strict` turns into exit 3.
- **`src/evaluation/run_live_eval.py`** — a live-fire harness. It clones real
  repositories and reports four things: what the scanner finds on
  deliberately-vulnerable applications (against a raw `bandit` run, so the skip
  lists can be judged rather than trusted), how much it says on widely-audited
  ones, end-to-end throughput, and — the number that was missing — **recall
  against synthetic credentials planted in a real application**, so recall is
  measured on code nobody here wrote rather than on a fixture written alongside
  the rules. It found six of the defects fixed in this release on its first run.
- **Wider generic secret names.** `JWT_SIGNING_SECRET`, `WEBHOOK_SECRET`,
  `SESSION_TOKEN`, `ENCRYPTION_KEY`, `DB_PASSWORD` and similar were silently
  uncovered — names formed from what the secret protects rather than from a
  vendor. Found by planting one in real code at entropy 5.33 and watching
  nothing happen. Measured after: no change to the 0 secret false positives over
  419.6 kLOC, because the name was never the whole test — length, entropy and
  the placeholder filter still are.
- **Test coverage for the paths that only fail in production.** `osv.py` and
  `llm.py` went from 25% to 100%, including the HTTP path against recorded
  osv.dev payloads; a quality suite covering the multi-chunk analyzer path,
  induced chunk failure, and the read budget. Whole-project coverage: 82% → 88%.

### Verified rather than claimed

Each of these was previously reasoned through and never executed:

- The image builds, its build-time gate passes inside it, and `--history` works
  against a read-only bind mount as uid 10001 — the dubious-ownership failure it
  was written for degrades silently, so it had to be run to be believed.
- `requires-python = ">=3.12"` — the full suite passes on CPython 3.12.12.
- Benchmark unchanged at P 0.96 / R 1.00 / F1 0.98 over 111 labelled cases; 0
  secret false positives over 419.6 kLOC of real third-party code, and 0 over
  205.7 kLOC of SQLAlchemy specifically, where there were 6.

### Changed

- `project.urls` now points at the repository the code is actually in. The
  package and the remote disagreed about where the project lived.

## [1.0.0] — 2026-08-08

First release. The project began as an LLM code-review copilot; this version
replaces LLM-based detection with real tools, demotes the model to triage, and
ships as a CLI with a serverless browser companion.

### Added

- **Secret detection** — ~25 gitleaks-derived regex fingerprints plus Shannon
  entropy for generic assignments, with placeholder suppression (`.env.example`
  files, `${TEMPLATE}` values, AWS's documented sample key) because staying
  quiet is what decides whether the tool stays installed.
- **Dependency detection** — `requirements.txt`, `pyproject.toml`,
  `Pipfile.lock`, `package.json`, `package-lock.json` and `yarn.lock` parsed for
  resolved versions and checked against OSV. Unpinned ranges are reported as
  unresolved, never guessed.
- **Unsafe-code detection** — bandit for Python, eslint-plugin-security for
  JS/TS, plus pattern rules for the XSS sinks and insecure ciphers eslint has no
  rules for.
- **LLM triage** — deduplicates, re-ranks by exploitability, explains against
  the real code, and proposes a fix. Bounded in code: replies are matched back
  by finding id, unknown ids are dropped, and file/line/rule are immutable.
- **Git-history scanning** (`--history`) — finds credentials that were committed
  and later deleted, anchored to the commit, author and date that introduced them.
- **`.secscanignore`** — gitignore-flavoured path and rule suppression.
- **A labelled benchmark** (`src/evaluation/`) scoring precision, recall and F1
  per detector against a fixture that is half decoys, with dependencies scored
  against a frozen OSV snapshot so upstream advisories cannot look like
  regressions. Currently 1.00 across all three detectors.
- **`reposec` CLI** — `scan` and `doctor`, text/JSON/SARIF output, documented
  exit codes, and `--strict` so "a detector could not run" is distinguishable
  from "findings were found".
- **Chrome extension** (MV3) with **no backend**: secrets and dependencies are
  checked entirely in the browser, so source is never uploaded. Its rules are
  generated from `rules.py`, and CI fails if the two drift.
- **Docker image** that ships its own detectors and fails the build if they are
  missing.
- **CI self-scan** — the scanner runs on its own repository every push and
  blocks on a high-severity finding.

### Security

- Secrets are redacted by a pipeline node that runs before triage or output, so
  a credential quoted verbatim by bandit's `B105` never reaches the report, the
  terminal, or the model prompt. That node's position is asserted by a test.
- The pipeline cannot write, fetch, or shell out, enforced structurally rather
  than documented.
- Paths are validated before anything is written to disk, since the scanner
  materialises files into a temp tree for bandit and eslint.
- Upgraded `langgraph` (CVE-2026-48776, CVE-2026-28277) and `requests`
  (CVE-2024-47081) after the scanner found them in our own dependencies.
- Fixed a ReDoS in the `requirements.txt` parser, in both the Python and the
  JavaScript implementation. Found by eslint-plugin-security running under this
  scanner's own CI gate. A manifest from an arbitrary repository is
  attacker-controlled input, and that parser is the first thing to touch it.
- The benchmark corpus is stored base64-encoded so the repository contains no
  plaintext credential.

### Removed

- The PR code-review flow, the LoRA fine-tuning pipeline, the Chroma RAG index,
  and the MCP server. None were used by the scanner; keeping them meant carrying
  two products in one repository.
- The FastAPI server, the scan-history database, and the Streamlit dashboard.
  A scan loads none of that — measured, not assumed — and removing it took six
  runtime dependencies with it and let the browser extension drop its backend.

### Known limitations

- **Triage lift is unmeasured.** `--triage` reports what the LLM stage changed,
  but no model has been benchmarked yet; with none configured the run reports
  zeroes and says so.
- The benchmark fixture was written alongside the scanner, so a perfect score
  means "no regression", not "solved". Real-world precision needs real
  repositories.
- Without Node, JS/TS detection falls back to narrower regex checks — reported
  in every scan's `degraded` list.
