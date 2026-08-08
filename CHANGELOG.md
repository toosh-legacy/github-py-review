# Changelog

Notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
