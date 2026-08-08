# reposec

Find exposed secrets, vulnerable dependencies, and unsafe code patterns in a
repository — with **tools doing the detection** and an LLM, optionally, doing
the judging.

```bash
pip install repo-security-scanner
reposec scan .
```

## Why this shape

Most "AI security scanner" tools ask a model to find vulnerabilities. That gets
you hallucinated findings and silent misses, with no way to tell which is which.

Whether a string is an AWS key, whether `flask==0.12.2` has a CVE, whether a
line concatenates user input into SQL — these are *decidable*. So a rule decides
them, the same way every time, and you can argue with the rule.

The model does the part rules genuinely cannot: collapsing duplicates, judging
how exploitable something is *in this codebase*, explaining the risk in plain
language, and writing the fix. **It cannot create a finding, move one, or change
which rule fired** — replies are matched back to detector output by id and
anything unrecognised is discarded, enforced in code rather than asked for in a
prompt.

**No model is required.** Run it with none and detection is identical; you get
the rule-authored explanations instead of model-written ones.

| Detector | How it works |
|---|---|
| **Secrets** | ~25 gitleaks-derived regex fingerprints (AWS, private keys, GitHub/Stripe/Slack/OpenAI tokens, DB URLs with passwords) plus Shannon entropy for generic `secret = "..."` assignments — in the working tree **and in git history** |
| **Dependencies** | `requirements.txt` / `pyproject.toml` / `Pipfile.lock` / `package.json` / `package-lock.json` / `yarn.lock` parsed for resolved versions, checked against **OSV** (GHSA + PySec + CVE) |
| **Unsafe code** | **bandit** for Python and **eslint-plugin-security** for JS/TS, plus pattern rules for the XSS sinks and insecure ciphers eslint has no rules for |

## Install

```bash
pip install repo-security-scanner          # detection only
pip install "repo-security-scanner[llm]"   # + LLM triage
```

Python covers itself out of the box. The JS/TS detector needs Node:

```bash
cd "$(python -c 'import reposec.detectors as d, pathlib; print(pathlib.Path(d.__file__).parent / "eslint")')"
npm install
```

Not sure what's active? Ask:

```console
$ reposec doctor

  [ok  ] secrets                built in — regex fingerprints + entropy
  [ok  ] dependencies           OSV over HTTPS (package names only)
  [ok  ] code (python)          bandit
  [MISS] code (js/ts)           not installed — run `npm install` in .../eslint
  [MISS] triage (llm)           no model configured — triage skipped
```

A scanner that quietly covers half of what you think it does is worse than one
that refuses to start, so every scan also lists what it could not run.

## Use

```bash
reposec scan .                     # working tree
reposec scan . --history           # + git history
reposec scan . --fail-on high      # exit 1 for CI
reposec scan . --format sarif      # GitHub Security tab
reposec scan . --format json       # anything else
```

**Exit codes** are the CI contract and are stable:

| Code | Meaning |
|---|---|
| `0` | clean, or nothing at or above `--fail-on` |
| `1` | findings at or above `--fail-on` |
| `2` | usage error |
| `3` | a detector could not run, and `--strict` was given |

`--strict` exists because "a detector could not run" and "findings were found"
are different failures. Gate on both if a partial scan should block your build.

### Why `--history` matters

A credential committed and later deleted is still in the repository. Anyone who
clones it can read it, and unless someone rotated it, it is still live — which
is exactly the case secret scanning exists for. A working-tree scan cannot see a
single one of them.

Findings name the commit, author and date that introduced the secret, because
"live for two years" and "added yesterday" call for different responses. One
credential committed, reverted, and re-added is reported once, anchored to the
earliest commit.

### In CI

```yaml
- run: pip install repo-security-scanner
- run: reposec scan . --history --fail-on high
```

`--history` needs real history, so set `fetch-depth: 0` on your checkout. To get
findings into the Security tab instead of a log nobody reads:

```yaml
- run: reposec scan . --format sarif > reposec.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reposec.sarif
```

### Docker

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/toosh-legacy/github-py-review scan /repo
```

Read-only mount because the scanner never writes to your repository. The image
ships its own detectors — a Node stage installs eslint-plugin-security, and the
build fails rather than producing an image whose detectors are missing.

### Suppressing known findings

Real repositories contain credential-shaped strings on purpose: documented
example tokens, test fixtures, deliberately vulnerable sample code. A
`.secscanignore` at the repo root drops them, gitignore-style:

```
docs/**                   # every finding under docs/
tests/**:github-pat       # one rule, only under tests/
:B101                     # one rule, anywhere
```

They are dropped rather than flagged — a report you have to mentally filter is
the thing this prevents — but the count appears in `report.suppressed`, so a
file that silences everything is still visible.

## Browser extension

For repositories you have not cloned and may never clone: vetting a dependency,
reviewing someone else's project, due diligence.

Load `src/apps/extension/` at `chrome://extensions` (Developer mode → *Load
unpacked*), open any GitHub repository, and click **🛡️ Scan for secrets**.

**It has no backend.** Secrets and dependencies are checked entirely in the
browser: the regex and entropy rules run in a service worker, and OSV is a public
HTTPS API. Your source is never uploaded anywhere. The only requests it makes are
to `api.github.com` (to read files) and `api.osv.dev` (package names and
versions, never code).

The third detector is honestly missing: bandit and eslint-plugin-security are
subprocesses over a directory tree, and there is no way to run them in a browser.
Every scan says so rather than presenting two thirds of a scan as a clean result.
Run `reposec scan` for the full set, git history, and CI gating.

The extension's secret rules are **generated** from `rules.py`, and CI fails if
they drift — two hand-maintained copies of a rule set diverge, and a diverged
scanner misses things exactly where nobody is looking.

## Choosing a model for triage

`LLM_BACKEND` selects one:

| Mode | Set this |
|---|---|
| No model (default) | nothing — detection runs, triage is skipped |
| Local, fully offline | `LLM_BACKEND=local`, `LOCAL_LLM_BASE_URL=http://localhost:11434/v1`, `LOCAL_LLM_MODEL=qwen2.5-coder:3b` |
| Hosted | `LLM_BACKEND=openai`, `OPENAI_API_KEY=sk-...` |

Other knobs: `SECURITY_TRIAGE=false` (turn the stage off), `SECURITY_OFFLINE=1`
(skip OSV for air-gapped runs). Both have `--no-triage` / `--offline` flags.

Triage prompts contain source code. Credentials are redacted before the prompt
is built, but `LLM_BACKEND=local` keeps everything on your machine.

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

**Precision is the number that matters.** Half the fixture is decoys: AWS's own
documented sample key, `${TEMPLATE}` values, parameter-bound SQL that reads like
concatenation, `yaml.safe_load`, `execFile` with an argument array, the word
`eval` inside a string literal, an `.env.example`, a vendored `node_modules`.
A scanner that fires on everything has perfect recall and is worthless.

Dependencies score against a frozen OSV snapshot, because otherwise a newly
published advisory upstream is indistinguishable from a regression here. The
fixture itself is stored base64-encoded — it is a repository full of planted
credentials, which every scanner in the world flags, including GitHub's push
protection and this one.

**What it does and does not prove.** The fixture was written alongside the
scanner, so 1.00 means "no regression", not "solved". Real-world precision is a
question only real repositories answer. It has earned its keep regardless:
building it found three bandit rules (`B101`, `B603`, `B607`) that fire on
ubiquitous *correct* code, and encoding its corpus exposed a newline bug that
made bandit fail to parse every Python file on Windows.

### Triage lift is not yet measured

`--triage` reports what the LLM stage changed — findings merged beyond the
deterministic pass, severities moved, precision@5 before and after, token cost.
**Those numbers do not exist yet**, because no model has been benchmarked; with
none configured the run reports zeroes and says so.

The triage path itself *is* tested, against a scripted stand-in reproducing how
small models actually fail: skipped ids, shouty `"HIGH"` severities, invented
ids, reciprocal duplicate claims, outright errors.

## How it holds together

```
reposec scan  ─▶  collect → secrets → deps(OSV) → code(bandit, eslint)
                          → suppress → redact → triage(LLM) → aggregate
```

The pipeline is a LangGraph state machine, and the node order is load-bearing.
`redact` sits between detection and triage so a raw credential cannot reach a
model prompt — bandit's `B105` quotes the offending source line verbatim, so
without it a token would reach the report, the terminal, and the prompt. That
ordering is asserted by a test, not just documented.

`tests/test_pipeline_safety.py` also proves the pipeline cannot fetch, cannot
shell out, and that no detection node references a model.

## Development

```bash
pip install -r requirements-dev.txt && pip install -e .
cd src/reposec/detectors/eslint && npm install && cd -

ruff check . && pytest && node --test tests/js/parity.test.mjs
reposec scan . --history --fail-on high      # what CI gates on
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — the short version is that a new
detector rule needs a decoy as well as a planted case, because precision is the
binding constraint. [`docs/GUIDE.md`](docs/GUIDE.md) is a guided tour of the
codebase.

## Security

To report a vulnerability in the scanner, see [`SECURITY.md`](SECURITY.md),
which also documents what it does with your code: with no LLM configured,
nothing leaves your machine except package names and versions sent to OSV, and
`--offline` stops that too.

The scanner runs on its own repository in CI and blocks on a high-severity
finding. That has already caught three high CVEs in its own dependencies and a
ReDoS in its own manifest parser.

## License

MIT — see [`LICENSE`](LICENSE).
