# What is left before this is production-ready

Written 2026-08-11 after the quality-harness pass, revised the same day after
the production-readiness pass. This is the working list to come back to — what
is genuinely done, what is claimed but never executed, and what is known-broken
and accepted. Delete items as they land; do not delete an item by lowering the
bar it failed.

The ordering is by consequence, not by effort.

---

## 1. Blockers — do not tag a release until these are cleared

### 1.1 ~~The browser extension no longer matches the scanner~~ — done

`_connection_string_verdict` and segment-wise `_secret_entropy` are ported to
`src/apps/extension/scanner.js`. More usefully, `tests/js/parity.test.mjs` now
*scores* the extension against the labelled decoys in `ground_truth.json`
instead of diffing the rule table — P 1.00 / R 1.00 / 23 caught, matching
`results.json` exactly. Before the port the same test failed with five decoy
false positives, which is the point: a parity test that only compares regexes
would have kept missing this class of drift indefinitely.

### 1.2 ~~The Docker image has never actually been built~~ — done

It had not been, and the first build failed: `.dockerignore` excluded `deploy/`,
so `COPY deploy/verify_image.py` could not resolve. Fixed with a negation, and
the build-time gate now runs inside the image (`image verified — 2 rule(s)
fired, no detector degraded`).

The case the image exists for is verified too. Against a read-only bind mount as
uid 10001, `scan /repo --history --strict` exits 0 and reports *"Plus 2
secret(s) found only in git history"* — so `git config --system safe.directory`
does defeat the dubious-ownership failure, which matters because that failure is
silent: it degrades, it does not error.

### 1.3 CI has never run green on the new configuration — half done

Verified locally:

- **The 3.12 matrix leg.** `requires-python` was lowered to `>=3.12` on the
  strength of a source audit and nothing had ever run on it. The full fast suite
  now passes on CPython 3.12.12 — 278 tests — plus `compileall`.
- **The image jobs**, per 1.2 above.
- **The coverage gate**, raised 78 → 85 after `osv.py` and `llm.py` went to
  100%; the suite measures 88.74%.

**Still unexercised:** the workflow files themselves. The `quality` job, the
matrix wiring, and the restructured release workflow have not run on a GitHub
runner. **Do:** push and read the run. Expect the quality job to take ~2 minutes.

### 1.4 The release workflow is untested end to end

Unchanged and still open — it cannot be closed locally. It builds once,
smoke-tests the wheel in a clean venv, and publishes that same artifact.

**Do:** tag a prerelease (`v1.1.0-rc1`) and watch it. Two things to confirm
specifically: the `node_modules` wheel guard runs *after* the npm install (so it
tests the contaminated case), and `:latest` does **not** move for a tag
containing a hyphen.

### 1.5 ~~Decide the canonical repository path~~ — done

Settled on the real remote, `toosh-legacy/github-py-review`. `pyproject.toml`'s
URLs and the SARIF `informationUri` follow it, which is what `release.yml`
already used via `${{ github.repository }}`. The distribution keeps the name
`repo-security-scanner`; a package name differing from its repository name is
ordinary, a package pointing at a repository that does not exist is not.

---

## 2. Gaps that will bite in the field

### 2.1 ~~`osv.py` is 25% covered and the entire HTTP path is untested~~ — done, and it was hiding three defects

Coverage is 100% (statement and branch), against fixtures cut from real recorded
osv.dev payloads. Writing the tests found the exact failure this section
predicted, in three forms:

1. **A renamed `vulns` key reported a clean bill of health.** Every slot parsed
   as "no vulnerabilities", `query_batch` returned success, and
   `scan_dependencies` returned `findings == []` *and* `degraded == []` — a
   lockfile full of CVEs, indistinguishable from a healthy repository.
2. **`results` arriving as an object crashed the scan.** `zip` walked the dict's
   keys, so `entry` was a `str`; the resulting `AttributeError` was not in the
   except clause and escaped past `scan_dependencies`, which only catches
   `OSVUnavailable`.
3. **A short `results` list silently dropped the tail.**

Fixed. Every branch of the batch parser now raises rather than returning empty —
the asymmetry is deliberate, because a clean package and an unparseable one both
yield "no ids" and only one is safe to report as clean — and a short list is
counted as `unmatched` and reported as unchecked.

### 2.2 ~~`llm.py` is 25% covered~~ — done

100%: client construction for every backend, `get_llm()` selection across all
four `LLM_BACKEND` values with and without credentials, and the lenient JSON
parser's edge cases. One latent crash fixed — `resp.usage` was read unguarded,
and it is an optional field several local servers omit.

### 2.3 ~~Only bandit is chunked~~ — done

eslint is chunked at 1,000 files (bandit stays at 2,000; eslint pays a process
start and a full JS toolchain rather than the stdlib `ast`). A timeout now costs
one chunk, is reported *as a timeout* rather than a generic "could not run", and
names the file count. The pattern rules widen to cover eslint's ground only over
the files eslint actually failed on, so a partial failure does not double-report
the chunks that succeeded.

`tests/quality/test_scale.py` exercises the multi-chunk path for real — 4,100
Python files and 2,010 JS files, with a planted finding at each end of the tree,
asserting findings come back from both. A fourth test induces a chunk failure
and asserts the surviving chunks still report.

### 2.4 ~~Memory is bounded per file, never in aggregate~~ — done

`--max-total-bytes`, default 256 MB. Reaching it stops the read, reports how
many files went unscanned, and `--strict` turns that into exit 3. Reporting
"scanned the first N MB" is honest; being OOM-killed is not.

### 2.5 `security/detect-object-injection` is now the loudest thing in the tool — open

Section 3 below has always said this rule is "left on because the vulnerability
it names is real; revisit if users complain before the noise budget does". The
noise budget has now complained, with a number: on `dvpwa`, **179 of 245
findings** came from this one rule — 73% of everything the scan said about a
45-file repository.

It is still not wrong, which is why it is not simply switched off. The options,
in the order they should be tried:

1. Cap it per file and report the cap (`… and 42 more on this file`), the way
   every other bound in this tool is reported.
2. Drop it to `low` so it cannot dominate a `--fail-on medium` run.
3. Enable it only when the indexed key is not a literal, which is what makes the
   rule meaningful — that means a real AST check, not a config change.

### 2.6 The vendored-directory heuristic is name-only, and silently skips first-party code — open

`VENDOR_DIRS` matches on a path *component name*: any file with `build`, `dist`,
`out`, `target`, `env` or `coverage` anywhere in its path is dropped before any
detector sees it. For generated output that is correct and is most of the reason
a scan is fast.

But it cannot tell a generated `build/` from a source directory that happens to
be called `build/`, and the second is not hypothetical — `build`, `coverage`,
`dist` and `env` are all real PyPI distributions. **A user whose source lives in
`src/target/` or `app/out/` gets it skipped with no note.** That is a silent
partial scan, which is the failure this tool exists to report in other people's
code.

Found by CI: the false-positive corpus selects installed packages and re-roots
them, so on a runner with `build` and `coverage` installed, 22 of 400 corpus
files never reached a detector. The harness now excludes package names that
collide with `VENDOR_DIRS`, which fixes the measurement — the product behaviour
is unchanged and still wrong at the edges.

**Do:** distinguish generated from source rather than guessing from the name —
`build/` next to a `pyproject.toml` is output, `build/` containing `__init__.py`
is a package. At minimum, count what the walk skipped for this reason and report
it, so a skipped tree is visible instead of silent.

### 2.7 `scan_code` writes a full second copy of the tree to `/tmp` — open

Counted and reported when writes fail, which is the important half. Still worth
revisiting whether bandit can be pointed at the original files for the CLI path,
where they already exist on disk — the temp copy exists for the browser-extension
case, where content arrives as strings over HTTP.

---

---

## 2b. Found by the live-fire harness and the diff review, and fixed

`src/evaluation/run_live_eval.py` (new) clones real applications instead of
sampling installed packages, and a review pass went over the whole diff. Between
them they found seven defects that the existing harnesses structurally could
not — the sampled corpora only ever select `.py`/`.js` source files, so `.pem`
fixtures, `.md` documentation and test trees had never been scanned at all.

- **Segment-wise entropy silenced real credentials, and stopped redacting
  them.** `/` and `+` are in the base64 alphabet, so a real AWS secret key
  contains a slash about 40% of the time; splitting on it left segments too
  short to clear the gate. Measured: 0.2% of 20,000 generated keys went
  unreported. Worse, `scrub()` shared the same measure — so those keys were no
  longer *masked*, and would have reached the report, the terminal and the model
  prompt, falsifying the one claim `_redact` exists to make. The segment
  discount now applies only when every segment is wordlike, and `scrub()`
  deliberately uses whole-string entropy: detection and redaction are different
  questions, and under-masking costs more than over-masking.
- **Five `high` private-key findings on `psf/requests` and `axios`** — every one
  a self-signed fixture cert under a test tree. That is a failing
  `--fail-on high` on two of the most audited repositories in open source.
- **Test trees are now treated like documentation**: entropy-gated rules
  downgrade, provider fingerprints do not.
- **One credential was reported as up to three findings.** `JWT_SECRET = "…"`
  matched both `hardcoded-crypto-key` and `generic-api-key`; `token = "ghp_…"`
  matched both `github-pat` and the generic rule. Collapsed to the
  highest-severity match, fingerprints first.
- **The generic name lists missed the commonest shapes.** `JWT_SIGNING_SECRET`,
  `WEBHOOK_SECRET`, `SESSION_TOKEN`, `DB_PASSWORD` all went unreported at
  entropy 5.33. Found by planting one in real code and watching nothing happen.
- **An eslint noise rule suppressed a real finding.** The JS dedup keyed on
  `(file, line)` alone, so `el.innerHTML = data[key]` reported
  `detect-object-injection` and *dropped* the XSS sink; two pattern rules on one
  line also collapsed. Now only the one genuinely overlapping pair is deduped.
- **`install-eslint --dir` reported a successful install as a failure**, exited
  2, and told the user to set the variable that would have made its own check
  pass — while the install itself was fine and unfindable by the scanner.

The lesson worth keeping: every one of these lived in a gap between what a
harness sampled and what a user actually has on disk. Sampling `.py` files is
not scanning a repository.

---

## 3. Known and accepted — do not "fix" these by weakening a fixture

- **Two labelled decoys fire** (`web/api.js:51`, `web/api.js:62`), both from
  eslint-plugin-security being conservative about computed paths and nested
  quantifiers. Recorded as `known_failure` in `ground_truth.json`; code
  precision is 0.92 because of them. `test_no_unlabelled_false_positive_appears`
  is what stops a third one appearing quietly.
- **`security/detect-object-injection`** fires 7 times per 420 kLOC of real
  code. Genuinely noisy upstream. Left on because the vulnerability it names is
  real; revisit if users complain before the noise budget does.
- **B311 (`random`) and B704** are the loudest remaining rules on real code, at
  low severity. Both are context-dependent rather than wrong.
- **The widened contextual name lists cost ~2.5× on their own rules.** Measured
  in isolation over 90 KB of source, `generic-api-key` went from 4.1 ms to
  10.2 ms per pass when the optional qualifier prefix was added; the same for
  `hardcoded-password` and `hardcoded-crypto-key`. Three alternative
  formulations were benchmarked and every one was slower — dropping the leading
  `\b` costs 15.8 ms, a bounded character class 16.8 ms, the lazy variant
  21.1 ms — because `\b` is what stops the engine attempting a match at every
  offset. The end-to-end cost is ~2% of a scan, since the secret detector is
  ~4% of wall time and the analyzers are ~95%. Accepted: it closed a whole class
  of missed credentials (`JWT_SIGNING_SECRET`, `DB_PASSWORD`) for a cost that
  does not show up outside a microbenchmark. Do not widen these further without
  re-running that measurement.
- **Wall-clock numbers on a developer laptop vary by up to 40% between runs.**
  Three clean sequential readings of the pure-Python path gave 39, 42 and
  27 kLOC/s. Publish ranges, not single readings — an earlier version of the
  README quoted "~56 kLOC/s" from one lucky run. What is stable across every
  reading, and is what the budgets actually guard, is the *shape*: growth factor
  1.0–1.1, and 94–97% of wall time inside the analyzer subprocesses.

---

## 4. Worth doing, not blocking

### 4.1 ~~Drop LangGraph~~ — done

`reposec/graph.py` is now `reposec/pipeline.py`: a tuple of eight functions and
a `for` loop. Measured cost of the framework it replaced, with `-X importtime`:
1.30s of import per invocation against 0.17s for the whole new module, on a CLI
that scans a small repository in about two seconds, plus ~25 transitive packages
in a tool that sells dependency hygiene.

It also deletes the tracing-leak class rather than suppressing it. The
`tracing_context(enabled=False)` guard is gone because there is no longer a
tracer to guard against, and `test_pipeline_safety.py` fails the build if
anything in the package imports langgraph, langsmith or langchain again.

### 4.2 Make the benchmark harder rather than larger — open

111 labelled cases is enough breadth. The next useful increment is depth in the
decoys: minified-but-not-`.min.js` bundles, generated protobuf, test fixtures
that legitimately contain credential-shaped strings, i18n files full of
high-entropy identifiers.

A concrete lead: scanning SQLAlchemy in full turned up six false positives that
the 1,500-file sampled corpus never selected (hostless libpq connection strings,
now fixed). Whole-package sweeps find what sampling misses.

### 4.3 Track the numbers over time — open

`run_fp_eval.py` and `run_perf_bench.py` write JSON that is gitignored because
it is machine-specific. A CI job that posts them as a PR comment would turn
"0.23 findings/kLOC" from a number in a doc into a trend anyone can see move.

---

## Where the numbers come from

Measured 2026-08-11, after the pass above.

| Harness | Command | Current |
|---|---|---|
| Labelled benchmark | `python src/evaluation/run_security_eval.py` | 111 cases, P 0.96 / R 1.00 / F1 0.98 |
| Real-code false positives | `python src/evaluation/run_fp_eval.py` | 0 secret FPs over 419.6 kLOC; 0.23 code findings/kLOC |
| Live fire — recall | `python src/evaluation/run_live_eval.py` | 16/16 planted findings in a real application; recall 1.00 |
| Live fire — noise | (same run) | 0 blocking secret FPs over 150.5 kLOC of `requests`, `flask`, `axios`; 22 downgraded to low |
| Live fire — signal | (same run) | `pygoat` 203, `dvpwa` 245, `nodegoat` 18 findings; 65% of bandit's output filtered as unactionable |
| Performance | `python src/evaluation/run_perf_bench.py` | ~2,000–4,000 files/s walk; ~30–50 kLOC/s pure-Python; ~10 kLOC/s end to end with real analyzers; growth 1.0–1.1 |
| Budgets and scale, as tests | `pytest -m quality` | 14 tests |
| Everything else | `pytest -m "not quality"` | 307 tests, 88%+ coverage |
| Extension parity | `node --test tests/js/parity.test.mjs` | 22 tests; secrets P 1.00 / R 1.00 |

"Blocking" means at or above `medium`. The detector deliberately downgrades
rather than drops in documentation and test trees, so counting a `low` doc
finding as a false positive would score the tool against a policy it does not
claim — `--fail-on high` is the CI contract.
