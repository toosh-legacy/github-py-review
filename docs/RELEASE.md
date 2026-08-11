# Release checklist

> **Status: nothing has been published yet.** No PyPI package, no public image,
> no Web Store listing — the project runs from a clone
> ([README](../README.md#run-it-locally)). This document is the process for when
> that changes; none of it has been executed end to end.
>
> **Two prerequisites block the very first release**, and neither is in this
> repository:
>
> 1. A PyPI **pending publisher** for `repo-security-scanner` — the project name
>    is unclaimed, and trusted publishing cannot create a project that has no
>    pending publisher configured. Without it the `pypi` job fails *after* the
>    image has already been pushed, which is the worst outcome: half released.
> 2. A GitHub environment named **`pypi`**.
>
> Do both before the first tag. See [§4](#4-first-run-prerequisites-once-before-the-first-tag).

Three artifacts ship from one tag: the **PyPI package**, the **container image**,
and the **Chrome extension**. The first two are automated; only the extension
needs a human, because the store listing and the permission justifications do.

## 0. Pre-flight

```bash
ruff check .
pytest                                         # including -m quality
node --test tests/js/parity.test.mjs
python src/evaluation/run_security_eval.py     # expect P 0.96 / R 1.00 / F1 0.98
python src/evaluation/run_fp_eval.py           # expect 0 secret false positives
python src/evaluation/run_live_eval.py         # real repositories; needs network
reposec scan . --history --fail-on high        # expect exit 0
docker build -f deploy/Dockerfile -t reposec:rc .
```

The Docker build scans a fixture repository with `--strict`, so a green build
means `node`, `eslint-plugin-security`, `bandit`, `git` and the OSV lookup all
work inside the image — not merely that the files are present.

`run_live_eval.py` is the one that has historically found things the others
could not: it clones real applications, so it sees file types the sampled
corpora never select — `.pem` fixtures, `.md` documentation, test trees.

Then bump the version in **three** places — `release.yml` refuses to publish if
they disagree with the tag:

| File | Field | For tag `v1.2.0` | For tag `v1.2.0-rc1` |
|---|---|---|---|
| `pyproject.toml` | `version` | `1.2.0` | `1.2.0rc1` |
| `src/apps/extension/manifest.json` | `version` | `1.2.0` | `1.2.0` |
| `CHANGELOG.md` | a new section | — | — |

The prerelease column is not a typo, and it is worth understanding before a
release fails halfway. Versions are compared as versions, not strings: PEP 440
normalises the tag `v1.2.0-rc1` to `1.2.0rc1`, which is what `pyproject.toml`
must contain. Chrome's manifest cannot express a prerelease at all — it takes
one to four dot-separated integers, and `package_extension.py` rejects anything
else — so the extension tracks the release *core* and ships `1.2.0` for both
tags.

## 1. Tag

```bash
git tag -a v<version> -m "v<version>"
git push origin main --tags
```

`.github/workflows/release.yml` then re-runs every gate (a tag is not a promise
the tree was green), publishes to PyPI via trusted publishing, pushes a
multi-architecture image (amd64 and arm64) to GHCR, and attaches the extension
zip to a GitHub release.

The wheel is built once, in the job that ran the tests, then installed from that
artifact into an empty virtualenv and smoke-tested before the publish job
uploads **that same file**. Building it again at publish time would ship a wheel
nobody has ever installed. A prerelease tag — anything with a hyphen, like
`v1.1.0-rc1` — publishes its own image tag but does not move `:latest`.

**One-time PyPI setup:** add this repository as a trusted publisher on PyPI for
the project name, and create a GitHub environment called `pypi`. There is no API
token to store — which is deliberate, since a long-lived token in CI is exactly
the kind of finding this project reports.

## 2. Chrome extension

The release workflow builds the zip; uploading it is manual.

```bash
python deploy/make_extension_icons.py   # only if the icon changed
python deploy/package_extension.py      # validates the manifest, writes dist/
```

The packager checks what costs a review round trip: manifest v3, a numeric
version, a description within the store's 132-character limit, all four icon
sizes, and every file the manifest references actually included.

Upload `dist/reposec-extension-<version>.zip` at the
[developer console](https://chrome.google.com/webstore/devconsole).

**Store listing needs, beyond the zip:**

- At least one 1280×800 or 640×400 screenshot. Show a scan result with real
  findings — the popup on a repository page is the product.
- A privacy policy URL. The honest and unusually short version: the extension
  has no backend, sends no source code anywhere, and talks only to
  `api.github.com` and `api.osv.dev`. `SECURITY.md` covers the substance.
- A justification per permission. `storage` holds the optional GitHub token;
  the host permissions are GitHub (to read files) and OSV (to check versions).
  There is no remote server to explain, which makes this review much easier
  than it used to be.

Review typically takes a few days; a permissions change can take longer.

## 3. Verify what shipped

Against the published artifacts, not the local tree — that is the whole point.

```bash
pipx install repo-security-scanner==<version> && reposec doctor
docker run --rm ghcr.io/toosh-legacy/github-py-review:v<version> --version

# The image is only useful if it can scan a real repository read-only, as a
# non-root user, with history. This is the case that degrades *silently* when
# it breaks, so --strict is what makes the failure visible.
docker run --rm -v "$PWD:/repo:ro" \
  ghcr.io/toosh-legacy/github-py-review:v<version> \
  scan /repo --history --strict --no-color
```

`doctor` should report five detectors; `code (js/ts)` missing means the image
lost its Node or its eslint install, which no unit test can catch.

## 4. First-run prerequisites (once, before the first tag)

- **PyPI trusted publishing.** Add this repository as a trusted publisher for
  the project name, and create a GitHub environment called `pypi`. There is no
  token to store — deliberately, since a long-lived token in CI is exactly the
  kind of finding this project reports.
- **GHCR.** Nothing to set up; `release.yml` authenticates with the automatic
  `GITHUB_TOKEN`. Make the package public after the first push, or `docker pull`
  will ask every user for credentials.
- **Chrome Web Store.** A one-time developer-account registration fee applies,
  and the first submission of a new extension is reviewed more slowly than
  updates.

## After the first public release

- **Measure triage lift.** `--triage` currently reports zeroes because no model
  has been benchmarked. Until that number exists, the LLM stage is unproven, and
  it is the only part of this tool whose value is asserted rather than measured.
- **Watch the noisiest rule.** `security/detect-object-injection` produced 179
  of 245 findings on one live target. It is left on deliberately (see
  `docs/PRODUCTION_READINESS.md` §3), but that ratio is the trigger to bound it.

**Real-world recall** is no longer on this list: `run_live_eval.py` plants a
known set of credentials and unsafe patterns into a real application and scores
the scan against them, so recall is measured against code nobody here wrote.
Run it before every release.
