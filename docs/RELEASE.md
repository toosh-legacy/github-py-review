# Release checklist

Three artifacts ship from one tag: the **PyPI package**, the **container image**,
and the **Chrome extension**. The first two are automated; only the extension
needs a human, because the store listing and the permission justifications do.

## 0. Pre-flight

```bash
ruff check .
pytest
node --test tests/js/parity.test.mjs
python src/evaluation/run_security_eval.py     # expect 1.00 across the board
reposec scan . --history --fail-on high        # expect exit 0
docker build -f deploy/Dockerfile -t reposec:rc .
```

The Docker build asserts its own detectors are present, so a green build means
`node`, `eslint-plugin-security` and `bandit` all made it into the image.

Then bump the version in **three** places — `release.yml` refuses to publish if
they disagree with the tag:

| File | Field |
|---|---|
| `pyproject.toml` | `version` |
| `src/apps/extension/manifest.json` | `version` |
| `CHANGELOG.md` | a new section |

## 1. Tag

```bash
git tag -a v<version> -m "v<version>"
git push origin main --tags
```

`.github/workflows/release.yml` then re-runs every gate (a tag is not a promise
the tree was green), publishes to PyPI via trusted publishing, pushes the image
to GHCR, and attaches the extension zip to a GitHub release.

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

```bash
pipx install repo-security-scanner==<version> && reposec doctor
docker run --rm ghcr.io/toosh-legacy/github-py-review:v<version> --version
```

## After the first public release

Two things are worth doing once real users exist, and are deliberately not done
yet:

- **Measure triage lift.** `--triage` currently reports zeroes because no model
  has been benchmarked. Until that number exists, the LLM stage is unproven.
- **Benchmark against real repositories.** The fixture was written alongside the
  scanner, so 1.00 means "no regression", not "solved". Real-world precision is
  the number that decides whether people keep it installed.
