# Release checklist

Three artifacts ship independently: the **API image**, the **Chrome extension**,
and the **dashboard**. Only the extension needs a human in the loop (store
review), so do that one first.

## 0. Pre-flight

```bash
ruff check .
pytest
python src/evaluation/run_security_eval.py          # expect 1.00 across the board
python -m security.cli . --history --fail-on high   # expect exit 0
docker build -f deploy/Dockerfile -t repo-security-scanner:rc .
```

The Docker build asserts its own detectors are present, so a green build means
`node`, `eslint-plugin-security` and `bandit` all made it into the image.

Then bump the version in **three** places and keep them in step:

| File | Field |
|---|---|
| `pyproject.toml` | `version` |
| `src/apps/extension/manifest.json` | `version` |
| `CHANGELOG.md` | a new section |

## 1. Chrome extension

```bash
python deploy/make_extension_icons.py   # only if the icon changed
python deploy/package_extension.py      # validates the manifest, writes dist/
```

The packager checks the things that cost a review round trip: manifest v3, a
numeric version, a description within the store's 132-character limit, all four
icon sizes present, and every file the manifest references actually included.

Upload `dist/repo-security-scanner-<version>.zip` at the
[developer console](https://chrome.google.com/webstore/devconsole).

**Store listing needs, beyond the zip:**

- At least one 1280×800 or 640×400 screenshot. Show a scan result with real
  findings — the popup on a repository page is the product.
- A privacy policy URL. `SECURITY.md` covers the substance: what is sent where,
  and that credentials are redacted before storage.
- A justification for each permission. Expect to be asked about
  `optional_host_permissions: https://*/*`; the honest answer is that the
  backend is self-hosted, so its hostname is not knowable at build time, and the
  permission is requested at runtime from a user gesture for the one origin the
  user typed.

Review typically takes a few days. A permissions change can trigger a longer one.

## 2. API

```bash
fly deploy                       # uses fly.toml -> deploy/Dockerfile
fly logs                         # confirm startup
curl https://<app>/health        # {"status":"ok", ...}
```

First deploy only:

```bash
fly launch --no-deploy
fly postgres create && fly postgres attach <db>   # injects DATABASE_URL
fly secrets set OPENAI_API_KEY=...                # optional: enables triage
```

`init_db()` runs `create_all` on startup, so a fresh Postgres needs no migration
step. There is no migration tooling — a future schema change to `security_scans`
will need one.

Set `ALLOWED_ORIGINS` to your dashboard's origin. The extension does not belong
in that list: its service worker holds a host permission and is not a CORS caller.

## 3. Dashboard

Deploy `src/apps/dashboard/app.py` to Streamlit Community Cloud, pointing it at
`src/apps/dashboard/requirements.txt`, and set `BACKEND_URL` to the deployed API.

## 4. Tag

```bash
git tag -a v<version> -m "v<version>"
git push origin main --tags
```

## After the first public release

Two things are worth doing once real users exist and are deliberately not done
yet:

- **Measure triage lift.** `--triage` currently reports zeroes because no model
  has been benchmarked. Until that number exists, the LLM stage is unproven.
- **Benchmark against real repositories.** The fixture was written alongside the
  scanner, so 1.00 means "no regression", not "solved". Real-world precision is
  the number that decides whether people keep it installed.
