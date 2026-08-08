"""The detectors: everything here is deterministic and model-free.

    secrets   regex fingerprints + Shannon entropy over file contents
    deps      manifest/lockfile parsing checked against the OSV database
    code      bandit (Python) and eslint-plugin-security (JS/TS)
    history   the secret rules, applied to git history
    suppress  .secscanignore
    common    shared helpers: ids, redaction, entropy, file filtering
    rules     the gitleaks-derived secret rule table

A detector that cannot run appends to the report's `degraded` list rather than
returning nothing. A check that did not run must never read as a check that
passed.
"""
