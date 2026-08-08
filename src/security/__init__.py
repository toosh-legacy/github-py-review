"""Security detectors.

Three independent detectors produce findings from real tools and rules — no LLM
is involved in detection:

    secrets_scan  regex + Shannon entropy over file contents (gitleaks rules)
    deps_scan     manifest/lockfile parsing + the OSV vulnerability database
    code_scan     bandit (Python) and eslint-plugin-security (JS/TS)

`triage` is where the LLM earns its place: it deduplicates overlapping findings,
re-ranks them by real-world exploitability, explains each in plain language
against the actual code, and proposes a fix. It can only ever narrow, reorder,
or annotate the detector output — never invent a finding.
"""
