"""reposec — a repository security scanner.

Three detectors find problems deterministically, and an LLM (if one is
configured) only judges what they found:

    detectors.secrets   regex fingerprints + Shannon entropy (gitleaks rules)
    detectors.deps      manifest/lockfile parsing + the OSV database
    detectors.code      bandit (Python) and eslint-plugin-security (JS/TS)
    detectors.history   the same secret rules, over git history
    triage              dedupe, rank, explain, fix — never detect

`graph.py` wires the detectors into a LangGraph pipeline whose node order is
load-bearing: redaction sits between detection and triage, so a raw credential
cannot reach a model prompt.

The public entry point is the `reposec` command; see `cli.py`.
"""

__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    # Lazy so that `import reposec` stays cheap — the CLI reads this only for
    # --version, and importing metadata machinery on every run is wasteful.
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("repo-security-scanner")
        except PackageNotFoundError:
            return "0.0.0+source"
    raise AttributeError(name)
