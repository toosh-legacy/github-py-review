"""Measure how noisy the scanner is on real code that is not the fixture.

    python src/evaluation/run_fp_eval.py                   # installed packages
    python src/evaluation/run_fp_eval.py --corpus ../djangoo
    python src/evaluation/run_fp_eval.py --files 2000 --json

The labelled benchmark answers "does it catch the planted bug". It cannot
answer "does it stay quiet on a real repository", because it was written
alongside the rules it scores. This harness answers the second question, which
is the one that decides whether anyone keeps the tool installed.

**The corpus.** By default it is the third-party packages installed in the
current interpreter — httpx, pydantic, numpy, bandit and friends. That is
tens of thousands of lines of real, reviewed, published Python and JavaScript
that happens to sit on every machine that can run this harness, including CI.
No network, no vendored fixture, and nothing written by the person tuning the
rules. Point `--corpus` at a checkout to score any tree instead.

**What counts as a false positive.** Two different claims, held to two
different standards:

    secrets     Any hit is treated as a false positive. A published package
                does not contain a live credential; if the detector fires here
                it fired on documentation, a test fixture, or a hash. This is
                the number that has to be zero, and the one `.fpignore`-style
                allowances are deliberately not offered for.

    code        Not scored as false positives at all. Real libraries do use
                `subprocess`, `md5` and `eval`, and a linter reporting that is
                doing its job — grading it against an unlabelled corpus would
                be inventing ground truth. It is scored as *noise*: findings
                per thousand lines. A scan nobody can read is a scan nobody
                acts on, so the rate carries a budget even though the
                individual findings are not adjudicated.

Dependency findings are excluded: installed packages carry no manifests, and
the labelled benchmark already scores that detector against a frozen snapshot.
"""
from __future__ import annotations

import argparse
import json
import sys
import sysconfig
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from reposec.detectors.common import VENDOR_DIRS  # noqa: E402

RESULTS = HERE / "fp_corpus_results.json"

# Packaging metadata and the scanner's own test corpora. The first is not code;
# the rest would score the fixture we already score, which proves nothing.
_EXCLUDE_DIRS = {
    "__pycache__",
    "bin",
    "reposec",
    "repo_security_scanner",
    "tests",
    "test",
}

# Packages whose *name* collides with a vendor directory — `build`, `coverage`,
# `dist`, `env`, `out`, `target` are all real PyPI distributions and all appear
# in VENDOR_DIRS. Re-rooting one produces `thirdparty/build/__init__.py`, which
# the scanner correctly refuses to read, so every file in it is selected into the
# corpus and then silently discarded.
#
# That made the measured corpus depend on which packages happened to be
# installed: on a runner with `build` and `coverage` present, 22 of 400 files
# never reached a detector and the guard test failed. Imported from the detector
# rather than restated, so the two cannot drift.
_VENDOR_NAME_COLLISIONS = VENDOR_DIRS

_SOURCE_SUFFIXES = (".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")

# Big generated modules (protobuf stubs, unicode tables, bundled minified JS)
# are not what a reviewer reads and would dominate the line count.
_MAX_FILE_BYTES = 200_000


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #
def _package_roots(purelib: Path) -> list[Path]:
    roots = []
    for entry in sorted(purelib.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name in _EXCLUDE_DIRS or entry.name.startswith((".", "_")):
            continue
        if entry.name.lower() in _VENDOR_NAME_COLLISIONS:
            continue
        if entry.name.endswith((".dist-info", ".egg-info", ".egg-link")):
            continue
        roots.append(entry)
    return roots


def _read(path: Path, root: Path) -> tuple[str, str] | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if "\x00" in content[:8192]:
        return None
    # The scanner drops anything under a vendor directory, and `site-packages`
    # is one — correctly, for a user's repository. Re-rooting under a neutral
    # prefix is what lets the same code be scanned as if it were first-party.
    # The prefix must not reintroduce a vendor name, or the whole corpus is
    # silently filtered out and the harness reports a flawless zero.
    return (f"thirdparty/{root.name}/{path.relative_to(root).as_posix()}", content)


def collect_corpus(source: Path | None, limit: int) -> list[tuple[str, str]]:
    """Gather up to `limit` real source files, spread across packages.

    Round-robin rather than depth-first: taking the first N files alphabetically
    would score one large package and call it "real code".
    """
    if source is not None:
        roots = [source.resolve()]
    else:
        roots = _package_roots(Path(sysconfig.get_paths()["purelib"]))

    per_root: list[list[tuple[str, str]]] = []
    for root in roots:
        found: list[tuple[str, str]] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or not path.name.endswith(_SOURCE_SUFFIXES):
                continue
            if any(part in _EXCLUDE_DIRS for part in path.parts):
                continue
            item = _read(path, root)
            if item is not None:
                found.append(item)
        if found:
            per_root.append(found)

    corpus: list[tuple[str, str]] = []
    index = 0
    while len(corpus) < limit and per_root:
        for bucket in list(per_root):
            if index >= len(bucket):
                per_root.remove(bucket)
                continue
            corpus.append(bucket[index])
            if len(corpus) >= limit:
                break
        index += 1
    return corpus


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
@dataclass
class NoiseReport:
    files: int
    scanned_files: int
    kloc: float
    latency_ms: int
    secret_findings: list[str]
    code_findings: int
    high_severity: int
    by_rule: dict[str, int]
    degraded: list[str]

    @property
    def secret_false_positives(self) -> int:
        return len(self.secret_findings)

    @property
    def code_per_kloc(self) -> float:
        return self.code_findings / self.kloc if self.kloc else 0.0

    @property
    def high_per_kloc(self) -> float:
        return self.high_severity / self.kloc if self.kloc else 0.0

    def as_dict(self) -> dict:
        return {
            "files": self.files,
            # If these diverge the corpus is being filtered before any detector
            # sees it, and every number below is measuring an empty scan.
            "scanned_files": self.scanned_files,
            "kloc": round(self.kloc, 2),
            "latency_ms": self.latency_ms,
            "secret_false_positives": self.secret_false_positives,
            "secret_false_positive_examples": self.secret_findings[:20],
            "code_findings": self.code_findings,
            "code_per_kloc": round(self.code_per_kloc, 3),
            "high_severity": self.high_severity,
            "high_severity_per_kloc": round(self.high_per_kloc, 3),
            "top_rules": dict(Counter(self.by_rule).most_common(15)),
            "degraded": self.degraded,
        }


def measure(corpus: list[tuple[str, str]]) -> NoiseReport:
    from reposec.config import settings

    # Detection only, and never the network: this measures the rules, and a
    # model that reranks findings cannot change how many there are.
    settings.security_triage = False
    settings.security_offline = True

    from reposec.pipeline import run_security_scan

    started = time.perf_counter()
    report = run_security_scan(files=corpus, repo="fp-corpus")
    latency = int((time.perf_counter() - started) * 1000)

    lines = sum(content.count("\n") + 1 for _, content in corpus)
    code = [f for f in report.findings if f.category == "code"]
    secrets = [f for f in report.findings if f.category == "secret"]

    return NoiseReport(
        files=len(corpus),
        scanned_files=report.scanned_files,
        kloc=lines / 1000,
        latency_ms=latency,
        secret_findings=[
            f"{f.file}:{f.line_start} {f.rule_id} — {f.evidence}" for f in secrets
        ],
        code_findings=len(code),
        high_severity=sum(1 for f in code if f.severity == "high"),
        by_rule=Counter(f.rule_id for f in code),
        degraded=report.degraded,
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--corpus",
        type=Path,
        help="directory to scan (default: third-party packages of this interpreter)",
    )
    ap.add_argument("--files", type=int, default=1500, help="cap on files scanned")
    ap.add_argument("--json", action="store_true", help="machine-readable output only")
    args = ap.parse_args()

    corpus = collect_corpus(args.corpus, args.files)
    if not corpus:
        print("no corpus found — pass --corpus <dir>", file=sys.stderr)
        return 2

    result = measure(corpus)
    payload = result.as_dict()
    payload["corpus"] = str(args.corpus) if args.corpus else "installed-packages"

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"\nFALSE POSITIVES ON REAL CODE  ({payload['corpus']})")
        print(
            f"  corpus        {result.files} files "
            f"({result.scanned_files} reached the detectors), "
            f"{result.kloc:,.1f} kLOC"
        )
        print(f"  scan time     {result.latency_ms} ms")
        print(
            f"  secrets       {result.secret_false_positives} false positive(s) "
            "— must be 0"
        )
        for line in result.secret_findings[:20]:
            print(f"                  - {line}")
        print(
            f"  code noise    {result.code_findings} finding(s), "
            f"{result.code_per_kloc:.2f}/kLOC "
            f"({result.high_severity} high, {result.high_per_kloc:.2f}/kLOC)"
        )
        for rule, count in Counter(result.by_rule).most_common(10):
            print(f"                  {count:>5}  {rule}")
        for note in result.degraded:
            print(f"  ! {note}")

    RESULTS.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if not args.json:
        print(f"\nwrote {RESULTS.relative_to(HERE.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
