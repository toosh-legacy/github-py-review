"""Measure how fast the scanner is, and where the time goes.

    python src/evaluation/run_perf_bench.py
    python src/evaluation/run_perf_bench.py --json

Three separate questions, because they have three separate answers:

    walk        how long it takes to read a repository off disk. This is the
                part that decides whether `reposec scan .` feels instant on a
                monorepo, and it is entirely ours — no subprocess involved.

    stages      where the time goes inside one scan. Splitting it matters
                because the answer is lopsided: the analyzers are subprocesses
                and dominate, so tuning a regex saves nothing while a wasted
                bandit invocation costs seconds.

    scaling     whether cost stays linear in repository size. Measured on the
                pure-Python path only (file collection, secrets, suppression,
                redaction, aggregation) because that is the code this project
                controls; bandit's own scaling is bandit's business, and
                shelling out to it 4,000 times would make the harness unusable.

Absolute numbers are machine-specific and only comparable against themselves on
one host. The shape — linear scaling, and which stage dominates — is not, and
that is what `tests/quality/test_performance.py` asserts on.
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

RESULTS = HERE / "perf_results.json"

SCALING_SIZES = (250, 1000, 4000)
PIPELINE_FILES = 200


# --------------------------------------------------------------------------- #
# A synthetic repository
# --------------------------------------------------------------------------- #
_PY_TEMPLATE = '''\
"""Module {n} — generated for the performance benchmark."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass


@dataclass
class Record{n}:
    identifier: str
    payload: dict
    checksum: str = ""


def load_{n}(path: str) -> list[Record{n}]:
    """Read records and compute a checksum for each."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    out = []
    for item in raw.get("records", []):
        digest = hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        out.append(Record{n}(identifier=item["id"], payload=item, checksum=digest))
    return out


def resolve_{n}(name: str) -> str:
    base = os.environ.get("DATA_ROOT", "/var/data")
    return os.path.join(base, name.replace("..", ""))


def summarise_{n}(records: list[Record{n}]) -> dict:
    return {{
        "count": len(records),
        "identifiers": sorted(r.identifier for r in records),
        "checksums": {{r.identifier: r.checksum for r in records}},
    }}
'''

_JS_TEMPLATE = """\
// Module {n} — generated for the performance benchmark.
export function render{n}(node, values) {{
  const list = document.createElement('ul');
  for (const value of values) {{
    const item = document.createElement('li');
    item.textContent = String(value);
    list.appendChild(item);
  }}
  node.replaceChildren(list);
  return list;
}}

export async function fetch{n}(url, signal) {{
  const response = await fetch(url, {{ signal, credentials: 'omit' }});
  if (!response.ok) throw new Error(`request failed: ${{response.status}}`);
  return response.json();
}}
"""

_MD_TEMPLATE = """\
# Component {n}

Configure it with `DATA_ROOT` and restart the worker. Records are keyed by
identifier and checksummed on load, so a partial write is detected rather than
silently served.

    export DATA_ROOT=/var/data
    python -m worker --module {n}
"""


def make_corpus(count: int) -> list[tuple[str, str]]:
    """A deterministic repository of `count` files: 70% Python, 20% JS, 10% docs.

    Ordinary code, not a fixture full of findings. Timing a scan against a file
    that produces forty findings measures the reporting path, not the scan.
    """
    files: list[tuple[str, str]] = []
    for n in range(count):
        bucket = n % 10
        if bucket < 7:
            files.append((f"src/pkg{n % 20}/module_{n}.py", _PY_TEMPLATE.format(n=n)))
        elif bucket < 9:
            files.append((f"web/components/widget_{n}.js", _JS_TEMPLATE.format(n=n)))
        else:
            files.append((f"docs/component_{n}.md", _MD_TEMPLATE.format(n=n)))
    return files


def _kloc(files: list[tuple[str, str]]) -> float:
    return sum(c.count("\n") + 1 for _, c in files) / 1000


def _time(fn, repeat: int = 1) -> float:
    """Best-of-`repeat` wall time in milliseconds.

    Best rather than mean: this is a throughput measurement on a shared machine,
    where every source of noise makes a run slower and none makes it faster.
    """
    samples = []
    for _ in range(repeat):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000)
    return min(samples)


# --------------------------------------------------------------------------- #
# 1. Reading the tree off disk
# --------------------------------------------------------------------------- #
def measure_walk(count: int = 2000) -> dict:
    from reposec.cli import read_repo

    root = Path(tempfile.mkdtemp(prefix="reposec-perf-"))
    try:
        for path, content in make_corpus(count):
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
        # A vendor tree the walk must prune rather than read. Not pruning it is
        # the difference between a scan feeling instant and feeling broken, and
        # it is invisible unless the benchmark contains one.
        for n in range(count):
            dest = root / "node_modules" / f"pkg{n % 50}" / f"index_{n}.js"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(_JS_TEMPLATE.format(n=n), encoding="utf-8")

        files: list[tuple[str, str]] = []

        def run():
            nonlocal files
            files, _ = read_repo(root, 400_000)

        elapsed = _time(run, repeat=3)
        return {
            "files_on_disk": count * 2,
            "files_read": len(files),
            "vendored_skipped": count,
            "ms": round(elapsed, 1),
            "files_per_second": round(len(files) / (elapsed / 1000), 1),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 2. Where the time goes in one scan
# --------------------------------------------------------------------------- #
def measure_stages(count: int = PIPELINE_FILES) -> dict:
    from reposec.config import settings
    from reposec.detectors.code import scan_code
    from reposec.detectors.deps import scan_dependencies
    from reposec.detectors.secrets import scan_files, scrub
    from reposec.detectors.suppress import apply, load_rules
    from reposec.pipeline import run_security_scan

    settings.security_triage = False
    settings.security_offline = True

    corpus = make_corpus(count)
    findings = scan_files(corpus)

    # Warm up the analyzers before timing anything. bandit and eslint pay a
    # one-off interpreter start on their first invocation in a process, and
    # charging that to whichever stage happens to run first makes the breakdown
    # add up to more than the end-to-end number it is supposed to explain.
    scan_code(corpus[:5])

    stages = {
        "secrets": _time(lambda: scan_files(corpus), repeat=3),
        "dependencies": _time(
            lambda: scan_dependencies(corpus, offline=True), repeat=3
        ),
        "code": _time(lambda: scan_code(corpus), repeat=2),
        "suppress": _time(lambda: apply(findings, load_rules(corpus)), repeat=3),
        "redact": _time(
            lambda: [scrub(f.evidence) for f in findings], repeat=3
        ),
    }
    end_to_end = _time(lambda: run_security_scan(files=corpus, repo="perf"), repeat=2)

    total = sum(stages.values()) or 1.0
    return {
        "files": count,
        "kloc": round(_kloc(corpus), 1),
        "end_to_end_ms": round(end_to_end, 1),
        "stages_ms": {k: round(v, 2) for k, v in stages.items()},
        "stages_pct": {k: round(100 * v / total, 1) for k, v in stages.items()},
        "files_per_second": round(count / (end_to_end / 1000), 1),
    }


# --------------------------------------------------------------------------- #
# 3. Does it stay linear?
# --------------------------------------------------------------------------- #
def measure_scaling(sizes: tuple[int, ...] = SCALING_SIZES) -> dict:
    """Time the pure-Python path at increasing sizes.

    Reported as microseconds per file, which is flat for a linear algorithm and
    climbs for a quadratic one — a shape that survives being run on a different
    machine, unlike the raw milliseconds.
    """
    from reposec.detectors.secrets import scan_files
    from reposec.detectors.suppress import apply, load_rules
    from reposec.pipeline import _aggregate, _collect, _redact

    points = []
    for size in sizes:
        corpus = make_corpus(size)

        def run(corpus=corpus):
            state = _collect({"files": corpus})
            state["findings"] = scan_files(state["files"])
            kept, _ = apply(state["findings"], load_rules(state["files"]))
            state["findings"] = kept
            _aggregate(_redact(state))

        elapsed = _time(run, repeat=3)
        points.append(
            {
                "files": size,
                "kloc": round(_kloc(corpus), 1),
                "ms": round(elapsed, 1),
                "us_per_file": round(elapsed * 1000 / size, 1),
                "kloc_per_second": round(_kloc(corpus) / (elapsed / 1000), 1),
            }
        )

    per_file = [p["us_per_file"] for p in points]
    return {
        "points": points,
        # Above ~1.5 the cost per file is growing with repository size, which
        # means something in the pipeline is quadratic.
        "growth_factor": round(max(per_file) / statistics.median(per_file), 2),
    }


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run_all() -> dict:
    return {
        "walk": measure_walk(),
        "pipeline": measure_stages(),
        "scaling": measure_scaling(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output only")
    args = ap.parse_args()

    results = run_all()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        walk = results["walk"]
        print("\nREADING THE TREE")
        print(
            f"  {walk['files_read']} files read, {walk['vendored_skipped']} vendored "
            f"pruned, in {walk['ms']} ms ({walk['files_per_second']:,.0f} files/s)"
        )

        pipe = results["pipeline"]
        print(f"\nONE SCAN  ({pipe['files']} files, {pipe['kloc']} kLOC)")
        print(
            f"  end to end    {pipe['end_to_end_ms']:,.0f} ms "
            f"({pipe['files_per_second']:,.0f} files/s)"
        )
        for stage, ms in sorted(
            pipe["stages_ms"].items(), key=lambda kv: -kv[1]
        ):
            print(f"    {stage:<14} {ms:>9,.2f} ms   {pipe['stages_pct'][stage]:>5}%")

        print("\nSCALING  (pure-Python path)")
        for point in results["scaling"]["points"]:
            print(
                f"  {point['files']:>5} files  {point['ms']:>8,.1f} ms   "
                f"{point['us_per_file']:>6.1f} us/file   "
                f"{point['kloc_per_second']:>8,.0f} kLOC/s"
            )
        print(f"  growth factor {results['scaling']['growth_factor']} (1.0 = linear)")

    RESULTS.write_text(json.dumps(results, indent=2), encoding="utf-8")
    if not args.json:
        print(f"\nwrote {RESULTS.relative_to(HERE.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
