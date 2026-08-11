"""Hold the scanner to a speed budget, and to linear scaling.

Absolute timings differ by an order of magnitude between a laptop and a shared
CI runner, so the budgets here are deliberately loose — roughly a quarter of the
measured throughput. They are not a benchmark; they catch the failures that make
a scanner unusable rather than slow:

    * a quadratic in the pure-Python path, which is invisible on a fixture and
      fatal on a monorepo
    * a regex that backtracks exponentially on hostile input
    * the tree walk descending into vendored directories

`python src/evaluation/run_perf_bench.py` prints the real numbers.
"""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.quality

# Per-file cost must not grow with repository size. 1.0 is perfectly linear;
# measured at 1.02 across 250 → 4,000 files.
MAX_GROWTH_FACTOR = 1.5

# Measured at ~70 kLOC/s. A quarter of that leaves room for a slow runner while
# still failing if the hot loop gains an order of magnitude.
MIN_KLOC_PER_SECOND = 15.0

# Measured at ~3,000 files/s including pruning an equal number of vendored ones.
MIN_WALK_FILES_PER_SECOND = 400.0


@pytest.fixture(scope="module")
def perf():
    from harness import load_harness

    return load_harness("run_perf_bench")


def test_the_pure_python_path_scales_linearly(perf):
    scaling = perf.measure_scaling((250, 1000, 4000))
    assert scaling["growth_factor"] <= MAX_GROWTH_FACTOR, (
        "cost per file grows with repository size — something in the pipeline "
        f"is super-linear: {scaling['points']}"
    )


def test_throughput_stays_above_the_floor(perf):
    scaling = perf.measure_scaling((1000,))
    rate = scaling["points"][0]["kloc_per_second"]
    assert rate >= MIN_KLOC_PER_SECOND, (
        f"{rate:.1f} kLOC/s is below the {MIN_KLOC_PER_SECOND} kLOC/s floor"
    )


def test_the_walk_prunes_vendored_trees_instead_of_reading_them(perf):
    walk = perf.measure_walk(500)
    assert walk["files_read"] == 500, (
        f"expected 500 first-party files, read {walk['files_read']} — the walk "
        "is descending into node_modules"
    )
    assert walk["files_per_second"] >= MIN_WALK_FILES_PER_SECOND


def test_hostile_input_does_not_hang_the_secret_detector():
    """A ReDoS canary.

    Every rule is a regex run over untrusted file content, so a pattern that
    backtracks exponentially turns `reposec scan` into a denial of service
    against the CI job that runs it. These are the shapes that trigger it:
    long unbroken runs, and near-misses that force the engine to explore.
    """
    from reposec.detectors.secrets import scan_file

    hostile = [
        "key = \"" + "A" * 50_000,           # unterminated assignment
        "postgres://" + "u" * 20_000 + ":",  # half a connection string
        "AKIA" + "0" * 30_000,               # a fingerprint prefix, then filler
        "-----BEGIN RSA PRIVATE KEY-----\n" + "x" * 50_000,
        ("a=b; " * 10_000),                  # many small assignment-like pairs
    ]
    for payload in hostile:
        started = time.perf_counter()
        scan_file("hostile.txt", payload)
        elapsed = time.perf_counter() - started
        assert elapsed < 2.0, (
            f"the secret rules took {elapsed:.1f}s on {len(payload)} bytes of "
            f"{payload[:24]!r} — that is a ReDoS in a rule"
        )
