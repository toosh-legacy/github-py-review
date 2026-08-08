"""Evaluation harness.

Runs the review agent over a labeled benchmark and reports whether it catches
the real bugs (recall), how often it fires on clean PRs (false-positive rate),
plus avg tokens and p95 latency. Writes `results.json` next to this file and
prints a table for the README / Streamlit "Evaluation results" tab.

    python src/ml/evaluation/run_eval.py   # from the repo root

Runs the agent in-process. With no reviewer configured it falls back to the mock,
which fires on every change — so the false-positive rate is only meaningful once
a real reviewer (local or OpenAI) is configured. The static-analysis findings
(ruff) are real in either mode.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parents[1]))  # the Python packages live in src/

from agent.graph import run_review_graph  # noqa: E402

_LINE_TOLERANCE = 3  # a bug is "caught" if flagged within N lines of the label


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return ordered[k]


def _caught(report, bug: dict) -> bool:
    for i in report.issues:
        if i.file == bug["file"] and abs(i.line_start - bug["line"]) <= _LINE_TOLERANCE:
            return True
    return False


def main() -> None:
    dataset = json.loads((HERE / "benchmark_dataset.json").read_text())

    caught = missed = false_pos = clean_total = buggy_total = 0
    tokens: list[int] = []
    latencies: list[float] = []
    rows = []

    for entry in dataset:
        report = run_review_graph(diff=entry["diff"])
        tokens.append(report.tokens_used)
        latencies.append(report.latency_ms)

        if entry["type"] == "buggy":
            buggy_total += 1
            hit = _caught(report, entry["bug"])
            caught += hit
            missed += not hit
            outcome = "caught" if hit else "MISSED"
        else:
            clean_total += 1
            fp = len(report.issues) > 0
            false_pos += fp
            outcome = "false-positive" if fp else "clean"
        rows.append((entry["id"], entry["type"], outcome, len(report.issues)))

    recall = caught / buggy_total if buggy_total else 0.0
    precision = caught / (caught + false_pos) if (caught + false_pos) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate = false_pos / clean_total if clean_total else 0.0
    results = {
        "bugs_caught": caught,
        "bugs_missed": missed,
        "false_positives": false_pos,
        "buggy_total": buggy_total,
        "clean_total": clean_total,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(fp_rate, 3),
        "avg_tokens": round(sum(tokens) / len(tokens), 1) if tokens else 0,
        "p95_latency_ms": _percentile(latencies, 95),
        "per_entry": rows,
    }
    (HERE / "results.json").write_text(json.dumps(results, indent=2))

    print(f"{'id':<20} {'type':<7} {'outcome':<15} issues")
    print("-" * 52)
    for rid, typ, outcome, n in rows:
        print(f"{rid:<20} {typ:<7} {outcome:<15} {n}")
    print("-" * 52)
    print(
        f"caught {caught}/{buggy_total}  missed {missed}  "
        f"false-positives {false_pos}/{clean_total}"
    )
    print(
        f"recall {recall:.2f}  precision {precision:.2f}  F1 {f1:.2f}  "
        f"FP-rate {fp_rate:.2f}  avg-tokens {results['avg_tokens']}  "
        f"p95 {results['p95_latency_ms']}ms"
    )
    print("\nWrote", HERE / "results.json")


if __name__ == "__main__":
    main()
