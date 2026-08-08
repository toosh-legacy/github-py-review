"""Score the security scanner against a labelled benchmark.

    python src/evaluation/run_security_eval.py            # detectors only
    python src/evaluation/run_security_eval.py --triage   # + the LLM stage

What it measures, and why precision leads:

    recall     of the planted findings, per detector — did we catch the bug
    precision  against the decoys — a scanner that fires on everything has
               perfect recall and is worthless, so this is the binding number
    F1         the two combined

The decoy set is the point. Every decoy is a false-positive mode that real
secret scanners and linters actually exhibit: AWS's documented sample key,
`${TEMPLATE}` values, parameter-bound SQL that looks like concatenation, the
word `eval` inside a string. Detection is easy; staying quiet is the hard part.

Dependencies are scored against a frozen OSV snapshot (`snapshot_osv.py`) so a
new advisory upstream cannot be mistaken for a regression here.

With --triage, the LLM stage runs too and the report adds triage lift: whether
re-ranking moved genuinely exploitable findings up, and what it cost in tokens.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

BENCH = HERE / "security_benchmark"
REPO = BENCH / "repo"
RESULTS = BENCH / "results.json"


# --------------------------------------------------------------------------- #
# Fixture loading
# --------------------------------------------------------------------------- #
def load_repo() -> list[tuple[str, str]]:
    """Read the fixture repo as (repo-relative path, content) pairs."""
    files = []
    for p in sorted(REPO.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO).as_posix()
        try:
            files.append((rel, p.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return files


def load_ground_truth() -> dict:
    return json.loads((BENCH / "ground_truth.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Offline OSV: replay the snapshot instead of hitting the network
# --------------------------------------------------------------------------- #
def install_osv_snapshot() -> None:
    """Point the dependency detector at the frozen snapshot."""
    from config import settings
    from security import deps_scan

    # The snapshot *is* the offline path, so SECURITY_OFFLINE must not also
    # short-circuit the detector — that would silently score dependencies zero
    # and look like a regression rather than a misconfigured environment.
    settings.security_offline = False

    snapshot = json.loads((BENCH / "osv_snapshot.json").read_text(encoding="utf-8"))
    hits, vulns = snapshot["hits"], snapshot["vulns"]

    def query_batch(packages):
        out = {}
        for pkg in packages:
            key = f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"
            if key in hits:
                out[pkg] = hits[key]
        return out

    deps_scan.query_batch = query_batch
    deps_scan.fetch_details = lambda ids: {i: vulns[i] for i in ids if i in vulns}


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
@dataclass
class Score:
    caught: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        total = len(self.caught) + len(self.missed)
        return len(self.caught) / total if total else 0.0

    @property
    def precision(self) -> float:
        # Precision here is "of the places we fired, how many were real",
        # measured over the labelled set: planted hits vs decoy hits.
        fired = len(self.caught) + len(self.false_positives)
        return len(self.caught) / fired if fired else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "caught": len(self.caught),
            "missed": len(self.missed),
            "false_positives": len(self.false_positives),
        }


def _near(finding, entry, tol: int) -> bool:
    return (
        finding.file == entry["file"]
        and finding.category == entry["category"]
        and abs(finding.line_start - entry["line"]) <= tol
    )


def score_locations(findings, truth: dict) -> tuple[Score, Score]:
    """Score secrets and code findings against planted sites and decoys."""
    tol = truth["line_tolerance"]
    scores = {"secret": Score(), "code": Score()}

    for entry in truth["planted"]:
        cat = entry["category"]
        hit = next(
            (
                f
                for f in findings
                if _near(f, entry, tol)
                and (not entry.get("rule_any") or f.rule_id in entry["rule_any"])
            ),
            None,
        )
        label = f"{entry['file']}:{entry['line']} {entry['why']}"
        (scores[cat].caught if hit else scores[cat].missed).append(label)

    for entry in truth["decoys"]:
        cat = entry["category"]
        hit = next((f for f in findings if _near(f, entry, tol)), None)
        if hit:
            scores[cat].false_positives.append(
                f"{entry['file']}:{entry['line']} fired {hit.rule_id} — {entry['why']}"
            )

    # A finding anywhere in a decoy file is a false positive by definition.
    for entry in truth["decoy_files"]:
        for f in findings:
            if f.file == entry["file"]:
                bucket = scores.get(f.category)
                if bucket is not None:
                    bucket.false_positives.append(
                        f"{f.file}:{f.line_start} fired {f.rule_id} — {entry['why']}"
                    )

    return scores["secret"], scores["code"]


def score_dependencies(findings, report, truth: dict) -> tuple[Score, list[str]]:
    """Score the dependency detector against the frozen snapshot."""
    spec = truth["dependencies"]
    score = Score()
    notes: list[str] = []

    dep_findings = [f for f in findings if f.category == "dependency"]
    hit_packages = {f.evidence.split(":")[1].split("@")[0].lower() for f in dep_findings}

    for name in spec["vulnerable_packages"]:
        (score.caught if name in hit_packages else score.missed).append(name)
    for name in spec["clean_packages"]:
        if name in hit_packages:
            score.false_positives.append(f"{name} has no advisories in the snapshot")

    found_cves = {f.rule_id for f in dep_findings}
    for cve in spec["must_include_cves"]:
        if cve not in found_cves:
            notes.append(f"expected {cve} in the results but it was absent")

    # An unpinned range must be reported as unresolved, never silently guessed.
    for name in spec["unresolved_packages"]:
        if name in hit_packages:
            score.false_positives.append(f"{name} is unpinned and must not be resolved")
        elif not any(name in d for d in report.degraded):
            notes.append(f"{name} is unpinned but was not reported as skipped")

    return score, notes


def score_triage_lift(before, after) -> dict:
    """Did re-ranking put genuinely exploitable findings nearer the top?

    Measured as precision@5 over the ordering: how many of the first five
    findings are ones the model judged directly exploitable. Ordering is the
    product here — nobody reads finding 40.
    """

    def p_at_5(findings) -> float:
        top = findings[:5]
        if not top:
            return 0.0
        hits = sum(1 for f in top if f.severity == "high")
        return hits / len(top)

    # The deterministic pass dedupes in both runs, so the raw merge count is
    # identical either way. Only the difference is attributable to the model.
    merged_before = sum(len(f.merged_from) for f in before)
    merged_after = sum(len(f.merged_from) for f in after)

    return {
        "high_severity_before": sum(1 for f in before if f.severity == "high"),
        "high_severity_after": sum(1 for f in after if f.severity == "high"),
        "precision_at_5_before": round(p_at_5(before), 4),
        "precision_at_5_after": round(p_at_5(after), 4),
        "findings_before": len(before),
        "findings_after": len(after),
        "merged_deterministically": merged_before,
        "merged_by_the_model": merged_after - merged_before,
        "reranked": sum(
            1
            # strict=False: triage merges duplicates, so `after` is legitimately
            # shorter. The id guard below is what keeps the pairing honest.
            for b, a in zip(
                sorted(before, key=lambda f: f.id),
                sorted(after, key=lambda f: f.id),
                strict=False,
            )
            if b.id == a.id and b.severity != a.severity
        ),
        "exploitability_labelled": sum(1 for f in after if f.exploitability),
        "triaged": sum(1 for f in after if f.triaged),
    }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _bar(label: str, score: Score) -> str:
    d = score.as_dict()
    return (
        f"  {label:<14} P {d['precision']:.2f}   R {d['recall']:.2f}   "
        f"F1 {d['f1']:.2f}    caught {d['caught']:>2}  missed {d['missed']:>2}  "
        f"FP {d['false_positives']:>2}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--triage",
        action="store_true",
        help="also run the LLM triage stage and report its lift",
    )
    ap.add_argument(
        "--live-osv", action="store_true", help="hit osv.dev, not the snapshot"
    )
    args = ap.parse_args()

    if not args.live_osv:
        install_osv_snapshot()

    from config import settings

    # Detection is what the detector score measures; the LLM must not be in it.
    settings.security_triage = False

    from agent.security_graph import run_security_scan

    files = load_repo()
    truth = load_ground_truth()

    baseline = run_security_scan(files=files, repo="benchmark/fixture")
    secret_score, code_score = score_locations(baseline.findings, truth)
    dep_score, dep_notes = score_dependencies(baseline.findings, baseline, truth)

    overall = Score(
        caught=secret_score.caught + code_score.caught + dep_score.caught,
        missed=secret_score.missed + code_score.missed + dep_score.missed,
        false_positives=(
            secret_score.false_positives
            + code_score.false_positives
            + dep_score.false_positives
        ),
    )

    print("\nDETECTION (no LLM involved)")
    print(_bar("secrets", secret_score))
    print(_bar("dependencies", dep_score))
    print(_bar("code", code_score))
    print(_bar("OVERALL", overall))

    if baseline.degraded:
        print("\n  degraded detectors:")
        for d in baseline.degraded:
            print(f"    - {d}")

    for label, items in (
        ("MISSED", overall.missed),
        ("FALSE POSITIVES", overall.false_positives),
        ("NOTES", dep_notes),
    ):
        if items:
            print(f"\n{label}")
            for i in items:
                print(f"    - {i}")

    results = {
        "detection": {
            "secrets": secret_score.as_dict(),
            "dependencies": dep_score.as_dict(),
            "code": code_score.as_dict(),
            "overall": overall.as_dict(),
        },
        "degraded": baseline.degraded,
        "missed": overall.missed,
        "false_positives": overall.false_positives,
        "notes": dep_notes,
        "latency_ms": baseline.latency_ms,
    }

    if args.triage:
        settings.security_triage = True
        triaged = run_security_scan(files=files, repo="benchmark/fixture")
        lift = score_triage_lift(baseline.findings, triaged.findings)
        lift["tokens_used"] = triaged.tokens_used
        lift["latency_ms"] = triaged.latency_ms
        lift["backend"] = settings.active_backend
        results["triage"] = lift

        print(f"\nTRIAGE LIFT ({settings.active_backend})")
        print(
            f"  findings      {lift['findings_before']} -> {lift['findings_after']}"
            f"   ({lift['merged_deterministically']} merged by rule, "
            f"{lift['merged_by_the_model']} more by the model)"
        )
        print(
            f"  precision@5   {lift['precision_at_5_before']:.2f} -> "
            f"{lift['precision_at_5_after']:.2f}"
            f"   ({lift['reranked']} severities changed)"
        )
        print(
            f"  annotated     {lift['triaged']}/{lift['findings_after']} triaged, "
            f"{lift['exploitability_labelled']} with exploitability"
        )
        print(f"  cost          {lift['tokens_used']} tokens, {lift['latency_ms']} ms")
        if settings.active_backend == "mock":
            print("  (mock backend — configure a real reviewer for a meaningful number)")

    RESULTS.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {RESULTS.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()
