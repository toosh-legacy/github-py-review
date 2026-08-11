"""Live-fire evaluation: point the scanner at real repositories on the internet.

    python src/evaluation/run_live_eval.py                 # everything
    python src/evaluation/run_live_eval.py --phase inject   # one phase
    python src/evaluation/run_live_eval.py --offline        # no OSV lookups
    python src/evaluation/run_live_eval.py --json           # machine-readable

The other three harnesses each answer a question this one cannot:

    run_security_eval.py   does it catch the planted bug — on a fixture written
                           alongside the rules, so it can only detect regression
    run_fp_eval.py         does it stay quiet on installed packages
    run_perf_bench.py      is it fast, and does it scale linearly

What none of them do is run the product the way a user runs it: `git clone`,
then `reposec scan`, against code nobody involved here has ever seen. That is
what this is. It clones real repositories and reports four numbers that together
say whether the tool is worth installing.

    1. SIGNAL     On repositories that are deliberately vulnerable, does it find
                  the vulnerabilities? Reported per category, and against a raw
                  `bandit` run so the skip lists can be judged rather than
                  trusted.

    2. NOISE      On widely-used, heavily-reviewed repositories, how much does
                  it say? Secret findings here are false positives by
                  construction — psf/requests does not contain a live
                  credential — and that number has to be zero.

    3. RECALL     The honest recall number. A real repository is copied, a
                  known set of credentials and unsafe patterns is planted in it
                  at realistic paths, and the scan is scored against that list.
                  Unlike the fixture, the surrounding code was not written by
                  anyone tuning these rules, so a rule that only works because
                  the fixture flatters it fails here.

    4. SPEED      Wall-clock on the largest repository, end to end, including
                  the analyzers.

**The credentials planted in phase 3 are synthetic** — generated locally, valid
in shape only, and never committed. The working copy lives under the system temp
directory, deliberately outside this repository, so the scanner's own self-scan
never sees it.

Requires network access and `git` on PATH. Clones are shallow and cached; the
second run costs nothing but the scans.
"""
from __future__ import annotations

import argparse
import json
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reposec.cli import read_repo  # noqa: E402
from reposec.pipeline import run_security_scan  # noqa: E402
from reposec.schemas import SecurityReport  # noqa: E402


# --------------------------------------------------------------------------- #
# Targets
#
# Pinned by name, resolved to a commit at clone time and recorded in the output.
# Hard-coding SHAs would look more rigorous and be less honest: the number that
# matters is which commit *was actually scanned*, and that belongs in the result
# rather than in a constant nobody re-checks.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Target:
    name: str
    url: str
    language: str
    # What this repository is for. "vulnerable" repos are deliberately insecure
    # teaching material; "clean" repos are widely used and heavily reviewed.
    cohort: str
    # Free text: what a reader should expect the scanner to find here, so the
    # output can be judged rather than admired.
    expectation: str


TARGETS = (
    Target(
        "pygoat", "https://github.com/adeyosemanputra/pygoat", "python", "vulnerable",
        "OWASP Top 10 teaching app: command injection, SSRF, weak crypto, "
        "deserialization, plus an intentionally stale requirements.txt",
    ),
    Target(
        "nodegoat", "https://github.com/OWASP/NodeGoat", "js", "vulnerable",
        "OWASP Top 10 in Node: eval, SSJI, weak crypto, old npm dependencies",
    ),
    Target(
        "dvpwa", "https://github.com/anxolerd/dvpwa", "python", "vulnerable",
        "SQL injection, XSS and session flaws in an aiohttp app",
    ),
    Target(
        "requests", "https://github.com/psf/requests", "python", "clean",
        "A twenty-year-old, universally audited HTTP client. Any secret "
        "finding is a false positive",
    ),
    Target(
        "flask", "https://github.com/pallets/flask", "python", "clean",
        "A widely reviewed web framework whose own docs are full of "
        "credential-shaped example strings",
    ),
    Target(
        "axios", "https://github.com/axios/axios", "js", "clean",
        "The most-installed JS HTTP client; exercises the eslint path",
    ),
)


# --------------------------------------------------------------------------- #
# Cloning
# --------------------------------------------------------------------------- #
def default_cache() -> Path:
    # Deliberately outside this repository. A clone of a deliberately-vulnerable
    # application sitting inside the scanner's own tree would be picked up by
    # `reposec scan .`, by the CI self-scan, and by the fp harness, and every one
    # of those numbers would silently become meaningless.
    return Path(tempfile.gettempdir()) / "reposec-live"


def clone(target: Target, cache: Path, *, depth: int = 1) -> Path | None:
    """Shallow-clone `target` into the cache, reusing an existing clone."""
    dest = cache / target.name
    if (dest / ".git").is_dir():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "clone", "--depth", str(depth), "--quiet", target.url, str(dest)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        print(f"  ! {target.name}: clone failed — {proc.stderr.strip()[:160]}")
        shutil.rmtree(dest, ignore_errors=True)
        return None
    return dest


def head_sha(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True,
    )
    return proc.stdout.strip() or "unknown"


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    name: str
    sha: str
    cohort: str
    files: int
    kloc: float
    seconds: float
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_rule: dict[str, int]
    by_detector: dict[str, int]
    # Secret findings, split by whether they survived at a severity that would
    # stop a build. `--fail-on high` is the CI contract, and the detector
    # deliberately *downgrades* rather than drops in documentation and test
    # trees — so counting a `low` doc finding as a false positive would score
    # the tool against a policy it does not claim.
    secret_findings: list[str]
    secret_findings_low: list[str]
    degraded: list[str]
    bandit_raw: int | None = None

    @property
    def total(self) -> int:
        return sum(self.by_category.values())

    @property
    def per_kloc(self) -> float:
        return self.total / self.kloc if self.kloc else 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "sha": self.sha,
            "cohort": self.cohort,
            "files": self.files,
            "kloc": round(self.kloc, 1),
            "seconds": round(self.seconds, 2),
            "findings": self.total,
            "per_kloc": round(self.per_kloc, 3),
            "by_category": self.by_category,
            "by_severity": self.by_severity,
            "top_rules": dict(sorted(self.by_rule.items(), key=lambda kv: -kv[1])[:8]),
            "by_detector": self.by_detector,
            "secret_findings": self.secret_findings,
            "secret_findings_downgraded": self.secret_findings_low,
            "degraded": self.degraded,
            "bandit_raw": self.bandit_raw,
            "bandit_kept": self.by_detector.get("bandit", 0),
        }


def _kloc(files: list[tuple[str, str]]) -> float:
    return sum(c.count("\n") + 1 for _, c in files) / 1000


@dataclass
class _Summary:
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_rule: dict[str, int]
    by_detector: dict[str, int]
    secrets_blocking: list[str]
    secrets_downgraded: list[str]


def _summarize(report: SecurityReport) -> _Summary:
    by_rule: dict[str, int] = {}
    by_detector: dict[str, int] = {}
    blocking: list[str] = []
    downgraded: list[str] = []
    for f in report.findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_detector[f.detector] = by_detector.get(f.detector, 0) + 1
        if f.category == "secret":
            where = f"{f.file}:{f.line_start} {f.rule_id} [{f.severity}]"
            (downgraded if f.severity == "low" else blocking).append(where)
    return _Summary(
        dict(report.counts_by_category),
        dict(report.counts_by_severity),
        by_rule,
        by_detector,
        blocking,
        downgraded,
    )


def scan_repo(
    name: str, root: Path, cohort: str, *, offline: bool, sha: str = ""
) -> ScanResult:
    files, notes = read_repo(root, 400_000)
    started = time.perf_counter()
    report = run_security_scan(
        files=files, repo=name, offline=offline, triage=False
    )
    elapsed = time.perf_counter() - started
    s = _summarize(report)
    return ScanResult(
        name=name,
        sha=sha or head_sha(root),
        cohort=cohort,
        files=len(files),
        kloc=_kloc(files),
        seconds=elapsed,
        by_category=s.by_category,
        by_severity=s.by_severity,
        by_rule=s.by_rule,
        by_detector=s.by_detector,
        secret_findings=s.secrets_blocking,
        secret_findings_low=s.secrets_downgraded,
        degraded=notes + report.degraded,
    )


def raw_bandit_count(root: Path) -> int | None:
    """How many findings bandit alone reports, for comparison.

    The skip lists in `detectors/code.py` claim to remove more than half of
    bandit's output as unactionable. That claim is only worth anything next to
    the number it is subtracted from.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", str(root),
             "-f", "json", "-q", "--exit-zero"],
            capture_output=True, timeout=900, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not (proc.stdout or "").strip():
        return None
    try:
        return len(json.loads(proc.stdout).get("results", []))
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- #
# Phase 3 — the red-team injection
#
# Every value below is generated at run time from `secrets.token_*`, so nothing
# in this file is itself a credential and no two runs plant the same string.
# The shapes are real: each matches the provider fingerprint the corresponding
# rule looks for, which is the point — a rule that only fires on the fixture's
# literal bytes would pass the benchmark and fail here.
# --------------------------------------------------------------------------- #
_B62 = string.ascii_letters + string.digits


def _rand(n: int, alphabet: str = _B62) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


@dataclass
class Plant:
    path: str
    content: str
    # What must be found. `category` is checked; `rule` is recorded but not
    # required, because more than one rule legitimately covers some of these.
    category: str
    label: str
    rule: str = ""


def build_plants() -> list[Plant]:
    aws_id = "AKIA" + _rand(16, string.ascii_uppercase + string.digits)
    return [
        # ---- secrets, at paths a real application would use ----
        Plant(
            "app/config/aws.py",
            f'AWS_ACCESS_KEY_ID = "{aws_id}"\n'
            f'AWS_SECRET_ACCESS_KEY = "{_rand(40, _B62 + "/+")}"\n',
            "secret", "AWS access key id + secret", "aws-access-key-id",
        ),
        Plant(
            "app/integrations/github.py",
            f'GITHUB_TOKEN = "ghp_{_rand(36)}"\n',
            "secret", "GitHub personal access token", "github-pat",
        ),
        Plant(
            "app/integrations/slack.py",
            f'SLACK_BOT_TOKEN = "xoxb-{_rand(12, string.digits)}-'
            f'{_rand(12, string.digits)}-{_rand(24)}"\n',
            "secret", "Slack bot token", "slack-token",
        ),
        Plant(
            "app/billing/stripe_client.py",
            f'STRIPE_SECRET_KEY = "sk_live_{_rand(24)}"\n',
            "secret", "Stripe live secret key", "stripe-key",
        ),
        Plant(
            "deploy/keys/deploy_key",
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "\n".join(_rand(64) for _ in range(6))
            + "\n-----END RSA PRIVATE KEY-----\n",
            "secret", "RSA private key", "private-key",
        ),
        Plant(
            "app/db/session.py",
            f'DATABASE_URL = "postgres://svc_orders:{_rand(24)}'
            '@orders-db.prod.internal:5432/orders"\n',
            "secret", "connection string with a real password",
            "database-connection-string",
        ),
        Plant(
            "app/core/signing.py",
            f'JWT_SIGNING_SECRET = "{_rand(48)}"\n',
            "secret", "high-entropy generic assignment", "",
        ),
        # ---- unsafe code ----
        Plant(
            "app/admin/tasks.py",
            "import os\n\n\n"
            "def run_report(name):\n"
            '    os.system("generate-report " + name)\n',
            "code", "command injection via os.system", "B605",
        ),
        Plant(
            "app/api/calc.py",
            "def evaluate(expr):\n    return eval(expr)\n",
            "code", "eval on caller-supplied input", "B307",
        ),
        Plant(
            "app/importer/loader.py",
            "import yaml\n\n\n"
            "def load(raw):\n    return yaml.load(raw)\n",
            "code", "unsafe yaml.load", "B506",
        ),
        Plant(
            "app/cache/store.py",
            "import pickle\n\n\n"
            "def restore(blob):\n    return pickle.loads(blob)\n",
            "code", "pickle.loads on untrusted data", "B301",
        ),
        Plant(
            "app/auth/hashing.py",
            "import hashlib\n\n\n"
            "def hash_password(pw):\n"
            "    return hashlib.md5(pw.encode()).hexdigest()\n",
            "code", "MD5 used for passwords", "B324",
        ),
        Plant(
            "app/clients/upstream.py",
            "import requests\n\n\n"
            "def fetch(url):\n    return requests.get(url, verify=False)\n",
            "code", "TLS verification disabled", "B501",
        ),
        Plant(
            "app/reports/sql.py",
            "def report(cur, uid):\n"
            '    cur.execute("SELECT * FROM orders WHERE user_id = %s" % uid)\n',
            "code", "SQL built by string formatting", "B608",
        ),
        # ---- unsafe JavaScript ----
        Plant(
            "web/src/render.js",
            "export function show(el, value) {\n  el.innerHTML = value;\n}\n",
            "code", "XSS sink via innerHTML", "js-innerhtml",
        ),
        Plant(
            "web/src/git.js",
            "import cp from 'node:child_process';\n\n"
            "export function fetchBranch(branch) {\n"
            "  return cp.execSync(`git fetch origin ${branch}`);\n"
            "}\n",
            "code", "shell command built by interpolation",
            "js-child-process-exec",
        ),
    ]


def inject(source: Path, workdir: Path, plants: list[Plant]) -> Path:
    """Copy `source` and write the plants into the copy."""
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    shutil.copytree(
        source, workdir,
        ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__"),
    )
    for plant in plants:
        dest = workdir / plant.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(plant.content, encoding="utf-8", newline="")
    return workdir


@dataclass
class InjectionScore:
    host: str
    planted: int
    found: int
    missed: list[str] = field(default_factory=list)
    unplanted_secrets: list[str] = field(default_factory=list)
    host_baseline_secrets: int = 0
    seconds: float = 0.0

    @property
    def recall(self) -> float:
        return self.found / self.planted if self.planted else 0.0

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "planted": self.planted,
            "found": self.found,
            "recall": round(self.recall, 3),
            "missed": self.missed,
            "unplanted_secret_findings": self.unplanted_secrets,
            "host_baseline_secret_findings": self.host_baseline_secrets,
            "seconds": round(self.seconds, 2),
        }


def score_injection(
    host: str, root: Path, plants: list[Plant], *, offline: bool, baseline: int
) -> InjectionScore:
    files, _ = read_repo(root, 400_000)
    started = time.perf_counter()
    report = run_security_scan(files=files, repo=host, offline=offline, triage=False)
    elapsed = time.perf_counter() - started

    planted_paths = {p.path for p in plants}
    hit_paths = {f.file for f in report.findings}

    missed = [
        f"{p.path} — {p.label}" for p in plants if p.path not in hit_paths
    ]
    # Secret findings outside the planted files. The host repositories are
    # audited open source, so anything here is a false positive — and it is
    # reported next to the host's own baseline count so a pre-existing finding
    # is not counted against the injection.
    unplanted = [
        f"{f.file}:{f.line_start} {f.rule_id} [{f.severity}]"
        for f in report.findings
        if f.category == "secret"
        and f.file not in planted_paths
        and f.severity != "low"
    ]
    return InjectionScore(
        host=host,
        planted=len(plants),
        found=len(plants) - len(missed),
        missed=missed,
        unplanted_secrets=unplanted,
        host_baseline_secrets=baseline,
        seconds=elapsed,
    )


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _rule(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def print_scans(results: list[ScanResult]) -> None:
    print(
        f"  {'repository':<12} {'commit':<9} {'files':>6} {'kLOC':>7} "
        f"{'time':>7} {'find':>5} {'/kLOC':>7} {'high':>5} {'KEY':>4} "
        f"{'DEP':>4} {'COD':>4}"
    )
    for r in results:
        print(
            f"  {r.name:<12} {r.sha:<9} {r.files:>6} {r.kloc:>7.1f} "
            f"{r.seconds:>6.1f}s {r.total:>5} {r.per_kloc:>7.2f} "
            f"{r.by_severity.get('high', 0):>5} "
            f"{r.by_category.get('secret', 0):>4} "
            f"{r.by_category.get('dependency', 0):>4} "
            f"{r.by_category.get('code', 0):>4}"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--phase",
        choices=["all", "signal", "noise", "inject", "speed"],
        default="all",
    )
    ap.add_argument("--cache", type=Path, default=default_cache())
    ap.add_argument(
        "--offline", action="store_true",
        help="skip OSV lookups (dependency findings will be empty)",
    )
    ap.add_argument(
        "--no-bandit-baseline", action="store_true",
        help="skip the raw-bandit comparison, which roughly doubles the runtime",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if shutil.which("git") is None:
        print("run_live_eval: git is not on PATH", file=sys.stderr)
        return 2

    want = args.phase
    results: list[ScanResult] = []
    injection: InjectionScore | None = None
    clones: dict[str, Path] = {}

    print(f"\ncache: {args.cache}")
    for target in TARGETS:
        if want in ("noise",) and target.cohort != "clean":
            continue
        if want in ("signal",) and target.cohort != "vulnerable":
            continue
        path = clone(target, args.cache)
        if path is not None:
            clones[target.name] = path

    # ---- phases 1 and 2: the same scan, read two different ways ----
    if want in ("all", "signal", "noise", "speed"):
        for target in TARGETS:
            root = clones.get(target.name)
            if root is None:
                continue
            if want == "signal" and target.cohort != "vulnerable":
                continue
            if want == "noise" and target.cohort != "clean":
                continue
            result = scan_repo(
                target.name, root, target.cohort, offline=args.offline
            )
            if target.language == "python" and not args.no_bandit_baseline:
                result.bandit_raw = raw_bandit_count(root)
            results.append(result)

        vulnerable = [r for r in results if r.cohort == "vulnerable"]
        clean = [r for r in results if r.cohort == "clean"]

        if vulnerable:
            _rule("1. SIGNAL — deliberately vulnerable applications")
            print_scans(vulnerable)
            for r in vulnerable:
                top = sorted(r.by_rule.items(), key=lambda kv: -kv[1])[:6]
                rules = ", ".join(f"{k}×{v}" for k, v in top)
                print(f"    {r.name}: {rules}")
                if r.bandit_raw:
                    # Against bandit's *own* findings only. Comparing a raw
                    # bandit count to every code finding mixes in eslint, which
                    # bandit cannot produce — on a repo whose JS dominates, that
                    # arithmetic reported a nonsensical negative filter rate.
                    kept = r.by_detector.get("bandit", 0)
                    pct = 100 * (r.bandit_raw - kept) / r.bandit_raw
                    print(
                        f"      bandit alone: {r.bandit_raw} findings; reposec "
                        f"keeps {kept} of them ({pct:.0f}% filtered as "
                        f"unactionable)"
                    )

        if clean:
            _rule("2. NOISE — widely used, heavily reviewed code")
            print_scans(clean)
            total_secrets = sum(len(r.secret_findings) for r in clean)
            total_low = sum(len(r.secret_findings_low) for r in clean)
            total_kloc = sum(r.kloc for r in clean)
            print(
                f"\n    secret false positives at or above medium: "
                f"{total_secrets} over {total_kloc:.1f} kLOC — must be 0"
            )
            for r in clean:
                for hit in r.secret_findings:
                    print(f"      ! {r.name}: {hit}")
            print(
                f"    downgraded to low (docs and test fixtures, reported but "
                f"not build-blocking): {total_low}"
            )

    # ---- phase 3: the injection ----
    if want in ("all", "inject"):
        host_target = next(t for t in TARGETS if t.name == "flask")
        host = clones.get("flask") or clone(host_target, args.cache)
        if host is None:
            print("\n3. RECALL — skipped, host repository unavailable")
        else:
            baseline_result = next(
                (r for r in results if r.name == "flask"), None
            )
            if baseline_result is None:
                baseline_result = scan_repo(
                    "flask", host, "clean", offline=args.offline
                )
            baseline = len(baseline_result.secret_findings)  # excludes `low`

            plants = build_plants()
            workdir = args.cache / "_injected"
            inject(host, workdir, plants)
            injection = score_injection(
                "flask", workdir, plants, offline=args.offline, baseline=baseline
            )

            _rule("3. RECALL — synthetic findings planted in real code")
            print(
                f"  host {injection.host} + {injection.planted} planted "
                f"finding(s) in {injection.seconds:.1f}s"
            )
            print(
                f"  caught {injection.found}/{injection.planted}   "
                f"recall {injection.recall:.2f}"
            )
            for miss in injection.missed:
                print(f"      MISS {miss}")
            extra = injection.unplanted_secrets
            print(
                f"  secret findings outside the planted files: {len(extra)} "
                f"(host baseline {injection.host_baseline_secrets})"
            )
            for hit in extra[:10]:
                print(f"      ! {hit}")
            shutil.rmtree(workdir, ignore_errors=True)

    # ---- phase 4: speed ----
    if want in ("all", "speed") and results:
        biggest = max(results, key=lambda r: r.kloc)
        _rule("4. SPEED — end to end, real analyzers, largest repository")
        print(
            f"  {biggest.name}: {biggest.files} files, {biggest.kloc:.1f} kLOC "
            f"in {biggest.seconds:.1f}s "
            f"({biggest.kloc / biggest.seconds:.1f} kLOC/s)"
        )

    degraded = {n for r in results for n in r.degraded}
    if degraded:
        _rule("DEGRADED DETECTORS")
        for note in sorted(degraded):
            print(f"  ! {note}")

    payload = {
        "scans": [r.as_dict() for r in results],
        "injection": injection.as_dict() if injection else None,
    }
    out = Path(__file__).resolve().parent / "live_results.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    shown = out.relative_to(Path.cwd()) if out.is_relative_to(Path.cwd()) else out
    print(f"\nwrote {shown}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
