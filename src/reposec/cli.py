"""`reposec` — scan a repository for secrets, vulnerable deps, and unsafe code.

    reposec scan .                     working tree
    reposec scan . --history           + git history
    reposec scan . --fail-on high      exit 1 for CI
    reposec scan . --format sarif      upload to GitHub code scanning
    reposec doctor                     which detectors are available, and why not
    reposec install-eslint             add the JS/TS analyzer

Exit codes are the CI contract, so they are stable:

    0  scan completed, nothing at or above --fail-on
    1  findings at or above --fail-on
    2  usage error (bad path, bad arguments)
    3  a detector could not run and --strict was given
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from reposec.schemas import SecurityReport

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_DEGRADED = 3

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

_COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[90m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_CATEGORY_TAG = {"secret": "KEY", "dependency": "DEP", "code": "COD"}


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("repo-security-scanner")
    except PackageNotFoundError:
        # Running from a source checkout without an install.
        return "0.0.0+source"


# --------------------------------------------------------------------------- #
# Reading the working tree
# --------------------------------------------------------------------------- #
# The whole working tree is held in memory, and the code detector then builds a
# second filtered list of the same strings — so peak usage is roughly twice this
# number. 256 MB of source is on the order of eight million lines, far past any
# repository a person scans interactively, and it is the difference between
# "scanned the first 256 MB, here is what was skipped" and being OOM-killed with
# no output at all. Raise it with --max-total-bytes.
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024


def read_repo(
    root: Path, max_bytes: int, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
) -> tuple[list[tuple[str, str]], list[str]]:
    """Read the working tree, honouring the detectors' own filters.

    Returns (files, notes). `notes` is non-empty only when the aggregate budget
    was reached, and is reported as a degraded detector — a scan that quietly
    covered part of a repository is the exact failure this tool reports in other
    people's code.

    Directories are pruned during the walk rather than filtered afterwards. On
    this repository a naive `rglob("*")` visits ~22,000 entries to keep 161 —
    `.venv` alone is 18,000 — and stats every one of them. On a monorepo with a
    large `.git` or `node_modules` that is the difference between a scan feeling
    instant and feeling broken.
    """
    from reposec.detectors.common import VENDOR_DIRS, is_scannable, looks_binary

    files: list[tuple[str, str]] = []
    total = 0
    over_budget = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutating dirnames in place is what stops os.walk descending.
        dirnames[:] = sorted(d for d in dirnames if d not in VENDOR_DIRS)

        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if not is_scannable(rel):
                continue
            try:
                size = path.stat().st_size
                if size > max_bytes:
                    continue
                if total + size > max_total_bytes:
                    # Keep walking rather than breaking out: stat is cheap and
                    # reading is not, so this costs little and lets the note say
                    # how much of the repository went unscanned.
                    over_budget += 1
                    continue
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError, ValueError):
                # Unreadable, not UTF-8, or a broken symlink. One bad file must
                # not lose the scan.
                continue
            if looks_binary(content):
                continue
            total += size
            files.append((rel, content))

    notes: list[str] = []
    if over_budget:
        # Not `// (1024 * 1024)`: integer division reported "the 0 MB aggregate
        # budget was reached" for any budget under a megabyte, which reads as a
        # bug in the scanner rather than as a setting the user chose.
        mb = max_total_bytes / (1024 * 1024)
        budget = f"{mb:.0f} MB" if mb >= 1 else f"{max_total_bytes:,} byte"
        notes.append(
            f"read: the {budget} aggregate budget was reached — {over_budget} "
            "file(s) were not scanned; raise --max-total-bytes to cover the "
            "whole tree"
        )
    return files, notes


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _use_color(no_color: bool) -> bool:
    # Honour NO_COLOR (https://no-color.org) as well as the flag: CI logs and
    # piped output should not be full of escape sequences.
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def render_text(report: SecurityReport, *, color: bool) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out: list[str] = ["", c(report.summary, _BOLD)]
    out.append(
        c(
            f"{report.scanned_files} file(s) scanned, "
            f"{report.skipped_files} skipped, {report.suppressed} suppressed",
            _DIM,
        )
    )
    for note in report.degraded:
        out.append(c(f"  ! {note}", _COLOR["medium"]))

    if not report.findings:
        out.append("\nNo findings.")
        return "\n".join(out) + "\n"

    out.append("")
    for f in report.findings:
        location = f.file if not f.line_start else f"{f.file}:{f.line_start}"
        head = c(f"{f.severity.upper():<6}", _COLOR[f.severity])
        tag = _CATEGORY_TAG.get(f.category, "?")
        out.append(f"{head} {tag}  {c(location, _BOLD)}")
        out.append(c(f"       {f.title}  [{f.rule_id} via {f.detector}]", _DIM))
        if f.evidence:
            out.append(f"       evidence: {f.evidence}")
        for line in (f.explanation or "").splitlines():
            if line.strip():
                out.append(f"       {line.strip()}")
        if f.suggested_fix:
            out.append(f"       {c('fix:', _BOLD)} {f.suggested_fix}")
        if f.merged_from:
            out.append(c(f"       ({len(f.merged_from)} duplicate(s) merged)", _DIM))
        out.append("")
    return "\n".join(out)


def render_sarif(report: SecurityReport, root: Path) -> str:
    """SARIF 2.1.0, so `github/codeql-action/upload-sarif` can ingest a scan.

    This is what makes the tool usable on a real project: findings appear in the
    Security tab and as pull-request annotations, instead of only in a CI log
    nobody reads.
    """
    import json

    rules: dict[str, dict] = {}
    results = []

    for f in report.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("/", "-"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.explanation or f.title},
                "helpUri": f.references[0] if f.references else None,
                "properties": {
                    "category": f.category,
                    "detector": f.detector,
                    # GitHub surfaces this as the severity chip.
                    "security-severity": {
                        "high": "8.0", "medium": "5.0", "low": "2.0"
                    }[f.severity],
                },
            }
            if rules[f.rule_id]["helpUri"] is None:
                del rules[f.rule_id]["helpUri"]

        message = f.explanation or f.title
        if f.suggested_fix:
            message = f"{message}\n\nFix: {f.suggested_fix}"

        results.append(
            {
                "ruleId": f.rule_id,
                # SARIF has no "medium"; error/warning/note is the whole scale.
                "level": {"high": "error", "medium": "warning", "low": "note"}[
                    f.severity
                ],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            # A line of 0 is invalid SARIF; history findings have
                            # no meaningful line in the checked-out tree.
                            "region": {"startLine": max(1, f.line_start)},
                        }
                    }
                ],
                "partialFingerprints": {"reposecFindingId": f.id},
            }
        )

    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "reposec",
                            "informationUri": "https://github.com/toosh-legacy/github-py-review",
                            "version": _version(),
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "workingDirectory": {"uri": root.as_uri()},
                            # Degraded detectors belong in the machine-readable
                            # output too, not only in the human one.
                            "toolExecutionNotifications": [
                                {"level": "warning", "message": {"text": note}}
                                for note in report.degraded
                            ],
                        }
                    ],
                }
            ],
        },
        indent=2,
    )


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"reposec: {root} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    from reposec.pipeline import run_security_scan

    files, read_notes = read_repo(root, args.max_file_bytes, args.max_total_bytes)
    # The flags are passed down rather than written onto the settings singleton.
    # That singleton is `@lru_cache`d for the life of the process, so mutating
    # it makes one `--offline` run change every later scan — which is invisible
    # in a one-shot CLI and wrong everywhere else, including in the test suite.
    # `None` means "whatever the environment configured".
    report = run_security_scan(
        files=files,
        repo=root.name,
        offline=True if args.offline else None,
        triage=False if args.no_triage else None,
    )
    if read_notes:
        # First in the list: everything below it was measured over a partial
        # tree, so this is the note that qualifies all the others. It also makes
        # --strict exit 3, which is the right answer for a truncated scan.
        report = report.model_copy(
            update={"degraded": read_notes + report.degraded}
        )

    if args.history:
        report = _add_history(report, root, files, args.max_commits)

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    elif args.format == "sarif":
        print(render_sarif(report, root))
    else:
        print(render_text(report, color=_use_color(args.no_color)), end="")

    # Findings outrank degradation. Both exit non-zero, but when a run has a
    # leaked credential *and* a missing linter, the credential is the thing the
    # exit code should name.
    if args.fail_on:
        floor = _SEVERITY_ORDER[args.fail_on]
        blocking = [
            f for f in report.findings if _SEVERITY_ORDER.get(f.severity, 3) <= floor
        ]
        if blocking:
            print(
                f"reposec: {len(blocking)} finding(s) at or above "
                f"'{args.fail_on}' severity",
                file=sys.stderr,
            )
            if args.strict and report.degraded:
                print(
                    f"reposec: also {len(report.degraded)} detector(s) could "
                    "not run",
                    file=sys.stderr,
                )
            return EXIT_FINDINGS

    if args.strict and report.degraded:
        print(
            f"reposec: {len(report.degraded)} detector(s) could not run (--strict)",
            file=sys.stderr,
        )
        return EXIT_DEGRADED
    return EXIT_OK


def _add_history(
    report: SecurityReport, root: Path, files: list[tuple[str, str]], max_commits: int
) -> SecurityReport:
    from reposec.detectors.history import scan_history
    from reposec.detectors.suppress import apply, load_rules

    found, degraded = scan_history(str(root), max_commits=max_commits)
    # History findings go through the same suppression rules as the rest;
    # otherwise a .secscanignore'd test fixture reappears via its commits.
    found, _ = apply(found, load_rules(files))

    known = {(f.rule_id, f.evidence) for f in report.findings}
    new = [f for f in found if (f.rule_id, f.evidence) not in known]

    counts = dict(report.counts_by_severity)
    for f in new:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    categories = dict(report.counts_by_category)
    categories["secret"] = categories.get("secret", 0) + len(new)

    return report.model_copy(
        update={
            "findings": report.findings + new,
            "degraded": report.degraded + degraded,
            "counts_by_severity": counts,
            "counts_by_category": categories,
            "summary": (
                f"{report.summary} Plus {len(new)} secret(s) found only in git history."
                if new
                else report.summary
            ),
        }
    )


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report which detectors can run, and what to do about the ones that can't.

    A scanner that quietly covers half of what you think it does is worse than
    one that refuses to start, so this makes the answer a single command.
    """
    import shutil

    from reposec.config import settings
    from reposec.detectors.code import _eslint_binary, _run_bandit

    color = _use_color(args.no_color)

    def line(name: str, ok: bool, detail: str) -> str:
        mark = "ok  " if ok else "MISS"
        if color:
            mark = f"{'\033[32m' if ok else _COLOR['high']}{mark}{_RESET}"
        return f"  [{mark}] {name:<22} {detail}"

    print("\nreposec doctor\n")

    print(line("secrets", True, "built in — regex fingerprints + entropy"))

    if settings.security_offline:
        print(line("dependencies", False, "SECURITY_OFFLINE is set; OSV not queried"))
    else:
        print(line("dependencies", True, "OSV over HTTPS (package names only)"))

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        _, bandit_error = _run_bandit(Path(tmp))
    print(
        line("code (python)", bandit_error is None, bandit_error or "bandit")
        if bandit_error
        else line("code (python)", True, "bandit")
    )

    eslint = _eslint_binary()
    node = shutil.which("node")
    if eslint and node:
        print(line("code (js/ts)", True, "eslint-plugin-security"))
    elif not node:
        print(line("code (js/ts)", False, "Node not on PATH — regex fallback only"))
    else:
        print(
            line(
                "code (js/ts)",
                False,
                "not installed — run `reposec install-eslint`",
            )
        )

    backend = settings.active_backend
    if backend == "mock":
        print(line("triage (llm)", False, "no model configured — triage skipped"))
    else:
        print(line("triage (llm)", True, f"{backend}"))

    print(f"\n  reposec {_version()}\n")
    # Missing detectors are a warning, not a failure: the scan still works.
    return EXIT_OK


def cmd_install_eslint(args: argparse.Namespace) -> int:
    """Install eslint-plugin-security somewhere the user can actually write.

    The alternative, which this replaces, was `npm install` inside the installed
    package — that is `/usr/lib/python3/dist-packages` on a distro Python and
    read-only in a container image, and where it does work it leaves hundreds of
    untracked directories inside a pip-managed package.
    """
    import shutil
    import subprocess

    from reposec.detectors.code import _ESLINT_ASSETS, eslint_user_dir

    npm = shutil.which("npm")
    if shutil.which("node") is None or npm is None:
        print(
            "reposec: Node.js and npm are required — install them first "
            "(https://nodejs.org)",
            file=sys.stderr,
        )
        return EXIT_USAGE

    target = Path(args.dir).expanduser() if args.dir else eslint_user_dir()
    try:
        target.mkdir(parents=True, exist_ok=True)
        for name in ("package.json", "eslint.config.mjs"):
            shutil.copyfile(_ESLINT_ASSETS / name, target / name)
    except OSError as exc:
        print(f"reposec: cannot write to {target}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(f"installing eslint-plugin-security into {target}\n")
    command = [npm, "install", "--omit=dev", "--no-audit", "--no-fund"]
    if npm.lower().endswith((".cmd", ".bat")):
        # npm ships as a batch shim on Windows, and CreateProcess cannot run one
        # directly. Naming cmd.exe explicitly keeps every argument a literal —
        # `shell=True` would hand this string to a shell for no reason, and this
        # scanner reports that as a high-severity finding in anyone else's code.
        command = ["cmd", "/c", *command]
    proc = subprocess.run(command, cwd=str(target))
    if proc.returncode != 0:
        print("reposec: npm install failed", file=sys.stderr)
        return EXIT_USAGE

    # Checked at `target`, not through `_eslint_binary()`. The scanner searches
    # a fixed list of roots, and a `--dir` outside that list is not one of them
    # — so validating through the search reported a *successful* install as a
    # failure, exited 2, and told the user to set the variable that would have
    # made the check pass. The install itself was fine and unusable.
    if not (target / "node_modules" / "eslint" / "bin" / "eslint.js").is_file():
        print(
            f"reposec: npm succeeded but no eslint binary is under {target}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    from reposec.detectors.code import _eslint_binary

    if _eslint_binary() is None:
        # Installed correctly, somewhere the scanner does not look.
        print(
            f"\ninstalled to {target}, which is not a directory reposec "
            "searches. Point it there:\n\n"
            f"    export REPOSEC_ESLINT_DIR={target}\n\n"
            "then `reposec doctor` will report the JS/TS detector."
        )
        return EXIT_OK
    print("\nok — `reposec doctor` should now report the JS/TS detector")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="reposec",
        description=(
            "Scan a repository for exposed secrets, vulnerable dependencies, "
            "and unsafe code patterns. Detection is deterministic; an LLM, if "
            "configured, only deduplicates, ranks and explains."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  clean (or below --fail-on)\n"
            "  1  findings at or above --fail-on\n"
            "  2  usage error\n"
            "  3  a detector could not run and --strict was given\n"
        ),
    )
    ap.add_argument("--version", action="version", version=f"reposec {_version()}")
    sub = ap.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repository")
    scan.add_argument("path", nargs="?", default=".", help="repository (default: .)")
    scan.add_argument(
        "--history",
        action="store_true",
        help="also scan git history for secrets that were committed then deleted",
    )
    scan.add_argument(
        "--max-commits",
        type=int,
        default=1000,
        help="how far back to walk with --history (default: 1000)",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=int,
        default=400_000,
        help="skip files larger than this (default: 400000)",
    )
    scan.add_argument(
        "--max-total-bytes",
        type=int,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help=(
            "stop reading once the tree exceeds this many bytes, and report how "
            f"much was skipped (default: {DEFAULT_MAX_TOTAL_BYTES})"
        ),
    )
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument(
        "--fail-on",
        choices=["high", "medium", "low"],
        help="exit 1 if any finding is at or above this severity",
    )
    scan.add_argument(
        "--strict",
        action="store_true",
        help="exit 3 if any detector could not run",
    )
    scan.add_argument(
        "--offline", action="store_true", help="skip the OSV lookup entirely"
    )
    scan.add_argument(
        "--no-triage", action="store_true", help="skip the LLM stage even if configured"
    )
    scan.add_argument("--no-color", action="store_true")
    scan.set_defaults(func=cmd_scan)

    doctor = sub.add_parser(
        "doctor", help="report which detectors are available, and why not"
    )
    doctor.add_argument("--no-color", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    install = sub.add_parser(
        "install-eslint",
        help="install the JS/TS analyzer into a directory you own",
    )
    install.add_argument(
        "--dir",
        help="where to install (default: $XDG_DATA_HOME/reposec/eslint)",
    )
    install.set_defaults(func=cmd_install_eslint)

    return ap


def main(argv: list[str] | None = None) -> int:
    # Findings quote source from the repository under scan, which contains
    # whatever characters that repository contains. On a stock Windows console
    # (cp1252) a single CJK identifier in one file otherwise ends the run in a
    # UnicodeEncodeError — losing the whole scan on most non-US monorepos.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")

    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nreposec: interrupted", file=sys.stderr)
        return EXIT_USAGE
    except ValidationError as exc:
        # A typo in an environment variable — `LLM_BACKEND=Local` — otherwise
        # surfaces as twelve frames of pydantic traceback, including for
        # `--version` and `doctor`, so there is no way to diagnose it with the
        # tool itself.
        print(f"reposec: invalid configuration\n{exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 - the exit code is a contract
        # Exit 1 means "findings at or above --fail-on" and nothing else. An
        # unexpected crash must not be indistinguishable from a blocking scan,
        # because CI treats the two completely differently.
        print(f"reposec: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
