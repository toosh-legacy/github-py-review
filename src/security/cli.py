"""Scan a local repository from the command line.

    python -m security.cli .                    # working tree
    python -m security.cli . --history          # + git history
    python -m security.cli . --format json      # machine-readable
    python -m security.cli . --fail-on high     # exit 1 on high findings (CI)

This is the entry point for anything the browser extension cannot do. History
scanning in particular needs a real clone: reconstructing it over the GitHub API
would take a request per blob, and the HTTP server deliberately never fetches
from a repository the caller did not send.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

_COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[90m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"

_CATEGORY_ICON = {"secret": "KEY", "dependency": "DEP", "code": "COD"}


def _read_repo(root: Path, max_bytes: int) -> list[tuple[str, str]]:
    """Read the working tree, honouring the same filters the server applies."""
    from security.common import is_scannable, looks_binary

    files: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if not is_scannable(rel):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if looks_binary(content):
            continue
        files.append((rel, content))
    return files


def _print_text(report, *, color: bool) -> None:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    print()
    print(c(report.summary, _BOLD))
    print(
        f"{report.scanned_files} file(s) scanned, {report.skipped_files} skipped, "
        f"{report.suppressed} suppressed"
    )
    for note in report.degraded:
        print(c(f"  ! {note}", _COLOR["medium"]))

    if not report.findings:
        print("\nNo findings.")
        return

    print()
    for f in report.findings:
        location = f.file if not f.line_start else f"{f.file}:{f.line_start}"
        head = c(f"{f.severity.upper():<6}", _COLOR[f.severity])
        print(f"{head} {_CATEGORY_ICON.get(f.category, '?')}  {c(location, _BOLD)}")
        print(f"       {f.title}  [{f.rule_id} via {f.detector}]")
        if f.evidence:
            print(f"       evidence: {f.evidence}")
        for line in (f.explanation or "").splitlines():
            if line.strip():
                print(f"       {line.strip()}")
        if f.suggested_fix:
            print(f"       fix: {f.suggested_fix}")
        if f.merged_from:
            print(f"       ({len(f.merged_from)} duplicate finding(s) merged)")
        print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="security.cli", description=__doc__)
    ap.add_argument("path", help="path to the repository to scan")
    ap.add_argument(
        "--history",
        action="store_true",
        help="also scan git history for secrets that were committed then deleted",
    )
    ap.add_argument(
        "--max-commits",
        type=int,
        default=1000,
        help="how far back to walk with --history (default: 1000)",
    )
    ap.add_argument(
        "--max-file-bytes", type=int, default=400_000, help="skip files larger than this"
    )
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument(
        "--fail-on",
        choices=["high", "medium", "low"],
        help="exit 1 if any finding is at or above this severity (for CI)",
    )
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    from agent.security_graph import run_security_scan

    files = _read_repo(root, args.max_file_bytes)
    report = run_security_scan(files=files, repo=root.name)

    if args.history:
        from security.history import scan_history
        from security.suppress import apply, load_rules

        history_findings, degraded = scan_history(
            str(root), max_commits=args.max_commits
        )
        # History findings go through the same suppression rules as the rest;
        # otherwise a .secscanignore'd test fixture reappears via its commits.
        history_findings, _ = apply(history_findings, load_rules(files))

        known = {(f.rule_id, f.evidence) for f in report.findings}
        new = [f for f in history_findings if (f.rule_id, f.evidence) not in known]
        report = report.model_copy(
            update={
                "findings": report.findings + new,
                "degraded": report.degraded + degraded,
                "summary": (
                    f"{report.summary} Plus {len(new)} secret(s) found only in "
                    "git history."
                    if new
                    else report.summary
                ),
            }
        )

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        _print_text(report, color=not args.no_color and sys.stdout.isatty())

    if args.fail_on:
        floor = _SEVERITY_ORDER[args.fail_on]
        blocking = [
            f for f in report.findings if _SEVERITY_ORDER.get(f.severity, 3) <= floor
        ]
        if blocking:
            print(
                f"\n{len(blocking)} finding(s) at or above '{args.fail_on}' severity.",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
