"""Detector 3 — unsafe code patterns, via bandit and eslint-plugin-security.

Both tools are run as subprocesses over a temporary copy of the submitted files,
because that is what they expect: a directory tree, not strings. Neither tool is
required at runtime — if one is missing the scan reports that detector as
degraded rather than pretending the language came back clean.

JavaScript gets a set of pattern rules alongside eslint. Some cover ground
eslint-plugin-security genuinely has no rules for — `innerHTML` and
`document.write` (XSS sinks), `createCipher` (insecure cipher construction),
`node-serialize` (insecure deserialization). The rest only run when eslint is
unavailable, tagged with a different detector name so nobody mistakes regex
matching for the real linter. Partial coverage that says so beats silent zero
coverage.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from reposec.schemas import SecurityFinding

from .common import (
    JS_SUFFIXES,
    PYTHON_SUFFIXES,
    finding_id,
    is_vendored,
)

_ESLINT_ASSETS = Path(__file__).resolve().parent / "eslint"

# Both analyzers emit UTF-8. `text=True` alone decodes with the platform default
# — cp1252 on Windows — and a single non-ASCII byte anywhere in the output kills
# the reader thread, leaving `proc.stdout` as None with a zero exit code. Any
# repository containing an emoji or an accented name would hit it, so decoding
# is pinned explicitly.
_DECODE = {"encoding": "utf-8", "errors": "replace"}

# Bandit checks that fire on ubiquitous, *correct* code and drown the findings
# that matter. Each is a prompt to go review something, not a finding:
#   B101 assert_used                      every test file in every Python repo
#   B603 subprocess_without_shell_equals_true
#                                         fires on `subprocess.run([...])` — the
#                                         recommended safe form
#   B607 start_process_with_partial_path  fires on `run(["git", ...])`; absolute
#                                         paths only matter in setuid contexts
#   B110 try_except_pass  \  swallowing an exception is a code smell, not a
#   B112 try_except_continue >  security finding, and it is everywhere.
#   B105 hardcoded_password_string  \  the secret detector owns this, and gates
#   B106 hardcoded_password_funcarg  >  it on entropy. Bandit gates it on
#   B107 hardcoded_password_default /   nothing, so it reports every
#                                       `token = "x-request-id"` in the tree —
#                                       and duplicates every real hit the
#                                       secret detector already found.
#
# These are measured, not guessed: on 420 kLOC of installed third-party packages
# the skipped rules were over half of every finding the scanner produced, none
# of them actionable. `src/evaluation/run_fp_eval.py` regenerates that number.
#
# Everything else bandit reports is security-relevant by construction, so the
# skip list stays this short deliberately.
_BANDIT_SKIP = {"B101", "B603", "B607", "B110", "B112", "B105", "B106", "B107"}

# Bandit's `blacklist` import checks, B401-B415: "this module contains a
# dangerous function". An import is not a vulnerability — calling the function
# is, and bandit has a separate check for each call that matters (B301 for
# `pickle.loads`, B310 for `urlopen`, B314 for the XML parsers, B304/B305 for
# the broken ciphers). Reporting both means every file that imports subprocess
# gets a finding it cannot act on, above the one it can.
_BANDIT_IMPORT_ADVISORIES = frozenset(f"B4{n:02d}" for n in range(1, 16))

_BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# Concrete remediation for the patterns this project is actually about, used
# verbatim when no LLM is configured to write a contextual one.
_BANDIT_FIXES = {
    "B307": (
        "Replace `eval()` with an explicit parser: `ast.literal_eval()` for "
        "literals, `json.loads()` for JSON, or a dispatch dict for command "
        "names. `eval` on any attacker-influenced string is arbitrary code "
        "execution."
    ),
    "B102": (
        "Remove `exec()`. If it is generating code from data, replace the "
        "generated code with a function that takes the data as arguments."
    ),
    "B608": (
        "Build the query with bound parameters — `cursor.execute(\"... WHERE "
        "id = %s\", (value,))` — instead of string concatenation or f-strings. "
        "Parameter binding is what makes the value data rather than SQL."
    ),
    "B301": (
        "Do not unpickle data you did not produce — `pickle.loads` executes "
        "constructor code from the payload. Use JSON, or sign the payload and "
        "verify the signature before deserializing."
    ),
    "B506": (
        "Use `yaml.safe_load()`. Plain `yaml.load()` can instantiate arbitrary "
        "Python objects from the document."
    ),
    "B324": (
        "Use SHA-256 or better for integrity, and a purpose-built password hash "
        "(bcrypt/scrypt/argon2) for passwords. MD5 and SHA-1 are broken for "
        "collision resistance."
    ),
    "B501": (
        "Enable certificate verification (`verify=True`). Disabling it removes "
        "the protection TLS exists to provide."
    ),
    "B602": (
        "Avoid `shell=True`. Pass the command as a list of arguments so the "
        "shell never parses attacker-controlled text."
    ),
}


def _safe_relpath(path: str) -> str | None:
    """Normalize a repo-relative path, rejecting anything that escapes the root.

    File contents arrive over HTTP from a browser extension, so a path like
    `../../etc/passwd` must never become a real write.
    """
    norm = path.replace("\\", "/")
    if not norm or norm.startswith("/"):  # absolute POSIX path
        return None
    if re.match(r"^[A-Za-z]:", norm):  # absolute Windows path
        return None
    norm = norm.removeprefix("./")
    if not norm or norm.startswith("../") or "/../" in norm or norm == "..":
        return None
    return norm


def _materialize(files: list[tuple[str, str]], root: Path) -> tuple[dict[str, str], int]:
    """Write files into `root`.

    Returns ({written relative path: original path}, count of files that could
    not be written). The count matters: this copies the whole tree into a temp
    directory, so on a large repository with a small `/tmp` it can run out of
    space — and a scan that silently reports fewer findings because the disk
    filled is exactly the quiet half-coverage this tool is written against.
    """
    written: dict[str, str] = {}
    failed = 0
    for path, content in files:
        rel = _safe_relpath(path)
        if rel is None:
            continue
        dest = root / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            # newline="" disables translation. Without it, content that already
            # contains CRLF becomes CRCRLF on Windows, which makes bandit fail to
            # parse the file and shifts every line number eslint reports.
            dest.write_text(content, encoding="utf-8", newline="")
        except OSError:
            failed += 1
            continue
        written[rel] = path
    return written, failed


# --------------------------------------------------------------------------- #
# bandit (Python)
# --------------------------------------------------------------------------- #
def _run_bandit(root: Path, *, timeout: int = 180) -> tuple[list[dict], str | None]:
    """Run bandit over `root`. Returns (results, error message if it failed)."""
    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "bandit",
                "-r", str(root),
                "-f", "json",
                "-q",
                "--exit-zero",
            ],
            capture_output=True,
            timeout=timeout,
            **_DECODE,
        )
    except FileNotFoundError:
        return [], "bandit is not installed (pip install bandit)"
    except subprocess.TimeoutExpired:
        return [], f"bandit timed out after {timeout}s"

    stdout = proc.stdout or ""
    if not stdout.strip():
        detail = (proc.stderr or "").strip().splitlines()
        if proc.returncode != 0:
            return [], f"bandit failed: {detail[-1] if detail else proc.returncode}"
        return [], None
    try:
        return json.loads(stdout).get("results", []), None
    except json.JSONDecodeError:
        return [], "bandit produced unreadable output"


def _bandit_findings(
    results: list[dict], root: Path, mapping: dict[str, str]
) -> list[SecurityFinding]:
    findings = []
    for r in results:
        test_id = r.get("test_id", "")
        if test_id in _BANDIT_SKIP or test_id in _BANDIT_IMPORT_ADVISORIES:
            continue
        try:
            rel = Path(r.get("filename", "")).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            continue
        original = mapping.get(rel)
        if original is None:
            continue
        line = int(r.get("line_number", 0) or 0)
        line_range = r.get("line_range") or [line]
        severity = _BANDIT_SEVERITY.get(
            str(r.get("issue_severity", "")).upper(), "medium"
        )
        # Bandit's own confidence is real signal: LOW confidence findings are
        # frequently pattern-matching artifacts, so they enter one notch lower.
        if str(r.get("issue_confidence", "")).upper() == "LOW" and severity == "high":
            severity = "medium"
        refs = [u for u in [r.get("more_info")] if isinstance(u, str)]
        findings.append(
            SecurityFinding(
                id=finding_id("code", "bandit", test_id, original, line),
                category="code",
                detector="bandit",
                rule_id=test_id,
                title=r.get("test_name", test_id).replace("_", " "),
                file=original,
                line_start=line,
                line_end=max(line, max(line_range) if line_range else line),
                detector_severity=severity,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                evidence=(r.get("code") or "").strip()[:400],
                references=refs,
                explanation=r.get("issue_text", ""),
                suggested_fix=_BANDIT_FIXES.get(test_id, ""),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# eslint-plugin-security (JavaScript / TypeScript)
# --------------------------------------------------------------------------- #
_ESLINT_SEVERITY = {2: "high", 1: "medium"}

_ESLINT_FIXES = {
    "security/detect-eval-with-expression": (
        "Remove `eval`. Parse the value (`JSON.parse`) or dispatch through an "
        "explicit map of allowed operations."
    ),
    "security/detect-child-process": (
        "Use `execFile`/`spawn` with an argument array instead of `exec` with an "
        "interpolated string, so the shell never parses user input."
    ),
    "security/detect-non-literal-require": (
        "Require modules by literal name, or map user input through an explicit "
        "allowlist before resolving."
    ),
    "security/detect-non-literal-fs-filename": (
        "Resolve the path and confirm it stays inside the intended directory "
        "before opening it, or index into an allowlist."
    ),
    "security/detect-object-injection": (
        "Validate the key against an allowlist, or use a `Map`, so a key like "
        "`__proto__` cannot reach the prototype chain."
    ),
    "security/detect-unsafe-regex": (
        "Rewrite the expression to remove nested quantifiers, or bound the input "
        "length — this pattern backtracks exponentially (ReDoS)."
    ),
    "security/detect-pseudoRandomBytes": (
        "Use `crypto.randomBytes()`; `Math.random()` is predictable and must "
        "never generate tokens, ids, or keys."
    ),
}


def eslint_user_dir() -> Path:
    """Where a user-owned eslint install goes, following the XDG convention."""
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "reposec" / "eslint"


def _eslint_roots() -> list[Path]:
    """Places an eslint install may live, most specific first.

    The package directory alone is not enough. It works for the Docker image and
    for a writable virtualenv, but on a distro-managed Python it is a root-owned
    `/usr/lib/python3/dist-packages`, and in an immutable image it is read-only
    — so the documented `npm install` into site-packages either fails outright
    or drops ~300 untracked directories inside a pip-managed package, which
    `pip uninstall` will not clean up. A user-owned location has to be
    searchable too.
    """
    roots = []
    if override := os.environ.get("REPOSEC_ESLINT_DIR"):
        roots.append(Path(override))
    roots.append(_ESLINT_ASSETS)
    roots.append(eslint_user_dir())
    return roots


def _eslint_root() -> Path | None:
    """The first root that holds a usable eslint, or None."""
    for root in _eslint_roots():
        if (root / "node_modules" / "eslint" / "bin" / "eslint.js").is_file():
            return root
    return None


def _eslint_binary() -> Path | None:
    root = _eslint_root()
    if root is None:
        return None
    return root / "node_modules" / "eslint" / "bin" / "eslint.js"


def _write_scan_config(root: Path, assets: Path) -> Path:
    """Re-export the installed config from inside the scan directory.

    ESLint 9 skips any file outside its config's base path, so pointing it at
    `src/reposec/detectors/eslint/eslint.config.mjs` while linting a temp
    directory silently produces zero findings. Re-exporting from inside the temp
    tree makes that tree the base path; the config itself still resolves the
    plugin against its real location.

    `assets` is the root the eslint install was actually found in, which is not
    always the package directory — it resolves the plugin relative to itself, so
    re-exporting the package's copy while running a user-directory install would
    look in the wrong `node_modules`.
    """
    config_source = assets / "eslint.config.mjs"
    if not config_source.is_file():
        config_source = _ESLINT_ASSETS / "eslint.config.mjs"
    source = config_source.resolve().as_uri()
    config = root / "eslint.config.mjs"
    config.write_text(f'export {{ default }} from "{source}";\n', encoding="utf-8")
    return config


def _run_eslint(root: Path, *, timeout: int = 240) -> tuple[list[dict], str | None]:
    assets = _eslint_root()
    if assets is None:
        return [], (
            "code(js): eslint-plugin-security not installed — run "
            "`reposec install-eslint` to enable it"
        )
    binary = assets / "node_modules" / "eslint" / "bin" / "eslint.js"
    node = shutil.which("node")
    if node is None:
        return [], "code(js): node not found on PATH — Node.js is required for eslint"
    try:
        config = _write_scan_config(root, assets)
        proc = subprocess.run(
            [
                node, str(binary),
                "--config", str(config),
                "--format", "json",
                "--no-error-on-unmatched-pattern",
                ".",
            ],
            capture_output=True,
            timeout=timeout,
            # The scan directory is the base path, so the files are in scope.
            cwd=str(root),
            env={**os.environ, "NODE_OPTIONS": ""},
            **_DECODE,
        )
    except subprocess.TimeoutExpired:
        return [], f"code(js): eslint timed out after {timeout}s"
    except OSError as exc:
        return [], f"code(js): eslint could not run ({type(exc).__name__})"

    stdout = proc.stdout or ""
    if not stdout.strip():
        detail = (proc.stderr or "").strip().splitlines()
        return [], f"code(js): eslint failed ({detail[-1] if detail else 'no output'})"
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return [], "code(js): eslint produced unreadable output"


def _eslint_findings(
    payload: list[dict], root: Path, mapping: dict[str, str]
) -> list[SecurityFinding]:
    findings = []
    for entry in payload:
        try:
            rel = Path(entry.get("filePath", "")).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            continue
        original = mapping.get(rel)
        if original is None:
            continue
        for msg in entry.get("messages", []):
            rule = msg.get("ruleId") or ""
            # The config only enables security rules, but parse errors have no
            # rule id and are not findings.
            if not rule.startswith("security/"):
                continue
            line = int(msg.get("line", 0) or 0)
            severity = _ESLINT_SEVERITY.get(msg.get("severity", 1), "medium")
            findings.append(
                SecurityFinding(
                    id=finding_id("code", "eslint", rule, original, line),
                    category="code",
                    detector="eslint-plugin-security",
                    rule_id=rule,
                    title=rule.removeprefix("security/").replace("-", " "),
                    file=original,
                    line_start=line,
                    line_end=int(msg.get("endLine", line) or line),
                    detector_severity=severity,  # type: ignore[arg-type]
                    severity=severity,  # type: ignore[arg-type]
                    evidence="",
                    explanation=msg.get("message", ""),
                    suggested_fix=_ESLINT_FIXES.get(rule, ""),
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Extra JS pattern rules.
#
# Two jobs, distinguished by the `always` flag:
#
#   always=True   eslint-plugin-security has no rule for these, but they are
#                 squarely in scope for this scanner (XSS sinks, insecure
#                 ciphers, insecure deserialization). They run alongside eslint.
#   always=False  eslint covers these properly; they only run as a fallback when
#                 eslint is unavailable, and are labelled as narrower coverage.
# --------------------------------------------------------------------------- #
_JS_PATTERN_RULES: list[tuple[bool, str, re.Pattern[str], str, str, str, str]] = [
    (
        False,
        "js-eval",
        re.compile(r"\beval\s*\(\s*(?!['\"`]\s*['\"`])"),
        "high",
        "Unsafe eval",
        "`eval()` executes whatever string it is given. If any part of that "
        "string is derived from input, this is arbitrary code execution.",
        "Replace `eval` with `JSON.parse` for data, or an explicit dispatch map.",
    ),
    (
        False,
        "js-new-function",
        re.compile(r"\bnew\s+Function\s*\("),
        "high",
        "Code construction from a string",
        "`new Function(...)` compiles a string into executable code, with the "
        "same consequences as `eval`.",
        "Define the function directly instead of building it from a string.",
    ),
    (
        # Always on. eslint-plugin-security's detect-child-process only fires
        # when it can see `require('child_process')` in scope, so an ESM
        # `import cp from 'node:child_process'` followed by
        # `cp.execSync(`git fetch ${branch}`)` goes unreported — which is most
        # modern JavaScript. The benchmark caught this as a missed planted
        # finding. Duplicates against eslint are dropped below.
        True,
        "js-child-process-exec",
        re.compile(r"\bexec(?:Sync)?\s*\(\s*[`\"'][^`\"']*\$\{|\bexec(?:Sync)?\s*\([^)]*\+"),
        "high",
        "Shell command built by string interpolation",
        "Interpolating a value into a shell command lets that value add its own "
        "commands (`; rm -rf /`). The shell, not your code, decides where the "
        "command ends.",
        "Use `execFile`/`spawn` with an argument array so no shell is involved.",
    ),
    (
        True,
        "js-innerhtml",
        re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*(?![`\"']\s*[`\"'])"),
        "medium",
        "HTML injection sink",
        "Assigning to `innerHTML` parses the value as HTML. Any attacker-"
        "controlled portion becomes markup and script in the page (XSS).",
        "Use `textContent` for text, or sanitize with DOMPurify before assigning.",
    ),
    (
        True,
        "js-document-write",
        re.compile(r"\bdocument\.write(?:ln)?\s*\("),
        "medium",
        "document.write injection sink",
        "`document.write` parses its argument as HTML into the page — the same "
        "XSS sink as `innerHTML`.",
        "Build nodes with `createElement`/`textContent` instead.",
    ),
    (
        True,
        "js-insecure-cipher",
        re.compile(r"crypto\.createCipher\s*\(|crypto\.createDecipher\s*\("),
        "high",
        "Insecure cipher construction",
        "`createCipher` derives the key from a password with a broken KDF and "
        "uses a fixed IV, so identical plaintexts encrypt identically.",
        "Use `createCipheriv` with a random IV and a key from a real KDF.",
    ),
    (
        True,
        "js-node-serialize",
        re.compile(r"\bunserialize\s*\(|node-serialize"),
        "high",
        "Insecure deserialization",
        "`node-serialize`'s `unserialize()` executes functions embedded in the "
        "payload — untrusted input here is remote code execution.",
        "Use `JSON.parse`, and sign payloads you must round-trip.",
    ),
]


def _js_pattern_findings(
    files: list[tuple[str, str]], *, eslint_ran: bool
) -> list[SecurityFinding]:
    """Run the pattern rules. With eslint working, only the ones it can't do."""
    detector = "js-pattern" if eslint_ran else "js-regex-fallback"
    findings: list[SecurityFinding] = []
    for path, content in files:
        lines = content.splitlines()
        for always, rule_id, pattern, severity, title, why, fix in _JS_PATTERN_RULES:
            if eslint_ran and not always:
                continue
            seen: set[int] = set()
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                if line in seen:
                    continue
                seen.add(line)
                evidence = lines[line - 1].strip()[:200] if line <= len(lines) else ""
                findings.append(
                    SecurityFinding(
                        id=finding_id("code", "js-pattern", rule_id, path, line),
                        category="code",
                        detector=detector,
                        rule_id=rule_id,
                        title=title,
                        file=path,
                        line_start=line,
                        line_end=line,
                        detector_severity=severity,  # type: ignore[arg-type]
                        severity=severity,  # type: ignore[arg-type]
                        evidence=evidence,
                        explanation=why,
                        suggested_fix=fix,
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
# Both analyzers are chunked, for the same reason: one subprocess over the whole
# tree means one timeout loses every finding in that language, repository-wide,
# and says so in a single degraded line nobody reads. Chunking makes a timeout
# cost one chunk, and names how many files that chunk held.
#
# Large enough that the per-invocation cost of starting the analyzer stays
# amortised, small enough that losing a chunk is a dent rather than the whole
# language. Measured: bandit runs ~2,000 ordinary source files well inside the
# budget below. The eslint chunk is half that, because eslint pays a ~1s process
# start and then parses with a full JS toolchain rather than the stdlib `ast`.
_PY_CHUNK = 2000
_JS_CHUNK = 1000


def _chunks(
    items: list[tuple[str, str]], size: int
) -> list[list[tuple[str, str]]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


# The one place an always-on pattern rule and an eslint rule describe the same
# defect. `js-child-process-exec` exists because eslint's detect-child-process
# only fires when it can see `require('child_process')` in scope, so it misses
# the ESM form — but when eslint *does* see it, both fire on the same line.
_PATTERN_TWINS = {"js-child-process-exec"}
_ESLINT_TWINS = {"security/detect-child-process"}


def _unwritable_note(language: str, count: int) -> str:
    return (
        f"code({language}): {count} file(s) could not be written to "
        f"{tempfile.gettempdir()} and were not analysed — check free space"
    )


def _scan_python(py: list[tuple[str, str]]) -> tuple[list[SecurityFinding], list[str]]:
    findings: list[SecurityFinding] = []
    degraded: list[str] = []
    for chunk in _chunks(py, _PY_CHUNK):
        with tempfile.TemporaryDirectory(prefix="secscan-py-") as tmp:
            root = Path(tmp).resolve()
            mapping, unwritable = _materialize(chunk, root)
            if unwritable:
                degraded.append(_unwritable_note("python", unwritable))
            # The budget scales with the chunk so a slow runner does not trip it
            # on the last few files of a short final chunk.
            results, error = _run_bandit(root, timeout=60 + len(chunk) // 20)
            if error:
                degraded.append(f"code(python): {error} ({len(chunk)} file(s))")
            else:
                findings.extend(_bandit_findings(results, root, mapping))
    return findings, degraded


def _scan_js(js: list[tuple[str, str]]) -> tuple[list[SecurityFinding], list[str]]:
    linted: list[SecurityFinding] = []
    degraded: list[str] = []
    # Tracked per chunk, because with chunking "did eslint run" is no longer one
    # answer for the language: a 6,000-file front end can lose one chunk to a
    # timeout and analyse the other five properly. The pattern rules widen to
    # cover eslint's ground only over the files eslint actually failed on —
    # widening them everywhere would report the same line twice for the chunks
    # that succeeded.
    unlinted: list[tuple[str, str]] = []
    failures: dict[str, int] = {}
    for chunk in _chunks(js, _JS_CHUNK):
        with tempfile.TemporaryDirectory(prefix="secscan-js-") as tmp:
            root = Path(tmp).resolve()
            mapping, unwritable = _materialize(chunk, root)
            if unwritable:
                degraded.append(_unwritable_note("js", unwritable))
            payload, error = _run_eslint(root, timeout=120 + len(chunk) // 8)
            if error:
                # Accumulated by cause rather than appended per chunk: when
                # eslint is simply not installed, every chunk fails the same way,
                # and a 6,000-file front end emitted the same sentence six times.
                # One line per distinct cause, carrying the total it cost.
                failures[error] = failures.get(error, 0) + len(chunk)
                unlinted.extend(chunk)
            else:
                linted.extend(_eslint_findings(payload, root, mapping))

    for error, count in failures.items():
        degraded.append(
            f"{error} ({count} file(s)); fell back to regex checks with "
            "narrower coverage"
        )

    # The always-on pattern rules cover XSS sinks, insecure ciphers and insecure
    # deserialization, which eslint-plugin-security has no rules for.
    unlinted_paths = {p for p, _ in unlinted}
    patterns = _js_pattern_findings(
        [(p, c) for p, c in js if p not in unlinted_paths], eslint_ran=True
    )
    patterns += _js_pattern_findings(unlinted, eslint_ran=False)

    # Drop a pattern finding only where eslint reported *the same problem* on
    # the same line. Deduplicating on position alone is wrong in both
    # directions, and both were live bugs:
    #
    #   `el.innerHTML = data[key]` — eslint reports detect-object-injection,
    #   the noisiest rule in the plugin; the position-only rule then discarded
    #   `js-innerhtml`, so the XSS sink was replaced by the noise;
    #
    #   `el.innerHTML = eval(u)` — two pattern rules on one line collapsed into
    #   whichever ran first. That is two problems.
    #
    # The overlap is one pair. The other always-on rules exist precisely because
    # eslint-plugin-security has no rule for what they find.
    equivalent = {(f.file, f.line_start) for f in linted if f.rule_id in _ESLINT_TWINS}
    findings = list(linted)
    findings.extend(
        f
        for f in patterns
        if f.rule_id not in _PATTERN_TWINS
        or (f.file, f.line_start) not in equivalent
    )
    return findings, degraded


def scan_code(files: list[tuple[str, str]]) -> tuple[list[SecurityFinding], list[str]]:
    """Run bandit over Python files and eslint-plugin-security over JS/TS files.

    Returns (findings, degraded). `degraded` names any language, or any chunk of
    one, whose real analyzer could not run.
    """
    py = [(p, c) for p, c in files if p.endswith(PYTHON_SUFFIXES) and not is_vendored(p)]
    js = [(p, c) for p, c in files if p.endswith(JS_SUFFIXES) and not is_vendored(p)]

    findings: list[SecurityFinding] = []
    degraded: list[str] = []
    for found, notes in (_scan_python(py), _scan_js(js) if js else ([], [])):
        findings.extend(found)
        degraded.extend(notes)
    return findings, degraded
