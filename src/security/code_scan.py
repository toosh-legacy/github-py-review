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

from schemas import SecurityFinding

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

# B101 (assert_used) fires on every test file in every Python repo and is not
# what anyone means by "unsafe code pattern". Everything else bandit reports is
# security-relevant by construction.
_BANDIT_SKIP = {"B101"}

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
    "B105": (
        "Move the credential out of source into an environment variable or "
        "secrets manager, and rotate the existing value."
    ),
    "B106": (
        "Pass the password in from configuration rather than as a literal "
        "argument, and rotate the existing value."
    ),
    "B107": (
        "Remove the credential default; require it to be supplied explicitly "
        "so a missing config fails loudly instead of using a known password."
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


def _materialize(files: list[tuple[str, str]], root: Path) -> dict[str, str]:
    """Write files into `root`, returning {written relative path: original path}."""
    written: dict[str, str] = {}
    for path, content in files:
        rel = _safe_relpath(path)
        if rel is None:
            continue
        dest = root / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
        except OSError:
            continue
        written[rel] = path
    return written


# --------------------------------------------------------------------------- #
# bandit (Python)
# --------------------------------------------------------------------------- #
def _run_bandit(root: Path) -> tuple[list[dict], str | None]:
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
            timeout=180,
            **_DECODE,
        )
    except FileNotFoundError:
        return [], "bandit is not installed (pip install bandit)"
    except subprocess.TimeoutExpired:
        return [], "bandit timed out"

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
        if test_id in _BANDIT_SKIP:
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


def _eslint_binary() -> Path | None:
    binary = _ESLINT_ASSETS / "node_modules" / "eslint" / "bin" / "eslint.js"
    return binary if binary.is_file() else None


def _write_scan_config(root: Path) -> Path:
    """Re-export the checked-in config from inside the scan directory.

    ESLint 9 skips any file outside its config's base path, so pointing it at
    `src/security/eslint/eslint.config.mjs` while linting a temp directory
    silently produces zero findings. Re-exporting from inside the temp tree
    makes that tree the base path; the config itself still resolves the plugin
    against its real location.
    """
    source = (_ESLINT_ASSETS / "eslint.config.mjs").resolve().as_uri()
    config = root / "eslint.config.mjs"
    config.write_text(f'export {{ default }} from "{source}";\n', encoding="utf-8")
    return config


def _run_eslint(root: Path) -> tuple[list[dict], str | None]:
    binary = _eslint_binary()
    if binary is None:
        return [], (
            "code(js): eslint-plugin-security not installed — run "
            "`npm install` in src/security/eslint/ to enable it"
        )
    node = shutil.which("node")
    if node is None:
        return [], "code(js): node not found on PATH — Node.js is required for eslint"
    try:
        config = _write_scan_config(root)
        proc = subprocess.run(
            [
                node, str(binary),
                "--config", str(config),
                "--format", "json",
                "--no-error-on-unmatched-pattern",
                ".",
            ],
            capture_output=True,
            timeout=240,
            # The scan directory is the base path, so the files are in scope.
            cwd=str(root),
            env={**os.environ, "NODE_OPTIONS": ""},
            **_DECODE,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
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
        False,
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
def scan_code(files: list[tuple[str, str]]) -> tuple[list[SecurityFinding], list[str]]:
    """Run bandit over Python files and eslint-plugin-security over JS/TS files.

    Returns (findings, degraded). `degraded` names any language whose real
    analyzer could not run.
    """
    py = [(p, c) for p, c in files if p.endswith(PYTHON_SUFFIXES) and not is_vendored(p)]
    js = [(p, c) for p, c in files if p.endswith(JS_SUFFIXES) and not is_vendored(p)]

    findings: list[SecurityFinding] = []
    degraded: list[str] = []

    if py:
        with tempfile.TemporaryDirectory(prefix="secscan-py-") as tmp:
            root = Path(tmp).resolve()
            mapping = _materialize(py, root)
            results, error = _run_bandit(root)
            if error:
                degraded.append(f"code(python): {error}")
            else:
                findings.extend(_bandit_findings(results, root, mapping))

    if js:
        with tempfile.TemporaryDirectory(prefix="secscan-js-") as tmp:
            root = Path(tmp).resolve()
            mapping = _materialize(js, root)
            payload, error = _run_eslint(root)
            if error:
                degraded.append(
                    f"{error}; fell back to regex checks with narrower coverage"
                )
            else:
                findings.extend(_eslint_findings(payload, root, mapping))
            # The always-on pattern rules cover XSS sinks, insecure ciphers and
            # insecure deserialization, which eslint-plugin-security has no
            # rules for. When eslint didn't run they widen to cover its ground.
            findings.extend(_js_pattern_findings(js, eslint_ran=error is None))

    return findings, degraded
