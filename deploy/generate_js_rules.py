"""Export the secret rules to JavaScript for the browser extension.

The extension runs the secret detector client-side, so the rules have to exist
in JS as well as Python. Hand-maintaining two copies guarantees they drift, and
a drifted secret scanner is one that misses things in exactly the place nobody
is looking — so the JS table is generated from `rules.py` and committed, with
`tests/test_js_rules.py` failing if the two fall out of step.

    python deploy/generate_js_rules.py

Two Python regex features do not exist in JavaScript and are translated here:

  (?i) inline flag   ->  the `i` RegExp flag
  named/verbose      ->  not used by these rules

Everything else (lookbehind, non-capturing groups, `\\b`) is supported by the
JS engines Chrome ships. Every pattern is compiled by Node before the file is
written, so an untranslatable rule fails here rather than silently never
matching in the browser.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "src" / "apps" / "extension" / "rules.generated.js"

from reposec.detectors.rules import ALL_RULES  # noqa: E402


def to_js(pattern: str) -> tuple[str, str]:
    """Return (source, flags) for a JavaScript RegExp."""
    flags = "g"  # every scan wants all matches, not just the first
    if pattern.startswith("(?i)"):
        pattern = pattern[4:]
        flags += "i"
    if "(?i)" in pattern:
        raise ValueError(f"inline (?i) outside the start is untranslatable: {pattern}")
    return pattern, flags


def validate_with_node(rules: list[dict]) -> None:
    """Compile every pattern in Node, so a bad rule fails now, not in a browser."""
    script = (
        "const rules = JSON.parse(process.argv[1]);\n"
        "const bad = [];\n"
        "for (const r of rules) {\n"
        "  try { new RegExp(r.pattern, r.flags); }\n"
        "  catch (e) { bad.push(r.id + ': ' + e.message); }\n"
        "}\n"
        "if (bad.length) { console.error(bad.join('\\n')); process.exit(1); }\n"
        "console.log(rules.length + ' patterns compile in JS');\n"
    )
    proc = subprocess.run(
        ["node", "-e", script, json.dumps(rules)],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise SystemExit(
            "these rules do not compile as JavaScript regexes:\n" + (proc.stderr or "")
        )
    print(f"  {proc.stdout.strip()}")


def main() -> int:
    rules = []
    for rule in ALL_RULES:
        pattern, flags = to_js(rule.pattern.pattern)
        rules.append(
            {
                "id": rule.id,
                "title": rule.title,
                "pattern": pattern,
                "flags": flags,
                "severity": rule.severity,
                # 0 means "fingerprint rule": a distinctive shape that needs no
                # further evidence. Non-zero gates a generic match on entropy.
                "minEntropy": rule.min_entropy,
                "group": 1 if rule.pattern.groups else 0,
                "explanation": rule.explanation,
                "remediation": rule.remediation,
                "references": list(rule.references),
            }
        )

    validate_with_node(rules)

    body = json.dumps(rules, indent=2, ensure_ascii=False)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "// GENERATED FILE — do not edit.\n"
        "//\n"
        "// Source of truth: src/reposec/detectors/rules.py\n"
        "// Regenerate:      python deploy/generate_js_rules.py\n"
        "//\n"
        "// Two copies of a secret rule set will drift, and a drifted scanner\n"
        "// misses things exactly where nobody is looking. tests/test_js_rules.py\n"
        "// fails if this file falls out of step with the Python rules.\n"
        f"export const SECRET_RULES = {body};\n",
        encoding="utf-8",
    )
    print(f"  wrote {OUT.relative_to(ROOT)} ({len(rules)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
