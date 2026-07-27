"""Build a labeled bug-detection dataset for fine-tuning the local reviewer.

Why synthesis, not "train on good codebases": a model fine-tuned on clean code
learns to *generate* code, not to *detect* bugs. A discriminating reviewer needs
both positives (buggy code with the defect labeled) and negatives (clean code
that must yield an empty report). We manufacture both from good source files:

  negative  = the original clean function            → {"issues": []}
  positive  = one taxonomy bug injected on one line  → {"issues": [that bug]}

Each example is rendered with the SAME prompts the runtime uses
(`llm_model.prompts`), so training matches inference exactly. Mutations are
applied to source text (line numbers preserved) and kept only if the result
still parses — the bug is semantic, not a syntax error.

Usage:
    python ml/curate_dataset.py --src . --out ml/data --max 4000

Stdlib only, so it runs anywhere (no GPU / ML deps needed).
"""
from __future__ import annotations

import argparse
import ast
import json
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# The Python packages live in src/; add it so this runs as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from llm_model.prompts import DEBUG_SYSTEM_PROMPT, DEBUG_USER_PROMPT  # noqa: E402

_SKIP_DIRS = {".venv", "_archive", "__pycache__", ".git", "training", "tests"}


def annotate(content: str) -> str:
    """Render a whole file as the runtime does: right-aligned line no. + '+'."""
    out = []
    for i, text in enumerate(content.splitlines(), start=1):
        out.append(f"{i:>5} + {text}")
    return "\n".join(out)


@dataclass
class Mutation:
    bug_type: str
    severity: str
    description: str


# Each operator: (name, regex over a single line, replacement fn, Mutation meta).
# The replacement must change behaviour without breaking syntax.
def _flip(op_from: str, op_to: str):
    pat = re.compile(rf"(?<![<>=!]){re.escape(op_from)}(?!=)")
    return lambda line: pat.subn(op_to, line, count=1)


def _sub(pattern: str, repl: str):
    """A one-shot regex replacer for a single source line."""
    rx = re.compile(pattern)
    return lambda line: rx.subn(repl, line, count=1)


_OPERATORS = [
    (
        "bare_except",
        re.compile(r"^(\s*)except\s+[\w.]+(\s+as\s+\w+)?\s*:"),
        _sub(r"except\s+[\w.]+(\s+as\s+\w+)?\s*:", "except:"),
        Mutation(
            "swallowed_error", "medium",
            "Bare `except:` swallows all errors, hiding real failures.",
        ),
    ),
    (
        "flip_eq",
        re.compile(r"(?<![<>=!])==(?!=)"),
        _flip("==", "!="),
        Mutation("wrong_logic", "high", "Inverted equality: `==` flipped to `!=`."),
    ),
    (
        "flip_lt",
        re.compile(r"(?<![<>=!])<(?!=)"),
        _flip("<", ">"),
        Mutation("wrong_logic", "high", "Inverted comparison: `<` flipped to `>`."),
    ),
    (
        "flip_lte",
        re.compile(r"<="),
        _flip("<=", ">="),
        Mutation("off_by_one", "medium", "Boundary flipped: `<=` changed to `>=`."),
    ),
    (
        "invert_is_not_none",
        re.compile(r"is\s+not\s+None"),
        _sub(r"is\s+not\s+None", "is None"),
        Mutation(
            "wrong_logic", "high",
            "None-guard inverted: `is not None` became `is None`.",
        ),
    ),
    (
        "off_by_one_range",
        re.compile(r"range\(len\([^)]+\)\)"),
        _sub(r"(range\(len\([^)]+\))\)", r"\1 + 1)"),
        Mutation(
            "off_by_one", "high",
            "Off-by-one: `range(len(x))` extended by one; index overflows.",
        ),
    ),
    (
        "wrong_operator_plus",
        re.compile(r"return\s+\w+\s+\+\s+\w+"),
        _sub(r"(return\s+\w+\s+)\+(\s+\w+)", r"\1-\2"),
        Mutation("wrong_logic", "medium", "Wrong operator: `+` changed to `-`."),
    ),
]


def _iter_py_files(src: Path):
    for p in src.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _example(path: str, content: str, issues: list[dict], meta: dict) -> dict:
    user = DEBUG_USER_PROMPT.format(path=path, source=annotate(content))
    assistant = json.dumps({"issues": issues}, ensure_ascii=False)
    return {
        "messages": [
            {"role": "system", "content": DEBUG_SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "meta": meta,
    }


def _mutate_file(path: str, content: str, rng: random.Random) -> list[dict]:
    """Return up to a few buggy examples for one file (one bug each)."""
    lines = content.splitlines()
    examples: list[dict] = []
    ops = _OPERATORS[:]
    rng.shuffle(ops)
    for name, finder, replace, mut in ops:
        candidates = [i for i, ln in enumerate(lines) if finder.search(ln)]
        rng.shuffle(candidates)
        for idx in candidates:
            new_line, n = replace(lines[idx])
            if not n or new_line == lines[idx]:
                continue
            mutated = lines[:]
            mutated[idx] = new_line
            src = "\n".join(mutated)
            try:
                ast.parse(src)  # keep only semantically-buggy, still-valid code
            except SyntaxError:
                continue
            issue = {
                "line_start": idx + 1,
                "line_end": idx + 1,
                "severity": mut.severity,
                "description": mut.description,
                "suggested_fix": lines[idx].strip(),  # the original line is the fix
            }
            meta = {"label": "buggy", "bug_type": mut.bug_type, "op": name}
            examples.append(_example(path, src, [issue], meta))
            break  # one bug per operator per file
        if len(examples) >= 3:
            break
    return examples


def build(src: Path, out: Path, max_examples: int, seed: int) -> dict:
    rng = random.Random(seed)
    records: list[dict] = []
    for p in _iter_py_files(src):
        try:
            content = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not content.strip() or len(content) > 8000:
            continue  # skip empty / very large files to keep sequences short
        try:
            ast.parse(content)
        except SyntaxError:
            continue
        rel = p.as_posix()
        buggy = _mutate_file(rel, content, rng)
        # Always add the clean file as a negative — a bug detector needs plenty
        # of negatives to keep false positives down (precision is the goal).
        records.append(_example(rel, content, [], {"label": "clean", "bug_type": "none"}))
        records.extend(buggy)
        if len(records) >= max_examples:
            break

    rng.shuffle(records)
    n_val = max(1, len(records) // 10)
    val, train = records[:n_val], records[n_val:]

    out.mkdir(parents=True, exist_ok=True)
    _write_jsonl(out / "train.jsonl", train)
    _write_jsonl(out / "val.jsonl", val)

    pos = sum(1 for r in records if r["meta"]["label"] == "buggy")
    stats = {
        "total": len(records),
        "train": len(train),
        "val": len(val),
        "positives": pos,
        "negatives": len(records) - pos,
    }
    (out / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return stats


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", default=".", help="Directory of good Python source")
    ap.add_argument("--out", default="ml/data", help="Output directory")
    ap.add_argument("--max", type=int, default=4000, help="Max examples")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    stats = build(Path(args.src), Path(args.out), args.max, args.seed)
    print(
        f"Wrote {stats['total']} examples "
        f"({stats['positives']} buggy / {stats['negatives']} clean) to {args.out}/ "
        f"[train={stats['train']}, val={stats['val']}]"
    )


if __name__ == "__main__":
    main()
