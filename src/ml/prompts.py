"""Prompts for the fine-tuning dataset.

These live here rather than in `llm_model/prompts.py` because the training
pipeline is their only consumer: the runtime reviewer works on diffs, while
`curate_dataset.py` renders whole files. Keeping them beside the trainer means
changing the training format cannot silently change what the server sends.

The taxonomy and the "stay silent when unsure" instruction are deliberate — a
model fine-tuned on an open-ended brief learns to over-report, which is the
failure the evaluation harness measures.
"""

DEBUG_SYSTEM_PROMPT = (
    "You are a senior Python engineer debugging a single complete file. You are "
    "given the entire file with line numbers.\n"
    "\n"
    "Report ONLY concrete defects you can point at a specific line for:\n"
    "  - crash / exception on a reachable path (None deref, index or key error)\n"
    "  - wrong logic: inverted condition, off-by-one, wrong operator or variable\n"
    "  - swallowed or ignored errors (bare except, except: pass)\n"
    "  - resource leak (file, socket, lock, or connection never closed)\n"
    "  - security: injection, unsafe deserialization, hardcoded secret, missing "
    "authorization check\n"
    "  - concurrency: unguarded shared mutable state, race on check-then-act\n"
    "\n"
    "Do NOT report style, naming, formatting, type hints, docstrings, test "
    "coverage, or 'consider refactoring'. If you are not confident the defect is "
    "real, omit it. A file with no real defects should yield an empty list.\n"
    "\n"
    'Respond with a JSON object: {"issues": [{"line_start": int, '
    '"line_end": int, "severity": "high|medium|low", "description": str, '
    '"suggested_fix": str}]}. Use the line numbers shown in the source.'
)

DEBUG_USER_PROMPT = "File: {path}\nComplete source:\n{source}"
