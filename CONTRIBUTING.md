# Contributing

## Setup

```bash
python -m venv .venv
pip install -r requirements-dev.txt
cd src/security/eslint && npm install && cd -   # enables the JS/TS detector
```

## Before you push

```bash
ruff check .
pytest
python -m security.cli . --history --fail-on high   # what CI gates on
```

CI runs the same three, plus a Docker build that asserts the image's detectors
are present.

## The one rule that matters

**Tools detect; the model judges.** A change that moves detection into a prompt
will not be merged, however well it works on your example. Detection has to be
reproducible and explainable — "bandit rule B608 fired on line 12" is something
a user can act on and argue with; "the model thought so" is not.

The model's authority is bounded in `security/triage.py:_apply`, in code rather
than in the prompt. If you widen it, the tests there should tell you why that is
hard to do safely.

## Adding a detector rule

Precision is the binding constraint. A rule that fires on correct code costs
more than the bug it catches, because the first noisy scan is what gets a
scanner uninstalled.

So a new rule needs both halves in `src/evaluation/security_benchmark/`:

1. a **planted** case in the fixture repo, proving it fires, and
2. a **decoy** — the nearest correct code that must *not* fire.

Then update `ground_truth.json` and run:

```bash
python src/evaluation/run_security_eval.py
```

`tests/test_security_benchmark.py` enforces the floors, so a rule that drops
precision fails CI rather than shipping.

For secret rules specifically: a *fingerprint* rule (a distinctive provider
prefix like `AKIA…`) needs no entropy gate. A *contextual* rule matching
`secret = "…"` is useless without one — it will fire on every string constant in
every repository.

## Conventions

- Line length 90, ruff with `E,F,I,B,UP`.
- Comments explain *why*, not what. If a line needs a comment to say what it
  does, rename something instead.
- New settings go in `config.py` with an env alias and a note in `.env.example`.
- A detector that cannot run must append to `report.degraded`. Silence is the
  one thing a security tool may not do.
