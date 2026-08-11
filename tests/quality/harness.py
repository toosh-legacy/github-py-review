"""Import the evaluation scripts as modules.

Everything under `src/evaluation/` is a script rather than a package — on
purpose, so each one can be run directly with no install and no import root to
remember. That leaves the tests needing a way in. This is it, and it is the only
one: the quality suite scores exactly the code the scripts run, so a number in
CI and a number on a laptop cannot come from two different implementations.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

EVAL = Path(__file__).resolve().parents[2] / "src" / "evaluation"


def load_harness(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, EVAL / f"{name}.py")
    if spec is None or spec.loader is None:  # pragma: no cover - packaging error
        raise ImportError(f"no evaluation harness named {name} in {EVAL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
