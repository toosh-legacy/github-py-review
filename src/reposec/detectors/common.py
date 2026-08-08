"""Shared helpers for the detectors: ids, redaction, entropy, file filtering."""
from __future__ import annotations

import hashlib
import math
from collections import Counter

# Directories that hold code we did not write. Scanning them produces findings
# nobody can act on and swamps the real ones.
VENDOR_DIRS = {
    "node_modules",
    "vendor",
    "third_party",
    "bower_components",
    ".venv",
    "venv",
    "env",
    "site-packages",
    "dist",
    "build",
    "target",
    "out",
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "coverage",
    ".next",
    ".nuxt",
}

# Binary or generated content: nothing useful, lots of entropy false positives.
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".class", ".jar", ".pyc",
    ".map", ".min.js", ".min.css", ".snap",
)

PYTHON_SUFFIXES = (".py", ".pyi")
JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


def is_vendored(path: str) -> bool:
    return any(part in VENDOR_DIRS for part in path.replace("\\", "/").split("/"))


def is_scannable(path: str) -> bool:
    """True when `path` is worth reading at all (any detector)."""
    lower = path.lower()
    if is_vendored(lower):
        return False
    return not lower.endswith(SKIP_SUFFIXES)


def looks_binary(content: str) -> bool:
    return "\x00" in content[:8192]


def finding_id(*parts: object) -> str:
    """Stable short id for a finding, so triage can refer back to it."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]


def shannon_entropy(value: str) -> float:
    """Entropy in bits per character. Random base64 sits near 5.5-6.0; English
    prose and identifiers sit near 3.0-4.0."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(secret: str) -> str:
    """Show enough to locate the secret, never enough to use it.

    The report is stored in a database and rendered in a browser extension, so
    the raw value must not survive detection.
    """
    secret = secret.strip()
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:3]}{'*' * 8}{secret[-3:]} ({len(secret)} chars)"


def snippet(lines: list[str], line_no: int, *, context: int = 2) -> str:
    """A few lines of source around `line_no` (1-indexed), for LLM context."""
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    out = []
    for i in range(start, end):
        marker = ">" if i + 1 == line_no else " "
        out.append(f"{i + 1:>5} {marker} {lines[i][:200]}")
    return "\n".join(out)
