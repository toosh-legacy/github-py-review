"""Minimal unified-diff parser.

We only need enough of the format to (a) know which Python files changed and
(b) reconstruct the *new-side* content of each hunk so a linter can be pointed
at the changed code, with a map back to real new-file line numbers.

Reconstruction from context + added lines is intentionally partial (we don't
have the whole file from a diff alone), so downstream callers should drop
syntax-error findings that are an artifact of the partial view.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class DiffLine:
    real_line: int  # line number in the new file
    text: str
    added: bool  # True for '+' lines, False for context ' ' lines


@dataclass
class DiffFile:
    path: str
    lines: list[DiffLine] = field(default_factory=list)


    @property
    def is_python(self) -> bool:
        return self.path.endswith(".py")

    @property
    def added_line_numbers(self) -> set[int]:
        return {ln.real_line for ln in self.lines if ln.added}

    def reconstructed_new_content(self) -> tuple[str, list[int]]:
        """Return (content, real_line_numbers) for context + added lines.

        `real_line_numbers[i]` is the new-file line number of content line i
        (0-indexed), so a linter's 1-indexed row R maps to
        `real_line_numbers[R - 1]`.
        """
        content = "\n".join(ln.text for ln in self.lines)
        real = [ln.real_line for ln in self.lines]
        return content, real


def parse_unified_diff(diff: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current: DiffFile | None = None
    new_line = 0

    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            # "+++ b/path" (or "+++ /dev/null" for deletions — skip those)
            target = raw[4:].strip()
            if target == "/dev/null":
                current = None
                continue
            path = target[2:] if target.startswith(("a/", "b/")) else target
            current = DiffFile(path=path)
            files.append(current)
            continue

        if raw.startswith("--- "):
            continue  # old-side header; ignore

        if raw.startswith("@@"):
            m = _HUNK_RE.match(raw)
            if m:
                new_line = int(m.group(1))
            continue

        if current is None:
            continue

        if raw.startswith("+"):
            current.lines.append(DiffLine(new_line, raw[1:], added=True))
            new_line += 1
        elif raw.startswith("-"):
            pass  # removed line: not present in the new file
        elif raw.startswith(" "):
            current.lines.append(DiffLine(new_line, raw[1:], added=False))
            new_line += 1
        # any other line (e.g. "\ No newline at end of file") is ignored

    return files
