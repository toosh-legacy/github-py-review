"""The paths that only exist on repositories bigger than any fixture.

Chunking and the aggregate read budget are both written for monorepos, and both
were dead code until this file: no test tree here has more than a couple of
thousand files, so the multi-chunk branch had never executed and the budget had
never been reached. A bound nobody has crossed is a bound nobody has tested.

Slow by construction — these generate thousands of files and run the real
analyzers over them — so they carry the `quality` marker.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reposec.detectors.code import _JS_CHUNK, _PY_CHUNK, scan_code

pytestmark = pytest.mark.quality

# A planted finding the analyzer cannot miss, and its JS equivalent. Each is put
# in the *first* and *last* generated file, so a result set containing both
# proves more than one chunk ran and reported.
_PY_FINDING = (
    "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
)
_PY_FILLER = "def add(a, b):\n    return a + b\n"
_JS_FINDING = "export function render(el, v) {\n  el.innerHTML = v;\n}\n"
_JS_FILLER = "export function add(a, b) {\n  return a + b;\n}\n"


def _tree(count: int, finding: str, filler: str, suffix: str) -> list[tuple[str, str]]:
    """`count` files, with the planted finding at both ends of the list."""
    files = [(f"pkg{i // 100}/mod_{i:05d}{suffix}", filler) for i in range(count)]
    files[0] = (files[0][0], finding)
    files[-1] = (files[-1][0], finding)
    return files


def test_bandit_findings_come_back_from_more_than_one_chunk(bandit_available):
    if not bandit_available:
        pytest.skip("bandit is not runnable in this environment")

    files = _tree(_PY_CHUNK * 2 + 100, _PY_FINDING, _PY_FILLER, ".py")
    findings, degraded = scan_code(files)

    hit_files = {f.file for f in findings}
    assert files[0][0] in hit_files, (
        "the planted finding in the first chunk was not reported"
    )
    assert files[-1][0] in hit_files, (
        f"the planted finding in the last of {len(files)} files was not "
        "reported — a single analyzer invocation is still covering the whole "
        f"tree, or a later chunk failed silently: {degraded}"
    )
    # Whatever else happened, a chunked scan must not lose the language wholesale.
    assert not any("timed out" in note for note in degraded), degraded


def test_eslint_findings_come_back_from_more_than_one_chunk():
    from reposec.detectors.code import _eslint_binary

    if _eslint_binary() is None:
        pytest.skip("eslint-plugin-security is not installed")

    files = _tree(_JS_CHUNK * 2 + 10, _JS_FINDING, _JS_FILLER, ".js")
    findings, degraded = scan_code(files)

    hit_files = {f.file for f in findings}
    assert files[0][0] in hit_files
    assert files[-1][0] in hit_files, (
        f"the planted finding in the last of {len(files)} JS files was not "
        f"reported: {degraded}"
    )


def test_one_failed_chunk_does_not_lose_the_other_chunks(monkeypatch):
    """A timeout must cost a chunk, not the language.

    This is the whole point of chunking, and it is the case that cannot be
    reached by making the input bigger — the timeout has to be induced.
    """
    from reposec.detectors import code

    calls = {"n": 0}
    real = code._run_bandit

    def fail_the_first_chunk(root, *, timeout=180):
        calls["n"] += 1
        if calls["n"] == 1:
            return [], f"bandit timed out after {timeout}s"
        return real(root, timeout=timeout)

    monkeypatch.setattr(code, "_run_bandit", fail_the_first_chunk)

    files = _tree(_PY_CHUNK + 50, _PY_FINDING, _PY_FILLER, ".py")
    findings, degraded = code.scan_code(files)

    assert calls["n"] >= 2, "the input did not span more than one chunk"
    assert any("timed out" in note for note in degraded), (
        "a failed chunk must be reported, not swallowed"
    )
    assert any(f"({_PY_CHUNK} file(s))" in note for note in degraded), (
        f"the degraded note must say how many files went unanalysed: {degraded}"
    )
    assert files[-1][0] in {f.file for f in findings}, (
        "the surviving chunk produced no findings — one timeout still loses the "
        "whole language"
    )


# --------------------------------------------------------------------------- #
# The aggregate read budget
# --------------------------------------------------------------------------- #
def test_the_read_budget_truncates_and_says_so(tmp_path: Path):
    from reposec.cli import read_repo

    body = "x = 1\n" * 200  # ~1.2 KB per file
    for i in range(200):
        (tmp_path / f"mod_{i:03d}.py").write_text(body, encoding="utf-8")

    everything, notes = read_repo(tmp_path, 400_000)
    assert len(everything) == 200
    assert notes == [], "the default budget must not truncate an ordinary tree"

    # 64 KB is roughly 53 of these files.
    partial, notes = read_repo(tmp_path, 400_000, max_total_bytes=64 * 1024)
    assert 0 < len(partial) < 200
    assert len(notes) == 1
    assert "were not scanned" in notes[0], notes
    assert str(200 - len(partial)) in notes[0], (
        f"the note must name how many files went unread: {notes[0]}"
    )


def test_a_truncated_read_is_reported_as_degraded(tmp_path: Path, capsys):
    """Truncation has to reach the report, not just the function that found it.

    A scan that quietly covered a third of a monorepo and printed "No findings"
    is the precise failure this tool exists to report in other people's code.
    """
    from reposec.cli import EXIT_DEGRADED, main

    body = "x = 1\n" * 200
    for i in range(50):
        (tmp_path / f"mod_{i:03d}.py").write_text(body, encoding="utf-8")

    code = main(
        [
            "scan", str(tmp_path),
            "--max-total-bytes", "16384",
            "--offline", "--no-triage", "--strict", "--no-color",
        ]
    )
    out = capsys.readouterr()
    assert "were not scanned" in out.out, out.out
    assert code == EXIT_DEGRADED, (
        "--strict must fail a truncated scan; a partial answer that exits 0 is "
        "indistinguishable from a clean one"
    )
