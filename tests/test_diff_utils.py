from agent.diff_utils import parse_unified_diff


def test_parses_new_path_and_line_numbers(sample_diff):
    files = parse_unified_diff(sample_diff)
    assert len(files) == 1
    df = files[0]
    assert df.path == "example.py"
    assert df.is_python
    # Added lines: `import sys` (2), a blank line (3), and `x = 1` (5).
    assert df.added_line_numbers == {2, 3, 5}


def test_context_lines_are_not_marked_added(sample_diff):
    df = parse_unified_diff(sample_diff)[0]
    context = {ln.real_line for ln in df.lines if not ln.added}
    # `import os` is context on line 1, present in the new file but unchanged.
    assert 1 in context


def test_ignores_dev_null_targets():
    diff = "--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-print(1)\n"
    assert parse_unified_diff(diff) == []
