from agent.nodes import run_static_analysis


def test_flags_unused_import_and_var_on_added_lines(sample_diff):
    issues = run_static_analysis(sample_diff)
    codes = {i.description.split(":")[0] for i in issues}
    assert "F401" in codes  # unused import `sys`
    assert "F841" in codes  # unused local `x`


def test_only_reports_added_lines(sample_diff):
    issues = run_static_analysis(sample_diff)
    # The unused `import os` is on context line 1 and must not be reported.
    assert all(i.line_start in {2, 5} for i in issues)


def test_non_python_files_ignored():
    diff = (
        "diff --git a/readme.md b/readme.md\n"
        "--- a/readme.md\n+++ b/readme.md\n"
        "@@ -1 +1,2 @@\n hi\n+import os\n"
    )
    assert run_static_analysis(diff) == []
