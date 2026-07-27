"""Whole-file debug flow: DiffFile.from_full_file, full-file ruff, and the route.

The debug path reuses the reviewer/verifier machinery but over a complete file
instead of a diff — every line counts as 'added', and E999 syntax errors are
real (not partial-view artifacts), so they are kept.
"""
from agent.diff_utils import DiffFile
from agent.nodes import run_static_analysis, run_static_analysis_on_file
from llm_model.mock_model import MockReviewLLM

BUGGY_FILE = (
    "import os\n"
    "\n"
    "\n"
    "def read(path):\n"
    "    try:\n"
    "        f = open(path)\n"
    "        return f.read()\n"
    "    except:\n"
    "        pass\n"
)

SYNTAX_ERROR_FILE = "def broken(:\n    pass\n"


def test_from_full_file_marks_every_line_added():
    df = DiffFile.from_full_file("a.py", "x = 1\ny = 2\n")
    assert df.is_python
    assert df.added_line_numbers == {1, 2}
    content, real = df.reconstructed_new_content()
    assert content == "x = 1\ny = 2"
    assert real == [1, 2]


def test_from_full_file_empty_content():
    df = DiffFile.from_full_file("a.py", "")
    assert df.added_line_numbers == set()
    assert df.reconstructed_new_content() == ("", [])


def test_full_file_ruff_flags_real_findings():
    issues = run_static_analysis_on_file("read.py", BUGGY_FILE)
    codes = {i.description.split(":", 1)[0] for i in issues}
    # F401 unused `os`, E722 bare except — both real, both on real line numbers.
    assert "F401" in codes
    assert "E722" in codes
    assert all(1 <= i.line_start <= BUGGY_FILE.count("\n") for i in issues)


def test_full_file_ruff_keeps_syntax_errors_but_diff_path_drops_them():
    # Whole-file path keeps E999 (a real defect when debugging a file)...
    file_issues = run_static_analysis_on_file("bad.py", SYNTAX_ERROR_FILE)
    assert any(i.description.startswith("E999") for i in file_issues)
    # ...while the diff path drops E999 (usually a partial-view artifact).
    diff = (
        "--- a/bad.py\n+++ b/bad.py\n@@ -0,0 +1,2 @@\n"
        "+def broken(:\n+    pass\n"
    )
    assert not any(i.description.startswith("E999") for i in run_static_analysis(diff))


def test_full_file_ruff_ignores_non_python():
    assert run_static_analysis_on_file("notes.txt", "not python at all") == []


def test_mock_debug_file_returns_low_severity_finding():
    df = DiffFile.from_full_file("a.py", BUGGY_FILE)
    issues, tokens = MockReviewLLM().debug_file(df)
    assert tokens == 0
    assert len(issues) == 1
    assert issues[0].severity == "low"
    assert issues[0].line_start in df.added_line_numbers


def test_debug_file_route_returns_report_contract(client):
    r = client.post("/debug/file", json={"path": "read.py", "content": BUGGY_FILE})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"summary", "issues", "tokens_used", "latency_ms"}
    assert body["issues"]
    issue = body["issues"][0]
    assert set(issue) == {
        "file",
        "line_start",
        "line_end",
        "severity",
        "description",
        "suggested_fix",
    }
    assert issue["severity"] in {"high", "medium", "low"}


def test_debug_file_persists_and_history_reads(client):
    created = client.post(
        "/debug/file/full", json={"path": "read.py", "content": BUGGY_FILE}
    ).json()
    rid = created["id"]
    assert created["source"] == "file"

    fetched = client.get(f"/reviews/{rid}").json()
    assert fetched["id"] == rid
    assert fetched["report"]["issues"] == created["report"]["issues"]


def test_debug_file_clean_file_has_no_findings_from_ruff(client):
    clean = "def add(a, b):\n    return a + b\n"
    body = client.post("/debug/file", json={"path": "ok.py", "content": clean}).json()
    # ruff finds nothing here; only the mock reviewer's single low note remains.
    assert all(i["description"].startswith("Mock reviewer") for i in body["issues"])
