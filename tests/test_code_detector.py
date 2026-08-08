"""Unsafe-code detector: bandit for Python, eslint (or a labelled fallback) for JS."""
from __future__ import annotations

import pytest

from reposec.detectors import code
from reposec.detectors.code import _safe_relpath, scan_code

VULNERABLE_PY = """\
import pickle
import hashlib


def get_user(conn, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchall()


def load(blob):
    return pickle.loads(blob)


def calculate(expr):
    return eval(expr)


def digest(value):
    return hashlib.md5(value).hexdigest()
"""

VULNERABLE_JS = """\
function render(el, data) {
  el.innerHTML = data.html;
  return eval(data.expr);
}

const crypto = require("crypto");
const c = crypto.createCipher("aes-256-cbc", password);
"""


@pytest.fixture(scope="module")
def python_findings():
    findings, degraded = scan_code([("app/db.py", VULNERABLE_PY)])
    if any("python" in d for d in degraded):
        pytest.skip("bandit is not installed in this environment")
    return findings


@pytest.mark.parametrize(
    ("rule_id", "what"),
    [
        ("B608", "SQL built by string concatenation"),
        ("B301", "insecure deserialization (pickle)"),
        ("B307", "unsafe eval"),
        ("B324", "weak hash"),
    ],
)
def test_bandit_catches_the_target_patterns(python_findings, rule_id, what):
    assert rule_id in {f.rule_id for f in python_findings}, what


def test_bandit_findings_map_back_to_the_submitted_path(python_findings):
    # Files are materialized into a temp directory to run bandit; the finding
    # must come back pointing at the path the caller sent, not the temp copy.
    assert {f.file for f in python_findings} == {"app/db.py"}
    assert all(f.category == "code" for f in python_findings)
    assert all(f.detector == "bandit" for f in python_findings)
    assert all(f.line_start > 0 for f in python_findings)


def test_bandit_findings_carry_a_concrete_fix(python_findings):
    sql = next(f for f in python_findings if f.rule_id == "B608")
    assert "bound parameters" in sql.suggested_fix


def test_assert_used_is_not_reported():
    src = "def test_a():\n    assert 1 == 1\n"
    findings, degraded = scan_code([("tests/test_x.py", src)])
    if any("python" in d for d in degraded):
        pytest.skip("bandit is not installed in this environment")
    assert "B101" not in {f.rule_id for f in findings}


def test_clean_python_produces_nothing():
    clean = "def add(a, b):\n    return a + b\n"
    findings, degraded = scan_code([("app/math.py", clean)])
    if any("python" in d for d in degraded):
        pytest.skip("bandit is not installed in this environment")
    assert findings == []


def test_javascript_is_covered_by_eslint_or_a_labelled_fallback():
    findings, degraded = scan_code([("web/main.js", VULNERABLE_JS)])
    js = [f for f in findings if f.file == "web/main.js"]
    assert js, "the JS half produced no findings at all"
    rules = {f.rule_id for f in js}

    if any(f.detector == "js-regex-fallback" for f in js):
        # eslint-plugin-security isn't installed: the user must be told that
        # coverage is narrower, not left thinking the linter ran.
        assert any("eslint" in d for d in degraded)
        assert any("fell back" in d for d in degraded)
        assert "js-eval" in rules
    else:
        assert "security/detect-eval-with-expression" in rules
        assert not any("js(" in d or "code(js)" in d for d in degraded)


def test_eval_is_caught_in_typescript_too():
    findings, degraded = scan_code([("web/app.ts", "const x: string = eval(y);\n")])
    if any("code(js)" in d for d in degraded):
        pytest.skip("eslint-plugin-security is not installed in this environment")
    assert "security/detect-eval-with-expression" in {f.rule_id for f in findings}


def test_patterns_eslint_does_not_cover_are_always_checked():
    # eslint-plugin-security has no rule for XSS sinks, insecure cipher
    # construction, or node-serialize, so these must fire whether or not the
    # linter ran — they are the JS half of the categories this scanner targets.
    source = (
        "el.innerHTML = data.html;\n"
        "document.write(data.raw);\n"
        "const c = crypto.createCipher('aes-256-cbc', pw);\n"
        "const o = unserialize(payload);\n"
    )
    findings, _ = scan_code([("web/render.js", source)])
    assert {
        "js-innerhtml",
        "js-document-write",
        "js-insecure-cipher",
        "js-node-serialize",
    } <= {f.rule_id for f in findings}


def test_vendored_files_are_not_scanned():
    findings, _ = scan_code([("node_modules/pkg/index.js", VULNERABLE_JS)])
    assert findings == []


@pytest.mark.parametrize(
    "path",
    [
        "../../../etc/passwd",
        "/etc/passwd",
        "\\etc\\passwd",
        "a/../../b.py",
        "C:/Windows/x.py",
        "",
    ],
)
def test_path_traversal_is_rejected_before_anything_is_written(path):
    # File contents arrive over HTTP from a browser extension; a path that
    # escapes the temp root must never become a real write.
    assert _safe_relpath(path) is None


def test_ordinary_paths_are_normalized():
    assert _safe_relpath("app/db.py") == "app/db.py"
    assert _safe_relpath("app\\db.py") == "app/db.py"
    assert _safe_relpath("./app/db.py") == "app/db.py"


def test_missing_bandit_degrades_instead_of_reporting_clean(monkeypatch):
    monkeypatch.setattr(
        code, "_run_bandit", lambda root: ([], "bandit is not installed")
    )
    findings, degraded = scan_code([("app/db.py", VULNERABLE_PY)])
    assert findings == []
    assert any("code(python)" in d for d in degraded)
