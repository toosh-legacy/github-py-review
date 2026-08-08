"""Dependency detector: manifest parsing, OSV mapping, and honest degradation.

The OSV network call is stubbed throughout — these tests are about whether we
read manifests correctly and turn an OSV record into an actionable finding, not
about whether osv.dev is up.
"""
from __future__ import annotations

import json

import pytest

from security import deps_scan
from security.deps_scan import (
    fixed_version_for,
    parse_manifests,
    scan_dependencies,
    severity_of,
)
from security.osv import OSVUnavailable, Package


def test_parses_pinned_requirements():
    content = "\n".join(
        [
            "# comment",
            "requests==2.19.0",
            "flask[async]==1.0.2",
            "django>=3.2          # a range, not a pin",
            "-r other.txt",
            "-e .",
            "",
        ]
    )
    m = parse_manifests([("requirements.txt", content)])
    assert {(p.name, p.version) for p in m.packages} == {
        ("requests", "2.19.0"),
        ("flask", "1.0.2"),
    }
    assert ("requirements.txt", "django") in m.unpinned


def test_requirements_line_numbers_are_reported():
    m = parse_manifests([("requirements.txt", "a==1.0\nb==2.0\n")])
    assert {p.name: p.line for p in m.packages} == {"a": 1, "b": 2}


def test_parses_pyproject_pep621_and_poetry():
    content = """
[project]
dependencies = ["requests==2.19.0", "urllib3>=1.26"]

[project.optional-dependencies]
dev = ["pytest==7.0.0"]

[tool.poetry.dependencies]
python = "^3.11"
click = "8.1.3"
rich = "^13.0"
"""
    m = parse_manifests([("pyproject.toml", content)])
    names = {(p.name, p.version) for p in m.packages}
    assert ("requests", "2.19.0") in names
    assert ("pytest", "7.0.0") in names
    assert ("click", "8.1.3") in names
    assert "python" not in {p.name for p in m.packages}
    unpinned = {n for _, n in m.unpinned}
    assert {"urllib3", "rich"} <= unpinned


def test_parses_package_lock_v3():
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/@scope/pkg": {"version": "1.0.0"},
            },
        }
    )
    m = parse_manifests([("package-lock.json", lock)])
    assert {(p.name, p.version, p.ecosystem) for p in m.packages} == {
        ("lodash", "4.17.15", "npm"),
        ("@scope/pkg", "1.0.0", "npm"),
    }


def test_parses_package_lock_v1_nested_tree():
    lock = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "minimist": {"version": "1.2.0"},
                "mkdirp": {
                    "version": "0.5.1",
                    "dependencies": {"nested": {"version": "1.0.0"}},
                },
            },
        }
    )
    m = parse_manifests([("package-lock.json", lock)])
    assert ("minimist", "1.2.0") in {(p.name, p.version) for p in m.packages}
    assert ("nested", "1.0.0") in {(p.name, p.version) for p in m.packages}


def test_parses_yarn_lock():
    content = (
        'lodash@^4.17.0:\n  version "4.17.15"\n  resolved "https://..."\n\n'
        '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n'
    )
    m = parse_manifests([("yarn.lock", content)])
    assert {(p.name, p.version) for p in m.packages} == {
        ("lodash", "4.17.15"),
        ("@scope/pkg", "1.2.3"),
    }


def test_package_json_is_ignored_when_a_lockfile_resolves_it():
    pkg = json.dumps({"dependencies": {"lodash": "^4.17.0"}})
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"version": "4.17.21"}},
        }
    )
    m = parse_manifests([("package.json", pkg), ("package-lock.json", lock)])
    # The lockfile's exact version wins; the range is not guessed at.
    assert [(p.name, p.version) for p in m.packages] == [("lodash", "4.17.21")]


def test_package_json_ranges_are_reported_as_unpinned():
    pkg = json.dumps({"dependencies": {"lodash": "^4.17.0", "left-pad": "1.3.0"}})
    m = parse_manifests([("package.json", pkg)])
    assert [(p.name, p.version) for p in m.packages] == [("left-pad", "1.3.0")]
    assert ("package.json", "lodash") in m.unpinned


def test_vendored_manifests_are_ignored():
    m = parse_manifests(
        [("node_modules/foo/package.json", '{"dependencies":{"a":"1.0.0"}}')]
    )
    assert m.packages == []


def test_duplicate_packages_are_collapsed():
    m = parse_manifests(
        [
            ("requirements.txt", "requests==2.19.0"),
            ("requirements-dev.txt", "requests==2.19.0"),
        ]
    )
    assert len(m.packages) == 1


# --------------------------------------------------------------------------- #
# OSV record → finding
# --------------------------------------------------------------------------- #
def test_severity_prefers_explicit_database_severity():
    assert severity_of({"database_specific": {"severity": "CRITICAL"}}) == "high"
    assert severity_of({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert severity_of({"database_specific": {"severity": "LOW"}}) == "low"


def test_severity_falls_back_to_cvss_then_to_medium():
    remote_rce = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }
    assert severity_of(remote_rce) == "high"
    # A record with no severity data at all must stay visible, not vanish.
    assert severity_of({"id": "PYSEC-1"}) == "medium"


def test_fixed_version_picks_the_lowest_fix_above_the_installed_version():
    vuln = {
        "affected": [
            {
                "package": {"name": "requests"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.20.0"},
                            {"fixed": "2.31.0"},
                        ]
                    }
                ],
            }
        ]
    }
    pkg = Package("requests", "2.19.0", "PyPI", "requirements.txt")
    assert fixed_version_for(vuln, pkg) == "2.20.0"

    already_patched = Package("requests", "2.31.0", "PyPI", "requirements.txt")
    assert fixed_version_for(vuln, already_patched) is None


def _stub_osv(monkeypatch, hits, details):
    monkeypatch.setattr(deps_scan, "query_batch", lambda pkgs: hits(pkgs))
    monkeypatch.setattr(deps_scan, "fetch_details", lambda ids: details)


def test_scan_builds_an_actionable_finding(monkeypatch):
    vuln = {
        "id": "GHSA-x8fr-2test-abcd",
        "aliases": ["CVE-2018-18074"],
        "summary": "Credentials leak on redirect.",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "requests"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
            }
        ],
        "references": [{"url": "https://example.invalid/advisory"}],
    }
    _stub_osv(
        monkeypatch,
        lambda pkgs: {pkgs[0]: ["GHSA-x8fr-2test-abcd"]},
        {"GHSA-x8fr-2test-abcd": vuln},
    )

    findings, degraded = scan_dependencies([("requirements.txt", "requests==2.19.0")])

    assert degraded == []
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "dependency"
    assert f.detector == "osv"
    assert f.rule_id == "CVE-2018-18074"  # CVE preferred over the GHSA id
    assert f.severity == "high"
    assert f.file == "requirements.txt"
    assert "2.20.0" in f.suggested_fix
    assert "Credentials leak on redirect." in f.explanation
    assert any("osv.dev" in r for r in f.references)


def test_scan_reports_degraded_when_osv_is_unreachable(monkeypatch):
    def boom(_pkgs):
        raise OSVUnavailable("connection refused")

    monkeypatch.setattr(deps_scan, "query_batch", boom)
    findings, degraded = scan_dependencies([("requirements.txt", "requests==2.19.0")])
    # An unreachable database must never read as "no vulnerabilities".
    assert findings == []
    assert any("OSV unreachable" in d for d in degraded)


def test_offline_mode_skips_the_lookup_and_says_so():
    findings, degraded = scan_dependencies(
        [("requirements.txt", "requests==2.19.0")], offline=True
    )
    assert findings == []
    assert any("offline" in d for d in degraded)


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ([("README.md", "hello")], "no supported manifest"),
        ([("requirements.txt", "django>=3.2\n")], "no pinned versions"),
    ],
)
def test_scan_explains_why_it_found_nothing(files, expected):
    findings, degraded = scan_dependencies(files)
    assert findings == []
    assert any(expected in d for d in degraded)
