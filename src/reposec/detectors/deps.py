"""Detector 2 — vulnerable dependencies, via manifest parsing + the OSV API.

Manifests are parsed for *resolved* versions and each (package, version) pair is
checked against OSV (https://osv.dev), which aggregates GHSA, PySec, and the CVE
feeds. No LLM involvement: a dependency is either in a vulnerable range or it
isn't.

Lockfiles are preferred over manifests because they pin exact versions.
`package.json` carries ranges (`^1.2.3`) that only the lockfile resolves, so a
range is reported as unpinned rather than guessed at — checking the wrong
version is worse than checking nothing.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass

from reposec.schemas import SecurityFinding

from .common import finding_id, is_vendored
from .osv import OSVUnavailable, Package, fetch_details, query_batch

_PY_MANIFESTS = re.compile(r"(^|/)(requirements[\w.-]*\.txt|constraints[\w.-]*\.txt)$")
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][\w.!+-]*)"
)
# A dependency spec that names a version but not exactly (>=, ~=, ^, *, ranges).
_REQ_UNPINNED = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*[<>~!^]"
)

_EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+")


@dataclass
class Manifests:
    packages: list[Package]
    unpinned: list[tuple[str, str]]  # (manifest, package name)


# --------------------------------------------------------------------------- #
# Manifest parsers
# --------------------------------------------------------------------------- #
def _parse_requirements(path: str, content: str) -> Manifests:
    pkgs, unpinned = [], []
    for i, raw in enumerate(content.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue  # -r includes, -e editable installs, --index-url, ...
        m = _REQ_LINE.match(line)
        if m:
            pkgs.append(
                Package(m.group(1).lower(), m.group(2), "PyPI", path, i)
            )
            continue
        u = _REQ_UNPINNED.match(line)
        if u:
            unpinned.append((path, u.group(1)))
    return Manifests(pkgs, unpinned)


def _parse_pyproject(path: str, content: str) -> Manifests:
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return Manifests([], [])

    pkgs, unpinned = [], []

    def take(spec: str) -> None:
        m = _REQ_LINE.match(spec)
        if m:
            pkgs.append(Package(m.group(1).lower(), m.group(2), "PyPI", path))
        else:
            u = _REQ_UNPINNED.match(spec)
            if u:
                unpinned.append((path, u.group(1)))

    for spec in data.get("project", {}).get("dependencies", []) or []:
        if isinstance(spec, str):
            take(spec)
    optional = data.get("project", {}).get("optional-dependencies", {}) or {}
    for specs in optional.values():
        for spec in specs or []:
            if isinstance(spec, str):
                take(spec)

    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
        if isinstance(version, str) and re.fullmatch(r"\d[\w.!+-]*", version or ""):
            pkgs.append(Package(name.lower(), version, "PyPI", path))
        else:
            unpinned.append((path, name))
    return Manifests(pkgs, unpinned)


def _parse_pipfile_lock(path: str, content: str) -> Manifests:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return Manifests([], [])
    pkgs = []
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = (spec or {}).get("version", "")
            if isinstance(version, str) and version.startswith("=="):
                pkgs.append(Package(name.lower(), version[2:], "PyPI", path))
    return Manifests(pkgs, [])


def _parse_package_json(path: str, content: str) -> Manifests:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return Manifests([], [])
    pkgs, unpinned = [], []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and _EXACT_NPM.fullmatch(spec.strip()):
                pkgs.append(Package(name, spec.strip(), "npm", path))
            else:
                # A range: only the lockfile knows what actually got installed.
                unpinned.append((path, name))
    return Manifests(pkgs, unpinned)


def _parse_package_lock(path: str, content: str) -> Manifests:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return Manifests([], [])
    pkgs: list[Package] = []

    # lockfileVersion 2/3: a flat "packages" map keyed by install path.
    for key, spec in (data.get("packages") or {}).items():
        if not key or "node_modules/" not in key:
            continue
        name = key.split("node_modules/")[-1]
        version = (spec or {}).get("version")
        if name and isinstance(version, str):
            pkgs.append(Package(name, version, "npm", path))

    # lockfileVersion 1: a nested "dependencies" tree.
    def walk(node: dict) -> None:
        for name, spec in (node.get("dependencies") or {}).items():
            version = (spec or {}).get("version")
            if isinstance(version, str):
                pkgs.append(Package(name, version, "npm", path))
            if isinstance(spec, dict):
                walk(spec)

    if not pkgs:
        walk(data)
    return Manifests(pkgs, [])


_YARN_ENTRY = re.compile(
    r'^"?((?:@[^/\s"]+/)?[^@\s"]+)@[^\n]*?:\n(?:.*\n)*?\s+version:?\s+"?([\w.+-]+)"?',
    re.MULTILINE,
)


def _parse_yarn_lock(path: str, content: str) -> Manifests:
    pkgs = [
        Package(m.group(1), m.group(2), "npm", path)
        for m in _YARN_ENTRY.finditer(content)
    ]
    return Manifests(pkgs, [])


def parse_manifests(files: list[tuple[str, str]]) -> Manifests:
    """Extract every resolved dependency from the recognised manifest files."""
    packages: list[Package] = []
    unpinned: list[tuple[str, str]] = []
    # Prefer lockfiles: if package-lock.json is present, package.json's ranges
    # add nothing but noise.
    have_npm_lock = any(
        p.endswith(("package-lock.json", "yarn.lock")) and not is_vendored(p)
        for p, _ in files
    )

    for path, content in files:
        if is_vendored(path):
            continue
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        if _PY_MANIFESTS.search(path.replace("\\", "/")):
            parsed = _parse_requirements(path, content)
        elif name == "pyproject.toml":
            parsed = _parse_pyproject(path, content)
        elif name == "Pipfile.lock":
            parsed = _parse_pipfile_lock(path, content)
        elif name == "package-lock.json":
            parsed = _parse_package_lock(path, content)
        elif name == "yarn.lock":
            parsed = _parse_yarn_lock(path, content)
        elif name == "package.json":
            if have_npm_lock:
                continue
            parsed = _parse_package_json(path, content)
        else:
            continue
        packages.extend(parsed.packages)
        unpinned.extend(parsed.unpinned)

    # Deduplicate: the same package at the same version in two manifests is one
    # dependency to check.
    seen: dict[tuple[str, str, str], Package] = {}
    for p in packages:
        seen.setdefault((p.ecosystem, p.name.lower(), p.version), p)
    return Manifests(list(seen.values()), unpinned)


# --------------------------------------------------------------------------- #
# OSV record → finding
# --------------------------------------------------------------------------- #
_SEVERITY_WORDS = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _cvss_base_score(vector: str) -> float | None:
    """Pull the base score out of a CVSS vector when the record embeds one.

    OSV usually ships the vector, not the score. Rather than implement the full
    CVSS formula, use the exploitability-relevant metrics that dominate it.
    """
    parts = dict(
        p.split(":", 1) for p in vector.split("/")[1:] if ":" in p
    )
    if not parts:
        return None
    impact = sum(
        1 for k in ("C", "I", "A") if parts.get(k) in ("H", "C")
    )
    network = parts.get("AV") == "N"
    no_auth = parts.get("PR", "N") == "N"
    no_ui = parts.get("UI", "N") == "N"
    score = 3.0 + impact * 1.8
    if network:
        score += 1.5
    if no_auth:
        score += 1.0
    if no_ui:
        score += 0.5
    return min(score, 10.0)


def severity_of(vuln: dict) -> str:
    """Map an OSV record to high/medium/low, preferring explicit severity."""
    explicit = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(explicit, str) and explicit.upper() in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[explicit.upper()]

    best: float | None = None
    for sev in vuln.get("severity") or []:
        score = sev.get("score")
        if not isinstance(score, str):
            continue
        if score.startswith("CVSS:"):
            value = _cvss_base_score(score)
        else:
            try:
                value = float(score)
            except ValueError:
                value = None
        if value is not None:
            best = value if best is None else max(best, value)

    if best is None:
        # No severity data at all (common for PySec records). "medium" keeps it
        # visible without claiming a criticality the data doesn't support.
        return "medium"
    if best >= 7.0:
        return "high"
    if best >= 4.0:
        return "medium"
    return "low"


def _version_key(version: str) -> tuple:
    """Sortable key for a version string, tolerant of anything non-numeric."""
    parts = re.split(r"[.\-+]", version)
    key = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part), ""))
        else:
            key.append((1, 0, part))
    return tuple(key)


def fixed_version_for(vuln: dict, pkg: Package) -> str | None:
    """The lowest published fix above the installed version, if OSV names one."""
    candidates: list[str] = []
    for affected in vuln.get("affected") or []:
        apkg = affected.get("package") or {}
        if apkg.get("name", "").lower() != pkg.name.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if isinstance(fixed, str):
                    candidates.append(fixed)
    current = _version_key(pkg.version)
    ahead = [c for c in candidates if _version_key(c) > current]
    if not ahead:
        return None
    return min(ahead, key=_version_key)


def _summary_of(vuln: dict) -> str:
    return (
        vuln.get("summary")
        or (vuln.get("details") or "").strip().split("\n")[0][:200]
        or "No description published."
    )


def _preferred_id(vuln: dict) -> str:
    """Prefer a CVE id — it's what people search for and file tickets against."""
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _to_finding(pkg: Package, vuln: dict) -> SecurityFinding:
    vid = vuln.get("id", "UNKNOWN")
    rule_id = _preferred_id(vuln)
    severity = severity_of(vuln)
    fixed = fixed_version_for(vuln, pkg)
    refs = [
        r["url"]
        for r in (vuln.get("references") or [])
        if isinstance(r, dict) and isinstance(r.get("url"), str)
    ][:5]
    refs.insert(0, f"https://osv.dev/vulnerability/{vid}")

    if fixed:
        fix = (
            f"Upgrade {pkg.name} from {pkg.version} to {fixed} or later in "
            f"{pkg.manifest}, then regenerate the lockfile."
        )
    else:
        fix = (
            f"No fixed version is published for {pkg.name} {pkg.version}. "
            "Check the advisory for a workaround, or replace the dependency."
        )

    return SecurityFinding(
        id=finding_id("dependency", vid, pkg.ecosystem, pkg.name, pkg.version),
        category="dependency",
        detector="osv",
        rule_id=rule_id,
        title=f"{pkg.name} {pkg.version} — {rule_id}",
        file=pkg.manifest,
        line_start=pkg.line,
        line_end=pkg.line,
        detector_severity=severity,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        evidence=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
        references=refs,
        explanation=(
            f"{pkg.name} {pkg.version} is affected by {rule_id}: "
            f"{_summary_of(vuln)}"
        ),
        suggested_fix=fix,
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def scan_dependencies(
    files: list[tuple[str, str]], *, offline: bool = False
) -> tuple[list[SecurityFinding], list[str]]:
    """Return (findings, degraded) for the dependency detector.

    `degraded` is non-empty when the detector could not do its whole job — no
    manifests found, OSV unreachable, or ranges that no lockfile resolved. It is
    surfaced to the user so an empty result is never mistaken for a clean bill
    of health.
    """
    manifests = parse_manifests(files)
    degraded: list[str] = []

    if not manifests.packages:
        if manifests.unpinned:
            names = ", ".join(sorted({n for _, n in manifests.unpinned})[:5])
            degraded.append(
                "dependency: no pinned versions found (unresolved ranges for "
                f"{names}…). Commit a lockfile so versions can be checked."
            )
        else:
            degraded.append("dependency: no supported manifest files found")
        return [], degraded

    if offline:
        degraded.append("dependency: OSV lookup disabled (offline mode)")
        return [], degraded

    try:
        hits = query_batch(manifests.packages)
    except OSVUnavailable as exc:
        degraded.append(f"dependency: OSV unreachable ({exc}) — versions not checked")
        return [], degraded

    all_ids = [vid for ids in hits.values() for vid in ids]
    details = fetch_details(all_ids)

    findings: list[SecurityFinding] = []
    for pkg, ids in hits.items():
        for vid in ids:
            vuln = details.get(vid)
            if vuln is None:
                continue
            findings.append(_to_finding(pkg, vuln))

    if manifests.unpinned:
        names = ", ".join(sorted({n for _, n in manifests.unpinned})[:5])
        degraded.append(
            f"dependency: {len(manifests.unpinned)} unpinned requirement(s) "
            f"skipped ({names}…) — commit a lockfile to include them"
        )
    return findings, degraded
