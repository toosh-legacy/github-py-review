"""Package the Chrome extension for upload to the Web Store.

    python deploy/package_extension.py

Writes `dist/repo-security-scanner-<version>.zip` containing only the files the
extension actually needs. The store rejects uploads with unreferenced or
oversized junk, and shipping a whole source directory would also mean shipping
whatever a developer happened to leave in it.

The manifest is validated first — a bad upload costs a review round trip, which
is days.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "src" / "apps" / "extension"
DIST = ROOT / "dist"

# An allowlist, not an ignore list: anything new has to be added deliberately.
INCLUDE = [
    "manifest.json",
    "background.js",
    "security_script.js",
    "popup.html",
    "popup.js",
    "icons/icon16.png",
    "icons/icon32.png",
    "icons/icon48.png",
    "icons/icon128.png",
]

REQUIRED_ICONS = ("16", "32", "48", "128")


def validate(manifest: dict) -> list[str]:
    """Catch the mistakes that get an upload rejected."""
    problems = []

    if manifest.get("manifest_version") != 3:
        problems.append("manifest_version must be 3; MV2 is no longer accepted")

    version = manifest.get("version", "")
    if not all(part.isdigit() for part in version.split(".") if part) or not version:
        problems.append(f"version {version!r} must be dot-separated integers")

    # The store truncates at 132 characters, so anything longer is silently cut.
    description = manifest.get("description", "")
    if not description:
        problems.append("description is required")
    elif len(description) > 132:
        problems.append(f"description is {len(description)} chars; the store allows 132")

    icons = manifest.get("icons") or {}
    for size in REQUIRED_ICONS:
        if size not in icons:
            problems.append(f"icons is missing the {size}x{size} entry")

    # A referenced file that is not in INCLUDE would 404 inside the packaged zip.
    referenced = set(icons.values())
    referenced |= set((manifest.get("action") or {}).get("default_icon", {}).values())
    referenced |= {(manifest.get("background") or {}).get("service_worker", "")}
    referenced |= {(manifest.get("action") or {}).get("default_popup", "")}
    for script in manifest.get("content_scripts") or []:
        referenced |= set(script.get("js") or [])
    for path in sorted(p for p in referenced if p):
        if path not in INCLUDE:
            problems.append(f"manifest references {path}, which the package excludes")
        if not (EXT / path).is_file():
            problems.append(f"manifest references {path}, which does not exist")

    return problems


def main() -> int:
    manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))

    problems = validate(manifest)
    if problems:
        print("manifest problems:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    missing = [name for name in INCLUDE if not (EXT / name).is_file()]
    if missing:
        print(f"missing files: {', '.join(missing)}", file=sys.stderr)
        print("run `python deploy/make_extension_icons.py` first?", file=sys.stderr)
        return 1

    DIST.mkdir(exist_ok=True)
    out = DIST / f"repo-security-scanner-{manifest['version']}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in INCLUDE:
            zf.write(EXT / name, arcname=name)

    size_kb = out.stat().st_size / 1024
    print(f"wrote {out.relative_to(ROOT)} ({size_kb:.1f} KB, {len(INCLUDE)} files)")
    print("upload at https://chrome.google.com/webstore/devconsole")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
