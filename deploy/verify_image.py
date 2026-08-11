"""Prove the image's detectors actually run, at build time.

    python deploy/verify_image.py            # builds a fixture and scans it

Run as the last step of the Docker build. The failure this exists to prevent is
an image that installs cleanly, starts cleanly, and quietly analyses nothing —
`reposec doctor` cannot catch it, because it reports what is available and exits
0 by design, so a missing analyzer prints a line into a build log nobody reads.

It scans a throwaway fixture and asserts on the machine-readable report rather
than on an exit code, so each analyzer is named when it fails. The scan runs
offline: OSV's network path is covered by the test suite and the CI self-scan,
and requiring a live query here would mean an osv.dev outage fails image builds.
What is specific to the image — and so what this checks — is whether the copied
node binary, the vendored eslint tree, and git work inside it.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# One finding per analyzer, chosen because each is unambiguous and stable:
# B605 is `os.system` with concatenation, and eslint-plugin-security's rule ids
# are the only ones that carry a `security/` prefix.
_FIXTURE = {
    "a.py": 'import os\n\n\ndef run(name):\n    os.system("ls " + name)\n',
    "a.js": "export function go(src) {\n  eval(src);\n}\n",
    # A manifest, so the dependency detector reports "OSV lookup disabled"
    # rather than "no supported manifest files found". The distinction is the
    # check: the first says the parser ran, the second says it had nothing.
    "requirements.txt": "flask==0.12.2\n",
}


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=build@local", "-c", "user.name=build", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="reposec-verify-") as tmp:
        root = Path(tmp)
        for name, content in _FIXTURE.items():
            (root / name).write_text(content, encoding="utf-8")
        # A commit, so `--history` has something to walk: history scanning is
        # the reason git is installed in this image at all.
        _git(root, "init", "-q", ".")
        _git(root, "add", "-A")
        _git(root, "commit", "-qm", "fixture")

        proc = subprocess.run(
            [
                sys.executable, "-m", "reposec",
                "scan", str(root),
                "--history", "--offline", "--format", "json",
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            # Inherit the environment rather than replacing it: a bare PATH is
            # missing SYSTEMROOT on Windows, which breaks socket initialisation
            # before the scan gets anywhere.
            env={**os.environ, "LLM_BACKEND": "mock"},
        )
        if proc.returncode not in (0, 1):
            print(proc.stderr, file=sys.stderr)
            return f_exit(f"the scan itself failed with exit {proc.returncode}")
        report = json.loads(proc.stdout)

    rules = {f["rule_id"] for f in report["findings"]}

    if "B605" not in rules:
        return f_exit(f"bandit did not run in this image — rules seen: {sorted(rules)}")
    if not any(r.startswith("security/") for r in rules):
        return f_exit(f"eslint did not run in this image — rules seen: {sorted(rules)}")

    # Offline is the one degradation this build asked for. Anything else means a
    # detector could not run, which is the whole point of the check.
    unexpected = [d for d in report["degraded"] if "offline mode" not in d]
    if unexpected:
        return f_exit(f"a detector degraded in this image: {unexpected}")

    print(f"image verified — {len(rules)} rule(s) fired, no detector degraded")
    return 0


def f_exit(message: str) -> int:
    print(f"reposec image verification failed: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
