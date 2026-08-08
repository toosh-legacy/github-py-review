"""Pack the benchmark fixture into an encoded corpus.

The fixture is a small repository full of deliberately-planted credentials —
that is what makes it a useful test corpus for a secret detector. It is also,
byte for byte, indistinguishable from a real leak to anything that reads the
files as text: GitHub's push protection blocks it, this project's own scanner
reports it, and so would anyone else's.

So the corpus is stored base64-encoded in `corpus.json` and materialised in
memory at scan time. No plaintext credential exists anywhere in the repository,
and the detector still sees exactly the bytes it needs.

    python src/evaluation/security_benchmark/build_corpus.py

Edit files under `repo/` (kept out of git), run this, and commit corpus.json.
Line numbers are preserved, so ground_truth.json stays valid.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE / "repo"
CORPUS = HERE / "corpus.json"


def build() -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(REPO.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO).as_posix()
        # Normalise to LF. A Windows checkout gives CRLF, which would otherwise
        # be baked into the corpus and shift every ground-truth line number the
        # moment anything re-wrote the file.
        raw = path.read_bytes().replace(b"\r\n", b"\n")
        files[rel] = base64.b64encode(raw).decode("ascii")
    return files


def main() -> None:
    if not REPO.is_dir():
        raise SystemExit(
            f"{REPO} does not exist. Run `unpack_corpus.py` first if you want to "
            "edit the fixture, or check out the repo/ directory."
        )
    files = build()
    CORPUS.write_text(
        json.dumps(
            {
                "_readme": (
                    "Base64-encoded benchmark fixture. Stored encoded so the "
                    "repository contains no plaintext credential; the planted "
                    "secrets are synthetic and were never issued. Regenerate "
                    "with build_corpus.py; unpack with unpack_corpus.py."
                ),
                "files": files,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"wrote {CORPUS.name}: {len(files)} file(s)")


if __name__ == "__main__":
    main()
