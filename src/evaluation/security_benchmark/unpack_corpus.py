"""Unpack the encoded corpus back into `repo/`, so the fixture can be edited.

    python src/evaluation/security_benchmark/unpack_corpus.py

Writes plaintext credentials to disk under repo/, which is gitignored for that
reason. Edit, then run build_corpus.py and commit corpus.json.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE / "repo"
CORPUS = HERE / "corpus.json"


def main() -> None:
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    for rel, encoded in data["files"].items():
        dest = REPO / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(base64.b64decode(encoded))
    print(f"unpacked {len(data['files'])} file(s) into {REPO.name}/")
    print("repo/ is gitignored — commit corpus.json instead")


if __name__ == "__main__":
    main()
