"""Refresh the frozen OSV snapshot the benchmark scores against.

OSV is a live database. Scoring the dependency detector against it directly
means the benchmark number changes whenever a new advisory is published, and a
genuine regression becomes indistinguishable from the world moving on. So the
benchmark replays a snapshot instead.

Run this deliberately, review the diff, and commit it — a changed snapshot is a
change to the benchmark, not an incidental update:

    python src/ml/evaluation/security_benchmark/snapshot_osv.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from security.deps_scan import parse_manifests  # noqa: E402
from security.osv import fetch_details, query_batch  # noqa: E402

SNAPSHOT = HERE / "osv_snapshot.json"
MANIFEST = HERE / "repo" / "requirements.txt"


def main() -> None:
    manifests = parse_manifests([("requirements.txt", MANIFEST.read_text("utf-8"))])
    print(f"querying OSV for {len(manifests.packages)} package(s)…")

    hits = query_batch(manifests.packages)
    ids = [vid for vids in hits.values() for vid in vids]
    details = fetch_details(ids)

    snapshot = {
        # Keyed by "ecosystem:name:version" so the replay stub can look a
        # package up without reconstructing the Package dataclass.
        "hits": {
            f"{p.ecosystem}:{p.name}:{p.version}": vids for p, vids in hits.items()
        },
        "vulns": details,
    }
    SNAPSHOT.write_text(json.dumps(snapshot, indent=2, sort_keys=True), "utf-8")
    print(
        f"wrote {SNAPSHOT.name}: {len(snapshot['hits'])} package(s), "
        f"{len(details)} vulnerability record(s)"
    )


if __name__ == "__main__":
    main()
