"""
Merge resolved assigner identities into ecosystems.json.

resolve_assigners.py works out who each unidentified assigner is. This writes
those findings into the assigner_overrides block so build_cna_map.py can use
them, without anyone retyping a UUID by hand.

Only touches assigner_overrides. Ecosystem membership stays a human decision.

Usage:
    python src/merge_assigner_lookup.py            # show what would change
    python src/merge_assigner_lookup.py --apply    # write it
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "data" / "reference"
ECOSYSTEMS = REF / "ecosystems.json"
LOOKUP = REF / "assigner_lookup.json"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the changes")
    parser.add_argument("--min-confidence", type=int, default=1,
                        help="require at least this many sampled CVEs to agree")
    args = parser.parse_args()

    for path in (ECOSYSTEMS, LOOKUP):
        if not path.exists():
            raise SystemExit(f"{path} not found.")

    config = json.loads(ECOSYSTEMS.read_text(encoding="utf-8"))
    lookup = json.loads(LOOKUP.read_text(encoding="utf-8"))
    overrides = dict(config.get("assigner_overrides") or {})

    # Which shortNames are already placed in an ecosystem?
    placed = {
        short.lower()
        for spec in config["ecosystems"].values()
        for short in spec["cnas"]
    }

    added, skipped, unplaced = [], [], []
    for entry in lookup:
        assigner = entry.get("assigner")
        short = entry.get("short_name")
        if not assigner or not short:
            continue

        agree = int((entry.get("confidence") or "0/0").split("/")[0])
        if agree < args.min_confidence:
            skipped.append((assigner, short, entry.get("confidence")))
            continue

        if assigner in overrides:
            continue
        overrides[assigner] = short
        added.append((assigner, short, entry.get("cves")))

        if short.lower() not in placed:
            unplaced.append((short, entry.get("cves"), entry.get("pct_no_cpe")))

    added.sort(key=lambda r: -(r[2] or 0))
    unplaced.sort(key=lambda r: -(r[1] or 0))

    print(f"overrides already present: {len(config.get('assigner_overrides') or {})}")
    print(f"new overrides to add:      {len(added)}")
    if skipped:
        print(f"skipped on low confidence: {len(skipped)}")

    if unplaced:
        print("\n" + "=" * 70)
        print(f"{len(unplaced)} RESOLVED BUT NOT IN ANY ECOSYSTEM")
        print("=" * 70)
        print("Add these shortNames to the right group in ecosystems.json.")
        print("Anything left out is simply excluded from ecosystem totals.\n")
        for short, cves, pct in unplaced:
            pct_s = f"{pct:.1f}%" if pct is not None else "?"
            print(f"  {short:<26} {cves:>6} CVEs   {pct_s:>6} no CPE")

    if not args.apply:
        print("\nDry run. Rerun with --apply to write these overrides.")
        return

    backup = ECOSYSTEMS.with_suffix(".json.bak")
    shutil.copy2(ECOSYSTEMS, backup)

    config["assigner_overrides"] = dict(sorted(overrides.items()))
    ECOSYSTEMS.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {len(overrides)} overrides to {ECOSYSTEMS}")
    print(f"previous version saved as {backup.name}")
    print("Now rerun: python src/build_cna_map.py")


if __name__ == "__main__":
    main()
