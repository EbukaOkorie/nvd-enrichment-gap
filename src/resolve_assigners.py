"""
Identify assigners that the official CNA list cannot resolve.

NVD reports some assigners as bare UUIDs, and some emails do not appear in the
official list at all. But every CVE List V5 record carries assignerShortName,
so fetching a couple of that assigner's CVEs tells you who they are.

Reads the unresolved rows from cna_map.csv, samples CVEs for each, and writes
the discovered names to data/reference/assigner_lookup.json. Merge the useful
ones into ecosystems.json by hand.

Usage:
    python src/resolve_assigners.py --min-cves 50
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import time
from collections import Counter
from pathlib import Path

import httpx
import polars as pl

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "cves.parquet"
REF = ROOT / "data" / "reference"
CNA_MAP = REF / "cna_map.csv"
OUT = REF / "assigner_lookup.json"

RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def record_url(cve_id: str) -> str | None:
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    return f"{RAW_BASE}/{year}/{(num[:-3] or '0')}xxx/{cve_id}.json"


def probe(client: httpx.Client, assigner: str, cve_ids: list[str]) -> dict:
    """Fetch a few of this assigner's CVEs and read the name off them."""
    names: Counter = Counter()
    orgs: Counter = Counter()

    for cve_id in cve_ids:
        url = record_url(cve_id)
        if not url:
            continue
        try:
            r = client.get(url, timeout=30.0)
        except httpx.RequestError:
            time.sleep(1)
            continue
        if r.status_code != 200:
            continue
        try:
            meta = r.json().get("cveMetadata", {}) or {}
        except json.JSONDecodeError:
            continue
        short = meta.get("assignerShortName")
        if short:
            names[short] += 1
        org = meta.get("assignerOrgId")
        if org:
            orgs[org] += 1

    top = names.most_common(1)
    return {
        "assigner": assigner,
        "short_name": top[0][0] if top else None,
        "confidence": f"{top[0][1]}/{len(cve_ids)}" if top else f"0/{len(cve_ids)}",
        "all_names_seen": dict(names),
        "org_id": orgs.most_common(1)[0][0] if orgs else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-cves", type=int, default=50, help="only probe assigners with at least this many CVEs")
    parser.add_argument("--samples", type=int, default=3, help="CVEs to fetch per assigner")
    parser.add_argument("--workers", type=int, default=5)
    args = parser.parse_args()

    for path in (DATA, CNA_MAP):
        if not path.exists():
            raise SystemExit(f"{path} not found. Run build_dataset.py and build_cna_map.py first.")

    cna_map = pl.read_csv(CNA_MAP)
    unresolved = (
        cna_map.filter(pl.col("short_name").is_null() & (pl.col("cves") >= args.min_cves))
        .sort("cves", descending=True)
    )
    print(f"{unresolved.height} unidentified assigners with {args.min_cves}+ CVEs")
    if unresolved.height == 0:
        return

    df = pl.read_parquet(DATA).filter(~pl.col("is_rejected"))

    # Pick sample CVE IDs per assigner. Recent ones are likelier to exist in
    # the repository with clean metadata.
    targets = unresolved["assigner"].to_list()
    samples: dict[str, list[str]] = {}
    for assigner in targets:
        ids = (
            df.filter(pl.col("assigner") == assigner)
            .sort("published_date", descending=True)
            .head(args.samples)["cve_id"]
            .to_list()
        )
        samples[assigner] = ids

    results = []
    with httpx.Client(follow_redirects=True) as client:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(probe, client, a, samples[a]) for a in targets]
            for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                results.append(fut.result())
                if i % 20 == 0:
                    print(f"  {i}/{len(targets)}")

    found = [r for r in results if r["short_name"]]
    missing = [r for r in results if not r["short_name"]]

    volumes = dict(zip(cna_map["assigner"].to_list(), cna_map["cves"].to_list()))
    absence = dict(zip(cna_map["assigner"].to_list(), cna_map["pct_no_cpe"].to_list()))
    for r in results:
        r["cves"] = volumes.get(r["assigner"])
        r["pct_no_cpe"] = absence.get(r["assigner"])
    found.sort(key=lambda r: -(r["cves"] or 0))

    print("\n" + "=" * 84)
    print(f"IDENTIFIED {len(found)} OF {len(results)}")
    print("=" * 84)
    print(f"{'short_name':<24} {'cves':>7} {'no_cpe':>7}   assigner")
    print("-" * 84)
    for r in found:
        print(f"{r['short_name']:<24} {r['cves']:>7} {r['pct_no_cpe']:>6.1f}%   {r['assigner'][:34]}")

    if missing:
        print(f"\nstill unidentified ({len(missing)}), look these up by hand:")
        for r in sorted(missing, key=lambda r: -(r["cves"] or 0))[:15]:
            print(f"  {r['assigner'][:40]:<42} {r['cves']:>7}")

    OUT.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"\nwritten to {OUT}")
    print("\nAdd the useful short_names to the relevant ecosystem in ecosystems.json,")
    print("then rerun build_cna_map.py. Assigners whose short_name is now known but")
    print("whose email still fails to match belong in assigner_overrides.")


if __name__ == "__main__":
    main()
