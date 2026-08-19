"""
Viability check for the translation idea.

Question this answers: for the CVEs that NVD left without CPE data, how many
carry usable product information in the CNA's own CVE List V5 submission?

If the answer is high, a translation layer is worth building. If it is low,
it is not, and better to know that now.

Fetches records individually from raw.githubusercontent.com. Sample rather
than the whole population, since a few hundred records answers the question
and 30,000 requests is rude.

Usage:
    python src/check_cna_data.py --sample 400
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import time
from pathlib import Path

import httpx
import polars as pl

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "cves.parquet"
OUT = ROOT / "data" / "outputs"

RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def record_url(cve_id: str) -> str | None:
    """CVE-2026-14251 -> .../cves/2026/14xxx/CVE-2026-14251.json"""
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    bucket = (num[:-3] or "0") + "xxx"
    return f"{RAW_BASE}/{year}/{bucket}/{cve_id}.json"


def classify(record: dict) -> dict:
    """What usable product information did the CNA actually supply?"""
    meta = record.get("cveMetadata", {}) or {}
    cna = (record.get("containers", {}) or {}).get("cna", {}) or {}
    affected = cna.get("affected") or []

    has_cpe = False
    has_vendor = has_product = has_versions = False
    vendor_unknown = False

    for entry in affected:
        if entry.get("cpes"):
            has_cpe = True
        vendor = (entry.get("vendor") or "").strip()
        product = (entry.get("product") or "").strip()
        if vendor and vendor.lower() not in ("unknown", "n/a", ""):
            has_vendor = True
        elif vendor:
            vendor_unknown = True
        if product and product.lower() not in ("unknown", "n/a", ""):
            has_product = True
        versions = entry.get("versions") or []
        if versions or entry.get("defaultStatus") == "affected":
            has_versions = True

    # Tiers, most useful first.
    if has_cpe:
        tier = "1_cpe_supplied"
    elif has_vendor and has_product and has_versions:
        tier = "2_vendor_product_version"
    elif has_product and has_versions:
        tier = "3_product_version_no_vendor"
    elif has_product:
        tier = "4_product_only"
    else:
        tier = "5_nothing_usable"

    return {
        "cve_id": meta.get("cveId"),
        "cna": meta.get("assignerShortName"),
        "state": meta.get("state"),
        "affected_entries": len(affected),
        "has_cpe": has_cpe,
        "has_vendor": has_vendor,
        "vendor_unknown": vendor_unknown,
        "has_product": has_product,
        "has_versions": has_versions,
        "tier": tier,
    }


def fetch_one(client: httpx.Client, cve_id: str) -> dict | None:
    url = record_url(cve_id)
    if not url:
        return None
    for attempt in range(3):
        try:
            r = client.get(url, timeout=30.0)
        except httpx.RequestError:
            time.sleep(2 ** attempt)
            continue
        if r.status_code == 200:
            try:
                return classify(r.json())
            except json.JSONDecodeError:
                return {"cve_id": cve_id, "tier": "0_unparseable", "cna": None}
        if r.status_code == 404:
            return {"cve_id": cve_id, "tier": "0_not_in_list", "cna": None}
        time.sleep(2 ** attempt)
    return {"cve_id": cve_id, "tier": "0_fetch_failed", "cna": None}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=400)
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()

    if not DATA.exists():
        raise SystemExit(f"{DATA} not found. Run build_dataset.py first.")

    df = pl.read_parquet(DATA)
    target = df.filter(
        ~pl.col("is_rejected")
        & pl.col("cpe_absent")
        & pl.col("post_policy")
    )
    print(f"{target.height} CPE-absent records published since the policy change")

    sample = target.sample(min(args.sample, target.height), seed=42)
    ids = sample["cve_id"].to_list()
    print(f"sampling {len(ids)} of them\n")

    results: list[dict] = []
    with httpx.Client(follow_redirects=True) as client:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(fetch_one, client, cid): cid for cid in ids}
            for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                res = fut.result()
                if res:
                    results.append(res)
                if i % 50 == 0:
                    print(f"  {i}/{len(ids)}")

    out = pl.DataFrame(results)
    n = out.height

    print("\n" + "=" * 72)
    print("HOW MUCH PRODUCT DATA DID THE CNA SUPPLY?")
    print("=" * 72)
    tiers = out.group_by("tier").len().sort("tier")
    for tier, count in tiers.iter_rows():
        print(f"  {tier:<32} {count:>5}  {count / n * 100:5.1f}%")

    usable = out.filter(pl.col("tier").is_in(
        ["1_cpe_supplied", "2_vendor_product_version", "3_product_version_no_vendor"]
    )).height
    print(f"\n  usable for translation:          {usable:>5}  {usable / n * 100:5.1f}%")

    print("\n" + "=" * 72)
    print("BY CNA (10+ in sample)")
    print("=" * 72)
    by_cna = (
        out.group_by("cna")
        .agg(
            pl.len().alias("n"),
            (pl.col("tier") == "1_cpe_supplied").mean().mul(100).round(1).alias("pct_cpe"),
            pl.col("tier").is_in(
                ["1_cpe_supplied", "2_vendor_product_version", "3_product_version_no_vendor"]
            ).mean().mul(100).round(1).alias("pct_usable"),
        )
        .filter(pl.col("n") >= 10)
        .sort("n", descending=True)
    )
    with pl.Config(tbl_rows=30, tbl_width_chars=90):
        print(by_cna)

    OUT.mkdir(parents=True, exist_ok=True)
    out.write_csv(OUT / "cna_data_availability.csv")
    by_cna.write_csv(OUT / "cna_data_availability_summary.csv")
    print(f"\nwritten to {OUT}")

    print("\n" + "-" * 72)
    print("Reading this: tier 1 records could be passed straight through.")
    print("Tier 2 needs a CPE constructed but has everything required.")
    print("Tier 3 has no vendor, so any CPE built from it involves a guess.")
    print("Tiers 4 and 5 cannot be translated without external lookup.")
    print("-" * 72)


if __name__ == "__main__":
    main()
