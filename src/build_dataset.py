"""
Turn the raw API pages into one tidy table.

Reads every data/raw/<run>/page_*.json.gz, extracts the fields the analysis
needs, deduplicates by CVE ID keeping the most recently modified version, and
writes data/interim/cves.parquet.

Deduplication matters. Pagination by startIndex against a live corpus can skip
or repeat records when new CVEs are published mid-run, so the page structure
is not trusted.

Usage:
    python src/build_dataset.py
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
OUT = ROOT / "data" / "interim" / "cves.parquet"

# NIST began risk-based enrichment on this date.
POLICY_CHANGE = "2026-04-15"


def extract(record: dict) -> dict:
    cve = record.get("cve", {}) or {}
    metrics = cve.get("metrics", {}) or {}

    has_primary = has_secondary = False
    for key, entries in metrics.items():
        # SSVC decision points share this object and are not CVSS scores.
        if not key.startswith("cvssMetric"):
            continue
        for entry in entries or []:
            if entry.get("type") == "Primary":
                has_primary = True
            else:
                has_secondary = True

    cpe_count = 0
    vendors: set[str] = set()
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                cpe_count += 1
                # cpe:2.3:part:vendor:product:version:...
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4:
                    vendors.add(parts[3])

    cwes = [
        d.get("value")
        for w in cve.get("weaknesses", []) or []
        for d in w.get("description", []) or []
        if (d.get("value") or "").startswith("CWE-")
    ]

    return {
        "cve_id": cve.get("id"),
        "published": (cve.get("published") or "")[:10],
        "last_modified": (cve.get("lastModified") or "")[:19],
        "vuln_status": cve.get("vulnStatus"),
        "assigner": cve.get("sourceIdentifier"),
        "has_primary_cvss": has_primary,
        "has_secondary_cvss": has_secondary,
        "cpe_match_count": cpe_count,
        "vendor_count": len(vendors),
        "vendors": sorted(vendors)[:20],
        "cwe_count": len(cwes),
    }


def load_all() -> list[dict]:
    pages = sorted(RAW_DIR.rglob("page_*.json.gz"))
    if not pages:
        raise SystemExit(f"no raw pages found under {RAW_DIR}. Run collect_nvd.py first.")

    print(f"reading {len(pages)} pages")
    rows: list[dict] = []
    for i, path in enumerate(pages, 1):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        for record in payload.get("vulnerabilities", []) or []:
            rows.append(extract(record))
        if i % 25 == 0:
            print(f"  {i}/{len(pages)} pages, {len(rows)} rows so far")
    return rows


def main() -> None:
    rows = load_all()
    raw_count = len(rows)

    df = pl.DataFrame(rows)

    # Keep the most recently modified copy of each CVE.
    df = (
        df.filter(pl.col("cve_id").is_not_null())
        .sort("last_modified", descending=True)
        .unique(subset=["cve_id"], keep="first")
    )

    df = df.with_columns(
        pl.col("published").str.to_date("%Y-%m-%d", strict=False).alias("published_date")
    ).with_columns(
        (pl.col("cpe_match_count") == 0).alias("cpe_absent"),
        (~pl.col("has_primary_cvss")).alias("no_nist_cvss"),
        (~pl.col("has_primary_cvss") & ~pl.col("has_secondary_cvss")).alias("no_cvss_at_all"),
        (pl.col("vuln_status") == "Rejected").alias("is_rejected"),
        (pl.col("published_date") >= pl.lit(POLICY_CHANGE).str.to_date()).alias("post_policy"),
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(OUT)

    dupes = raw_count - df.height
    print(f"\nrows read:        {raw_count}")
    print(f"duplicates dropped: {dupes}")
    print(f"unique CVEs:      {df.height}")
    print(f"written to:       {OUT}")

    live = df.filter(~pl.col("is_rejected"))
    print(f"\nrejected excluded: {df.height - live.height}")
    print(f"date range:        {live['published_date'].min()} to {live['published_date'].max()}")
    print("\nvulnStatus counts:")
    for row in live.group_by("vuln_status").len().sort("len", descending=True).iter_rows():
        print(f"  {row[0]:<20} {row[1]}")


if __name__ == "__main__":
    main()
