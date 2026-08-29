"""
Run a software inventory against CVEs that carry no CPE data in NVD.

This is the thing a person other than the author can actually use. Give it a
list of what you run, get back the vulnerabilities a CPE-based scanner cannot
match to your software.

Input is a plain text or CSV file, one item per line, any of these forms:

    wordpress
    WooCommerce Subscriptions, 4.2.1
    Red Hat Enterprise Linux==9.4
    django 4.2

Three outcomes per item, and the difference matters:

    matched      the name was found and CVEs apply
    no_cves      the name was found but nothing applies at that version
    unrecognised the name was not found at all

An unrecognised item is not a clean bill of health. It means this tool has no
opinion, usually because the CNA writes that product's name differently. Those
are reported separately rather than counted as safe.

Usage:
    python src/audit.py --inventory my_stack.txt
    python src/audit.py --inventory my_stack.csv --out report.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match import find, name_candidates  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "normalised_products.parquet"
DEFAULT_OUT = ROOT / "data" / "outputs" / "audit_report.csv"

SPLITTERS = re.compile(r"\s*(?:==|,|\t|\s+)\s*")


def parse_line(line: str) -> tuple[str, str | None] | None:
    """Accept several casual formats rather than demanding one."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # A trailing token that looks like a version is treated as one.
    if "," in line or "==" in line:
        parts = [p.strip() for p in re.split(r",|==", line, maxsplit=1)]
        name = parts[0]
        version = parts[1] if len(parts) > 1 and parts[1] else None
        return (name, version) if name else None

    tokens = line.split()
    if len(tokens) > 1 and re.fullmatch(r"v?\d+(\.\d+)*[a-z0-9.\-]*", tokens[-1], re.IGNORECASE):
        return " ".join(tokens[:-1]), tokens[-1].lstrip("vV")
    return line, None


def load_inventory(path: Path) -> list[tuple[str, str | None]]:
    text = path.read_text(encoding="utf-8-sig")

    # A CSV with a header gets read properly rather than line by line.
    first = text.splitlines()[0].lower() if text.strip() else ""
    if "," in first and any(h in first for h in ("product", "name", "software")):
        items = []
        for row in csv.DictReader(text.splitlines()):
            keys = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}
            name = keys.get("product") or keys.get("name") or keys.get("software")
            version = keys.get("version") or keys.get("release") or None
            if name:
                items.append((name, version or None))
        return items

    items = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed:
            items.append(parsed)
    return items


def name_rows(df: pl.DataFrame, product: str) -> pl.DataFrame:
    """Every row matching this name, ignoring version and CPE status."""
    keys = name_candidates(product)
    if not keys["slug"]:
        return df.head(0)
    exprs = [
        pl.col("product_slug") == keys["slug"],
        pl.col("product_base") == keys["slug"],
        pl.col("package_slug") == keys["slug"],
        pl.col("product_compact") == keys["compact"],
        pl.col("product_base_compact") == keys["compact"],
    ]
    for variant in keys.get("variants") or []:
        exprs.append(pl.col("product_base") == variant)
    return df.filter(pl.any_horizontal(exprs))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--since", help="only count CVEs published on or after this date, YYYY-MM-DD")
    args = parser.parse_args()

    if not DATA.exists():
        raise SystemExit(f"{DATA} not found. Run normalise.py first.")
    if not args.inventory.exists():
        raise SystemExit(f"{args.inventory} not found.")

    df = pl.read_parquet(DATA)
    items = load_inventory(args.inventory)
    if not items:
        raise SystemExit("no items read from the inventory file")

    print(f"auditing {len(items)} item(s) against {df.height} product entries\n")

    results = []
    detail_rows = []

    for name, version in items:
        hits = find(df, name, version)
        if args.since and hits.height:
            hits = hits.filter(pl.col("date_published") >= args.since)

        if hits.height:
            cves = sorted(set(hits["cve_id"].to_list()))
            tiers = sorted(set(hits["match_tier"].to_list()))
            status = "matched"
            for row in hits.iter_rows(named=True):
                detail_rows.append({
                    "input_product": name,
                    "input_version": version or "",
                    "cve_id": row["cve_id"],
                    "cna": row["cna"],
                    "date_published": row["date_published"],
                    "matched_product": row["product_raw"],
                    "match_tier": row["match_tier"],
                    "version_verdict": row["version_verdict"],
                })
        else:
            cves, tiers = [], []
            known = name_rows(df, name)
            if not known.height:
                status = "unrecognised"
            elif "nvd_cpe_absent" in known.columns and not known["nvd_cpe_absent"].any():
                # Found, and every CVE for it carries CPE data in NVD.
                status = "covered"
            else:
                status = "no_cves"

        results.append({
            "product": name,
            "version": version or "",
            "status": status,
            "cve_count": len(cves),
            "match_tiers": ", ".join(tiers),
        })

    summary = pl.DataFrame(results)
    matched = summary.filter(pl.col("status") == "matched")
    unknown = summary.filter(pl.col("status") == "unrecognised")
    clean = summary.filter(pl.col("status") == "no_cves")
    covered = summary.filter(pl.col("status") == "covered")

    total_cves = len({r["cve_id"] for r in detail_rows})

    print("=" * 74)
    print("BLIND SPOT SUMMARY")
    print("=" * 74)
    print(f"items audited:                {len(items)}")
    print(f"items with invisible CVEs:    {matched.height}")
    print(f"items fully covered by NVD:   {covered.height}")
    print(f"items with none at this ver:  {clean.height}")
    print(f"items not recognised:         {unknown.height}")
    print(f"\ndistinct CVEs your scanner cannot match: {total_cves}")
    if args.since:
        print(f"(published on or after {args.since})")

    if matched.height:
        print("\n" + "-" * 74)
        print("WHERE THE GAPS ARE")
        print("-" * 74)
        with pl.Config(tbl_rows=40, tbl_width_chars=120, fmt_str_lengths=34):
            print(matched.sort("cve_count", descending=True)
                  .select(["product", "version", "cve_count", "match_tiers"]))

    if covered.height:
        print("\n" + "-" * 74)
        print("COVERED (NVD publishes CPE for these, so a scanner can see them)")
        print("-" * 74)
        for row in covered.iter_rows(named=True):
            print(f"  {row['product']}" + (f"  {row['version']}" if row["version"] else ""))

    if unknown.height:
        print("\n" + "-" * 74)
        print("NOT RECOGNISED (no opinion, not a clean result)")
        print("-" * 74)
        print("These names were not found in the data. Usually the CNA writes the")
        print("product name differently. Do not read this as safe.\n")
        for row in unknown.iter_rows(named=True):
            print(f"  {row['product']}" + (f"  {row['version']}" if row["version"] else ""))

    if detail_rows:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        pl.DataFrame(detail_rows).write_csv(args.out)
        print(f"\nfull detail written to {args.out}")
        print("Every CVE listed there is checkable at https://www.cve.org")

    print("\n" + "-" * 74)
    print("These are vulnerabilities NVD publishes without product identifiers.")
    print("A scanner that matches on CPE has nothing to match them against.")
    print("Whether your particular scanner misses them depends on how it works,")
    print("which this tool does not test.")
    print("-" * 74)


if __name__ == "__main__":
    main()
