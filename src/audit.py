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

Four outcomes per item, and the difference matters:

    matched      the name was found and CPE-absent CVEs apply
    covered      the name was found and NVD publishes CPE for all its CVEs
    no_cves      the name was found but nothing applies at that version
    unrecognised the name was not found at all

An unrecognised item is not a clean bill of health. It means this tool has no
opinion, usually because the CNA writes that product's name differently. Those
are reported separately rather than counted as safe.

Matched CVEs are then split by what NVD has said about them, because "no CPE"
covers different situations:

    deferred     NVD has marked the record as not scheduled for enrichment.
                 This is the settled gap.
    queued       NVD has not processed the record yet. It has no CPE today
                 and may or may not gain one.
    analysed     NVD has processed the record and it still carries no CPE.

A report that adds these together overstates the permanent gap, since a CVE
published last week may simply not have been processed yet. A report that
drops the queued ones understates today's exposure. So both are shown, never
summed without the split beside them.

Usage:
    python src/audit.py --inventory my_stack.txt
    python src/audit.py --inventory my_stack.csv --out report.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import date
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from match import find, name_candidates  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "normalised_products.parquet"
DEFAULT_OUT = ROOT / "data" / "outputs" / "audit_report.csv"

SPLITTERS = re.compile(r"\s*(?:==|,|\t|\s+)\s*")

# NVD statuses that mean a record is waiting to be processed.
QUEUED_STATUSES = {"Received", "Awaiting Analysis", "Undergoing Analysis"}

# A queued record older than this has waited long enough that calling it
# "recent" stops being a fair description.
STALE_DAYS = 30


def gap_type(nvd_status: str | None) -> str:
    """Why a CVE has no CPE in NVD, as far as NVD's own status says."""
    if nvd_status == "Deferred":
        return "deferred"
    if nvd_status in QUEUED_STATUSES:
        return "queued"
    if nvd_status is None:
        return "unknown"
    return "analysed"


def days_between(published: str | None, as_of: date) -> int | None:
    try:
        return (as_of - date.fromisoformat((published or "")[:10])).days
    except ValueError:
        return None


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
    if "product_latin" in df.columns:
        exprs.append(pl.col("product_latin") == keys["slug"])
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

    has_status = "nvd_status" in df.columns
    as_of_text = df["nvd_as_of"][0] if "nvd_as_of" in df.columns and df.height else None
    try:
        as_of = date.fromisoformat(as_of_text) if as_of_text else date.today()
    except ValueError:
        as_of = date.today()

    print(f"auditing {len(items)} item(s) against {df.height} product entries")
    if as_of_text:
        print(f"NVD enrichment state as of {as_of_text}")
    print()

    results = []
    detail: dict[tuple[str, str, str], dict] = {}

    for name, version in items:
        hits = find(df, name, version)
        if args.since and hits.height:
            hits = hits.filter(pl.col("date_published") >= args.since)

        counts = {"deferred": 0, "queued": 0, "analysed": 0, "unknown": 0}
        if hits.height:
            tiers = sorted(set(hits["match_tier"].to_list()))
            status = "matched"
            item_cves: dict[str, str] = {}
            for row in hits.iter_rows(named=True):
                kind = gap_type(row["nvd_status"]) if has_status else "unknown"
                item_cves[row["cve_id"]] = kind
                # One line per CVE per inventory item. A CVE listing forty
                # version specs is still one vulnerability.
                key = (name, version or "", row["cve_id"])
                if key not in detail:
                    detail[key] = {
                        "input_product": name,
                        "input_version": version or "",
                        "cve_id": row["cve_id"],
                        "gap_type": kind,
                        "nvd_status": (row["nvd_status"] if has_status else None) or "",
                        "date_published": row["date_published"],
                        "days_since_published": days_between(row["date_published"], as_of),
                        "cna": row["cna"],
                        "matched_product": row["product_raw"],
                        "match_tier": row["match_tier"],
                        "version_verdict": row["version_verdict"],
                    }
            for kind in item_cves.values():
                counts[kind] += 1
            cve_count = len(item_cves)
        else:
            cve_count, tiers = 0, []
            known = name_rows(df, name)
            if not known.height:
                status = "unrecognised"
            elif "nvd_cpe_absent" in known.columns and not known["nvd_cpe_absent"].fill_null(False).any():
                # Found, and no CVE for it is known to lack CPE data in NVD.
                status = "covered"
            else:
                status = "no_cves"

        results.append({
            "product": name,
            "version": version or "",
            "status": status,
            "deferred": counts["deferred"],
            "queued": counts["queued"],
            "analysed": counts["analysed"],
            "unknown": counts["unknown"],
            "cve_count": cve_count,
            "match_tiers": ", ".join(tiers),
        })

    summary = pl.DataFrame(results)
    matched = summary.filter(pl.col("status") == "matched")
    unknown = summary.filter(pl.col("status") == "unrecognised")
    clean = summary.filter(pl.col("status") == "no_cves")
    covered = summary.filter(pl.col("status") == "covered")

    detail_rows = list(detail.values())
    # A CVE can hit two inventory items. Count it once in the totals.
    by_cve: dict[str, dict] = {}
    for row in detail_rows:
        by_cve.setdefault(row["cve_id"], row)
    kinds = [r["gap_type"] for r in by_cve.values()]
    queued_days = sorted(
        r["days_since_published"] for r in by_cve.values()
        if r["gap_type"] == "queued" and r["days_since_published"] is not None
    )
    stale = sum(1 for d in queued_days if d > STALE_DAYS)

    print("=" * 74)
    print("BLIND SPOT SUMMARY")
    print("=" * 74)
    print(f"items audited:                {len(items)}")
    print(f"items with invisible CVEs:    {matched.height}")
    print(f"items fully covered by NVD:   {covered.height}")
    print(f"items with none at this ver:  {clean.height}")
    print(f"items not recognised:         {unknown.height}")
    print(f"\ndistinct CVEs with no CPE in NVD: {len(by_cve)}")
    if has_status:
        print(f"  deferred, NVD will not enrich them:   {kinds.count('deferred'):>6}")
        line = f"  queued, not yet processed by NVD:     {kinds.count('queued'):>6}"
        if queued_days:
            median = queued_days[len(queued_days) // 2]
            line += f"   (median wait {median} days, {stale} waiting over {STALE_DAYS})"
        print(line)
        if kinds.count("analysed"):
            print(f"  analysed, and still no CPE:           {kinds.count('analysed'):>6}")
        if kinds.count("unknown"):
            print(f"  NVD status not known:                 {kinds.count('unknown'):>6}")
    else:
        print("  (this product table carries no NVD status, so these cannot be split")
        print("   into deferred and queued. Rerun normalise.py to add it.)")
    if args.since:
        print(f"(published on or after {args.since})")

    if matched.height:
        print("\n" + "-" * 74)
        print("WHERE THE GAPS ARE")
        print("-" * 74)
        cols = ["product", "version"]
        if has_status:
            cols += ["deferred", "queued"]
            if matched["analysed"].sum():
                cols.append("analysed")
            if matched["unknown"].sum():
                cols.append("unknown")
        cols += ["cve_count", "match_tiers"]
        with pl.Config(tbl_rows=40, tbl_width_chars=120, fmt_str_lengths=34,
                       tbl_hide_dataframe_shape=True, tbl_hide_column_data_types=True):
            print(matched.sort(["deferred", "cve_count"], descending=True).select(cols))
        if any(t == "latin_part" for row in matched["match_tiers"].to_list() for t in row.split(", ")):
            print("\nA latin_part match means only the Latin-script words of a name in two")
            print("scripts matched. Check the matched_product column before relying on it.")

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
        pl.DataFrame(detail_rows, infer_schema_length=None).write_csv(args.out)
        print(f"\nfull detail written to {args.out}")
        print("Every CVE listed there is checkable at https://www.cve.org")

    print("\n" + "-" * 74)
    print("These are vulnerabilities NVD publishes without product identifiers.")
    print("A scanner that matches on CPE has nothing to match them against.")
    if has_status:
        print("\nDeferred records are the settled gap: NVD has said it does not plan")
        print("to enrich them. Queued records have no CPE today and may gain one, so")
        print("that count is a snapshot of current exposure, not a permanent total.")
        print("Neither list is a list of safe software.")
        if as_of_text:
            print(f"\nNVD state is as of {as_of_text}. CVEs published after that date are")
            print("not assessed. Pull the latest snapshots and rerun normalise.py to")
            print("refresh it.")
    print("\nWhether your particular scanner misses these depends on how it works,")
    print("which this tool does not test.")
    print("-" * 74)


if __name__ == "__main__":
    main()
