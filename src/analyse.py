"""
Analyse the enrichment gap.

Produces three tables from data/interim/cves.parquet:

  1. Monthly cohorts: share of each publication month still lacking CPE data.
  2. The same split by enrichment type, so CPE and CVSS can be compared.
  3. CNA breakdown for post-policy records, used as an ecosystem proxy.

Ecosystem note: vendor names come from CPE strings, so records lacking CPE
carry no vendor information by definition. The assigning CNA is used as a
proxy instead, since CNAs map closely onto software ecosystems.

Usage:
    python src/analyse.py
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "cves.parquet"
OUT_DIR = ROOT / "data" / "outputs"

POLICY_CHANGE = "2026-04-15"
MONTHS_SHOWN = 30


def load() -> pl.DataFrame:
    if not DATA.exists():
        raise SystemExit(f"{DATA} not found. Run build_dataset.py first.")
    df = pl.read_parquet(DATA)
    # Rejected records are not vulnerabilities and are excluded throughout.
    return df.filter(~pl.col("is_rejected") & pl.col("published_date").is_not_null())


def monthly_cohorts(df: pl.DataFrame) -> pl.DataFrame:
    return (
        df.with_columns(pl.col("published_date").dt.truncate("1mo").alias("cohort"))
        .group_by("cohort")
        .agg(
            pl.len().alias("cves"),
            (pl.col("cpe_absent").mean() * 100).round(1).alias("pct_no_cpe"),
            (pl.col("no_nist_cvss").mean() * 100).round(1).alias("pct_no_nist_cvss"),
            (pl.col("no_cvss_at_all").mean() * 100).round(1).alias("pct_no_cvss_at_all"),
            (pl.col("vuln_status") == "Deferred").mean().mul(100).round(1).alias("pct_deferred"),
        )
        .sort("cohort")
    )


def cna_breakdown(df: pl.DataFrame, min_cves: int = 100) -> pl.DataFrame:
    post = df.filter(pl.col("post_policy"))
    return (
        post.group_by("assigner")
        .agg(
            pl.len().alias("cves"),
            pl.col("cpe_absent").sum().alias("no_cpe"),
            (pl.col("cpe_absent").mean() * 100).round(1).alias("pct_no_cpe"),
        )
        .filter(pl.col("cves") >= min_cves)
        .sort("no_cpe", descending=True)
    )


def show(title: str, df: pl.DataFrame, rows: int = 25) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)
    with pl.Config(tbl_rows=rows, tbl_width_chars=110, fmt_str_lengths=40):
        print(df.head(rows))


def main() -> None:
    df = load()
    print(f"analysing {df.height} non-rejected CVEs")

    cohorts = monthly_cohorts(df)
    recent = cohorts.tail(MONTHS_SHOWN)
    show(f"CPE absence by publication month (last {MONTHS_SHOWN})", recent, MONTHS_SHOWN)

    pre = df.filter(~pl.col("post_policy"))
    post = df.filter(pl.col("post_policy"))
    print("\n" + "=" * 78)
    print(f"BEFORE AND AFTER {POLICY_CHANGE}")
    print("=" * 78)
    for label, part in (("published before", pre), ("published on or after", post)):
        if part.height == 0:
            continue
        print(
            f"  {label:<22} n={part.height:>7}  "
            f"no CPE {part['cpe_absent'].mean() * 100:5.1f}%  "
            f"no NIST CVSS {part['no_nist_cvss'].mean() * 100:5.1f}%  "
            f"no CVSS at all {part['no_cvss_at_all'].mean() * 100:5.1f}%"
        )

    cnas = cna_breakdown(df)
    show("Post-policy CPE absence by assigning CNA (100+ CVEs)", cnas, 25)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cohorts.write_csv(OUT_DIR / "monthly_cohorts.csv")
    cnas.write_csv(OUT_DIR / "cna_breakdown.csv")
    print(f"\nwritten to {OUT_DIR}")

    print("\n" + "-" * 78)
    print("CAVEAT: this is a single snapshot. Recent cohorts have had less time")
    print("for enrichment to occur, so some absence reflects processing lag")
    print("rather than a permanent gap. Age and policy regime cannot be fully")
    print("separated from one snapshot alone.")
    print("-" * 78)


if __name__ == "__main__":
    main()
