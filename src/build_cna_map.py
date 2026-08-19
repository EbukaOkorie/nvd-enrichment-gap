"""
Resolve the assigner identifiers in the NVD data to named CNAs and ecosystems.

NVD reports an assigner as either a contact email or a bare UUID. The official
CNA list keys on shortName and carries contact emails, so emails resolve
automatically. UUIDs do not appear in that list and need identifying by hand.

Writes data/reference/cna_map.csv, which the coverage audit reads.

Usage:
    python src/build_cna_map.py
    python src/build_cna_map.py --unresolved   # what still needs a human
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx
import polars as pl

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "cves.parquet"
REF = ROOT / "data" / "reference"
ECOSYSTEMS = REF / "ecosystems.json"
CNA_CACHE = REF / "cna_list.json"
OUT = REF / "cna_map.csv"

CNA_LIST_URL = (
    "https://raw.githubusercontent.com/CVEProject/cve-website/"
    "dev/src/assets/data/CNAsList.json"
)


def fetch_cna_list(refresh: bool = False) -> list[dict]:
    if CNA_CACHE.exists() and not refresh:
        return json.loads(CNA_CACHE.read_text(encoding="utf-8"))
    print("fetching official CNA list")
    with httpx.Client(follow_redirects=True) as client:
        r = client.get(CNA_LIST_URL, timeout=60.0)
        r.raise_for_status()
    data = r.json()
    REF.mkdir(parents=True, exist_ok=True)
    CNA_CACHE.write_text(json.dumps(data), encoding="utf-8")
    print(f"cached {len(data)} CNAs")
    return data


def email_index(cnas: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    """Two lookups: exact contact email, and email domain.

    NVD does not always report the same address a CNA lists officially, so
    exact matching alone leaves large CNAs unresolved. Domain matching catches
    those. It is looser, so exact always wins."""
    exact: dict[str, dict] = {}
    domain: dict[str, dict] = {}
    for entry in cnas:
        for contact in entry.get("contact") or []:
            for email in contact.get("email") or []:
                addr = (email.get("emailAddr") or "").strip().lower()
                if not addr or "@" not in addr:
                    continue
                exact.setdefault(addr, entry)
                domain.setdefault(addr.split("@", 1)[1], entry)
    return exact, domain


def load_config() -> dict:
    return json.loads(ECOSYSTEMS.read_text(encoding="utf-8"))


def ecosystem_index(config: dict) -> dict[str, str]:
    """shortName -> ecosystem key."""
    out: dict[str, str] = {}
    for key, spec in config["ecosystems"].items():
        for short in spec["cnas"]:
            out[short.lower()] = key
    return out


def resolve(assigner: str, exact, domain, by_short, overrides) -> tuple[dict | None, str]:
    """Returns the CNA entry and how it was matched."""
    key = (assigner or "").strip().lower()
    if key in overrides:
        entry = by_short.get(overrides[key].lower())
        if entry:
            return entry, "override"
    if key in exact:
        return exact[key], "email"
    if "@" in key:
        dom = key.split("@", 1)[1]
        if dom in domain:
            return domain[dom], "domain"
    return None, "unresolved"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unresolved", action="store_true", help="only list what needs manual work")
    parser.add_argument("--refresh", action="store_true", help="refetch the CNA list")
    args = parser.parse_args()

    if not DATA.exists():
        raise SystemExit(f"{DATA} not found. Run build_dataset.py first.")

    cnas = fetch_cna_list(args.refresh)
    exact, domain = email_index(cnas)
    by_short = {e["shortName"].lower(): e for e in cnas}
    config = load_config()
    overrides = {k.lower(): v for k, v in (config.get("assigner_overrides") or {}).items()}
    by_eco = ecosystem_index(config)

    df = pl.read_parquet(DATA).filter(~pl.col("is_rejected"))
    counts = (
        df.group_by("assigner")
        .agg(
            pl.len().alias("cves"),
            pl.col("cpe_absent").sum().alias("cpe_absent"),
            (pl.col("cpe_absent").mean() * 100).round(1).alias("pct_no_cpe"),
        )
        .sort("cves", descending=True)
    )

    rows = []
    for assigner, cves, absent, pct in counts.iter_rows():
        entry, how = resolve(assigner, exact, domain, by_short, overrides)
        short = entry["shortName"] if entry else None
        rows.append({
            "assigner": assigner,
            "short_name": short,
            "organisation": entry["organizationName"] if entry else None,
            "ecosystem": by_eco.get((short or "").lower()),
            "matched_by": how,
            "cves": cves,
            "cpe_absent": absent,
            "pct_no_cpe": pct,
            "is_uuid": entry is None and "@" not in (assigner or ""),
        })

    out = pl.DataFrame(rows)

    named = out.filter(pl.col("short_name").is_not_null())
    placed = out.filter(pl.col("ecosystem").is_not_null())
    total_cves = out["cves"].sum()

    print(f"\nassigners in data:      {out.height}")
    print(f"resolved to a CNA:      {named.height}  ({named['cves'].sum() / total_cves * 100:.1f}% of CVEs)")
    print(f"placed in an ecosystem: {placed.height}  ({placed['cves'].sum() / total_cves * 100:.1f}% of CVEs)")
    print("\nmatched by:")
    for how, n in out.group_by("matched_by").len().sort("len", descending=True).iter_rows():
        print(f"  {how:<12} {n}")

    if args.unresolved:
        gaps = out.filter(pl.col("ecosystem").is_null() & (pl.col("cves") >= 50)).sort("cves", descending=True)
        print("\n" + "=" * 78)
        print("NEEDS A HUMAN (50+ CVEs, no ecosystem assigned)")
        print("=" * 78)
        print("UUID rows cannot be resolved from the official list. Look one up at")
        print("cve.org to identify it, then add its shortName to ecosystems.json.\n")
        with pl.Config(tbl_rows=40, tbl_width_chars=120, fmt_str_lengths=44):
            print(gaps.select(["assigner", "short_name", "organisation", "cves", "pct_no_cpe", "is_uuid"]))
    else:
        print("\n" + "=" * 78)
        print("CPE ABSENCE BY ECOSYSTEM")
        print("=" * 78)
        summary = (
            placed.group_by("ecosystem")
            .agg(
                pl.col("cves").sum().alias("cves"),
                pl.col("cpe_absent").sum().alias("no_cpe"),
            )
            .with_columns((pl.col("no_cpe") / pl.col("cves") * 100).round(1).alias("pct_no_cpe"))
            .sort("pct_no_cpe", descending=True)
        )
        with pl.Config(tbl_rows=20, tbl_width_chars=90):
            print(summary)

    REF.mkdir(parents=True, exist_ok=True)
    out.write_csv(OUT)
    print(f"\nwritten to {OUT}")
    if not args.unresolved:
        print("Run with --unresolved to see which assigners still need placing.")


if __name__ == "__main__":
    main()
