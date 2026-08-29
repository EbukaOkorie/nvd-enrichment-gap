"""
Normalise CNA-supplied product data into something matchable.

Two jobs.

Names: "Red Hat", "redhat" and "Red Hat, Inc." have to become the same thing
before any comparison works. Produces a slug for ecosystem-style matching and
a CPE-style form for dictionary comparison.

Versions: the affected-version specs come in several shapes and, importantly,
some of them describe versions that are NOT vulnerable. An entry can carry
defaultStatus "affected" with a list of unaffected versions, meaning everything
is vulnerable except those. Reading that the wrong way round inverts the answer,
so status is tracked explicitly rather than assumed.

No version ordering happens here. Comparing "2:3.28.1-2.el7_9" against
"3.28.2" needs rpm semantics, and semver rules do not apply. That belongs in
the matcher, which can pick comparison rules per version type.

Writes data/interim/normalised_products.parquet.

Usage:
    python src/normalise.py
    python src/normalise.py --show-unparsed 30
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent.parent
IN = ROOT / "data" / "interim" / "cna_products.parquet"
NVD = ROOT / "data" / "interim" / "cves.parquet"
OUT = ROOT / "data" / "interim" / "normalised_products.parquet"

# Dropped from the end of vendor names before comparison. Order matters:
# longer forms first so "corporation" is not left as "corp".
LEGAL_SUFFIXES = [
    "corporation", "incorporated", "technologies", "technology", "foundation",
    "software", "systems", "solutions", "holdings", "company", "limited",
    "project", "group", "labs", "gmbh", "s.a.s", "s.a", "b.v", "n.v", "pty",
    "llc", "ltd", "inc", "co", "plc", "ag", "sa", "srl", "spa", "oy", "ab",
]

PLACEHOLDER_NAMES = {"unknown", "n/a", "na", "none", "unspecified", "", "-"}

# A single string that is really a range, e.g. Joomla's "1.0.0-4.1.64".
EMBEDDED_RANGE = re.compile(
    r"^\s*(\d+(?:\.\d+)*(?:[a-z0-9]*)?)\s*(?:-|through|to|\.\.)\s*(\d+(?:\.\d+)*(?:[a-z0-9]*)?)\s*$",
    re.IGNORECASE,
)

WILDCARDS = {"*", "all", "any", "unspecified", ""}

# Declared explicitly for the same reason as in ingest_cve_list.py: several of
# these columns are null across tens of thousands of consecutive rows, so type
# inference from the first rows locks in Null and then fails on a real value.
OUT_SCHEMA = {
    "cve_id": pl.Utf8,
    "cna": pl.Utf8,
    "date_published": pl.Utf8,
    "vendor_raw": pl.Utf8,
    "vendor_slug": pl.Utf8,
    "vendor_cpe": pl.Utf8,
    "vendor_compact": pl.Utf8,
    "product_raw": pl.Utf8,
    "product_slug": pl.Utf8,
    "product_cpe": pl.Utf8,
    "product_compact": pl.Utf8,
    "product_base": pl.Utf8,
    "product_base_compact": pl.Utf8,
    "product_trailing_version": pl.Utf8,
    "package_slug": pl.Utf8,
    "default_status": pl.Utf8,
    "cna_cpes": pl.Utf8,
    "has_cna_cpe": pl.Boolean,
    "status": pl.Utf8,
    "version_type": pl.Utf8,
    "lower": pl.Utf8,
    "lower_inclusive": pl.Boolean,
    "upper": pl.Utf8,
    "upper_inclusive": pl.Boolean,
    "parse_quality": pl.Utf8,
    "nvd_cpe_absent": pl.Boolean,
}


LEADING_ARTICLES = {"the", "a", "an"}


def slugify(name: str | None) -> str | None:
    """Lowercase, strip legal suffixes, hyphen separated."""
    if not name:
        return None
    text = name.strip().lower()
    if text in PLACEHOLDER_NAMES:
        return None

    text = re.sub(r"[\u2018\u2019\u201c\u201d]", "", text)
    text = re.sub(r"[^a-z0-9]+", " ", text).strip()

    parts = text.split()
    while len(parts) > 1 and parts[0] in LEADING_ARTICLES:
        parts = parts[1:]

    changed = True
    while changed and len(parts) > 1:
        changed = False
        for suffix in LEGAL_SUFFIXES:
            tokens = suffix.replace(".", "").split()
            n = len(tokens)
            if len(parts) > n and parts[-n:] == tokens:
                parts = parts[:-n]
                changed = True
                break

    slug = "-".join(parts)
    return slug or None


def compact(name: str | None) -> str | None:
    """Separators removed entirely, so "Red Hat" and "redhat" collapse to the
    same key. Looser than the slug, so it is a fallback rather than the
    primary match, but it catches the most common spelling split."""
    slug = slugify(name)
    return slug.replace("-", "") if slug else None


# Trailing release numbers that belong in the version field rather than the
# product name: "Red Hat Enterprise Linux 10", "Red Hat Data Grid 8".
TRAILING_VERSION = re.compile(r"-(?:v)?\d+(?:-\d+)*$")


def product_base(product: str | None, vendor: str | None) -> tuple[str | None, str | None]:
    """Strip the vendor prefix and any trailing release number from a product
    name, returning the base slug and the number if one was removed.

    CNAs write "Red Hat Enterprise Linux 10" where the CPE says
    "enterprise_linux" with version 10. Without this the two never match."""
    slug = slugify(product)
    if not slug:
        return None, None

    vendor_slug = slugify(vendor)
    if vendor_slug and slug.startswith(vendor_slug + "-"):
        stripped = slug[len(vendor_slug) + 1:]
        if stripped:
            slug = stripped

    trailing = None
    match = TRAILING_VERSION.search(slug)
    if match:
        candidate = slug[: match.start()]
        if candidate:
            trailing = match.group(0).lstrip("-")
            slug = candidate

    return slug or None, trailing


def cpe_form(name: str | None) -> str | None:
    """CPE 2.3 uses underscores where a name has spaces."""
    slug = slugify(name)
    return slug.replace("-", "_") if slug else None


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    return str(value)


def parse_version(spec: dict, default_status: str | None) -> dict:
    """Turn one version object into an explicit range with a status.

    Returns lower and upper bounds as strings. No ordering is attempted."""
    status = (_text(spec.get("status")) or _text(default_status) or "").lower()
    version = _text(spec.get("version")) or ""
    less_than = _text(spec.get("lessThan")) or ""
    less_eq = _text(spec.get("lessThanOrEqual")) or ""
    vtype = (_text(spec.get("versionType")) or "").lower() or None

    lower = version or None
    lower_inclusive = True
    upper = None
    upper_inclusive = False
    quality = "clean"

    if less_than:
        upper = None if less_than in WILDCARDS else less_than
        upper_inclusive = False
        if less_than in WILDCARDS:
            quality = "unbounded_above"
    elif less_eq:
        upper = None if less_eq in WILDCARDS else less_eq
        upper_inclusive = True
        if less_eq in WILDCARDS:
            quality = "unbounded_above"
    elif version:
        match = EMBEDDED_RANGE.match(version)
        if match:
            # A range smuggled into the version string.
            lower, upper = match.group(1), match.group(2)
            upper_inclusive = True
            quality = "range_in_string"
        elif version in WILDCARDS:
            lower = None
            quality = "wildcard_only"
        else:
            upper = version
            upper_inclusive = True
            quality = "single_version"

    if lower is None and upper is None:
        quality = "unparseable"

    return {
        "status": status or "unknown",
        "version_type": vtype,
        "lower": lower,
        "lower_inclusive": lower_inclusive,
        "upper": upper,
        "upper_inclusive": upper_inclusive,
        "parse_quality": quality,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--show-unparsed", type=int, default=15)
    args = parser.parse_args()

    if not IN.exists():
        raise SystemExit(f"{IN} not found. Run ingest_cve_list.py first.")

    src = pl.read_parquet(IN)
    print(f"normalising {src.height} affected entries")

    # Which of these CVEs does NVD publish without CPE data? Without this the
    # audit cannot tell "this product is properly covered" from "I could not
    # find this product", which are opposite answers.
    absent: set[str] = set()
    have_nvd = NVD.exists()
    if have_nvd:
        nvd = pl.read_parquet(NVD)
        absent = set(nvd.filter(pl.col("cpe_absent"))["cve_id"].to_list())
        print(f"  {len(absent)} of {nvd.height} NVD records carry no CPE")
    else:
        print(f"  WARNING: {NVD.name} not found, every row will be marked CPE-absent")

    rows = []
    for rec in src.iter_rows(named=True):
        vendor_slug = slugify(rec["vendor"])
        product_slug = slugify(rec["product"])
        package_slug = slugify(rec["package_name"])
        vendor_compact = compact(rec["vendor"])
        product_compact = compact(rec["product"])
        base, trailing = product_base(rec["product"], rec["vendor"])

        try:
            versions = json.loads(rec["versions_raw"] or "[]")
        except json.JSONDecodeError:
            versions = []
        if not isinstance(versions, list):
            versions = []

        specs = [v for v in versions if isinstance(v, dict)]
        if not specs:
            # No version detail at all. Still matchable by name.
            specs = [{}]

        for spec in specs:
            parsed = parse_version(spec, rec["default_status"])
            rows.append({
                "cve_id": rec["cve_id"],
                "cna": rec["cna"],
                "date_published": rec["date_published"],
                "vendor_raw": rec["vendor"],
                "vendor_slug": vendor_slug,
                "vendor_cpe": cpe_form(rec["vendor"]),
                "vendor_compact": vendor_compact,
                "product_raw": rec["product"],
                "product_slug": product_slug,
                "product_cpe": cpe_form(rec["product"]),
                "product_compact": product_compact,
                "product_base": base,
                "product_base_compact": base.replace("-", "") if base else None,
                "product_trailing_version": trailing,
                "nvd_cpe_absent": (rec["cve_id"] in absent) if have_nvd else True,
                "package_slug": package_slug,
                "default_status": rec["default_status"],
                "cna_cpes": rec["cpes"],
                "has_cna_cpe": rec["cpe_count"] > 0,
                **parsed,
            })

    out = pl.DataFrame(rows, schema=OUT_SCHEMA)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    out.write_parquet(OUT)

    n = out.height
    print("\n" + "=" * 70)
    print("NAMES")
    print("=" * 70)
    print(f"rows (one per version spec):  {n}")
    print(f"vendor slug resolved:         {out.filter(pl.col('vendor_slug').is_not_null()).height:>7}  "
          f"({out.filter(pl.col('vendor_slug').is_not_null()).height / n * 100:.1f}%)")
    print(f"product slug resolved:        {out.filter(pl.col('product_slug').is_not_null()).height:>7}  "
          f"({out.filter(pl.col('product_slug').is_not_null()).height / n * 100:.1f}%)")
    print(f"distinct vendor slugs:        {out['vendor_slug'].n_unique():>7}")
    print(f"distinct vendor compact:      {out['vendor_compact'].n_unique():>7}"
          "   (fewer means spelling variants collapsed)")
    print(f"distinct product slugs:       {out['product_slug'].n_unique():>7}")
    print(f"distinct product compact:     {out['product_compact'].n_unique():>7}")
    print(f"distinct product base:        {out['product_base'].n_unique():>7}"
          "   (vendor prefix and trailing release stripped)")
    stripped = out.filter(pl.col('product_trailing_version').is_not_null()).height
    print(f"trailing release stripped:    {stripped:>7}  ({stripped / n * 100:.1f}%)")

    print("\n" + "=" * 70)
    print("VERSION STATUS (read this before trusting any match)")
    print("=" * 70)
    for status, count in out.group_by("status").len().sort("len", descending=True).iter_rows():
        print(f"  {str(status):<14} {count:>7}  {count / n * 100:5.1f}%")
    print("\n  Entries marked unaffected describe versions that are SAFE.")
    print("  Matching against them without checking status inverts the result.")

    print("\n" + "=" * 70)
    print("VERSION PARSE QUALITY")
    print("=" * 70)
    for quality, count in out.group_by("parse_quality").len().sort("len", descending=True).iter_rows():
        print(f"  {str(quality):<18} {count:>7}  {count / n * 100:5.1f}%")

    print("\nversion types seen:")
    for vtype, count in out.group_by("version_type").len().sort("len", descending=True).head(10).iter_rows():
        print(f"  {str(vtype):<14} {count:>7}")

    bad = out.filter(pl.col("parse_quality") == "unparseable")
    if bad.height and args.show_unparsed:
        print(f"\nunparseable examples ({bad.height} total):")
        cols = ["cna", "product_raw", "cve_id"]
        with pl.Config(tbl_rows=args.show_unparsed, tbl_width_chars=100, fmt_str_lengths=34):
            print(bad.select(cols).head(args.show_unparsed))

    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
