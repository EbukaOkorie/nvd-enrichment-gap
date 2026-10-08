"""
Match a user's software against CVEs that NVD left without CPE data.

Two parts.

Version comparison, which is per type rather than universal. semver and dotted
numeric versions can be ordered. rpm versions carry epoch and release fields
and order differently. git hashes and "custom" strings have no order at all, so
those can only ever match exactly. Applying one comparison rule to all of them
produces confident wrong answers, which is worse than admitting ignorance.

Name matching, which tries progressively looser keys and records which one hit,
so a caller can weigh an exact slug match differently from a compact one.

Also carries a validation mode. The entries that do have a CNA-supplied CPE act
as ground truth: build a CPE from the vendor and product fields, compare it to
the published one, and the agreement rate measures whether normalisation is
actually right rather than merely plausible. Every such entry is scored, and
the result is broken down by CNA, because two or three large publishers supply
most of the ground truth and an overall figure mostly describes them.

Usage:
    python src/match.py --validate
    python src/match.py --product "WooCommerce Subscriptions" --version 4.2.1
    python src/match.py --product wordpress --ecosystem wordpress
"""

from __future__ import annotations

import argparse
import json
import re
from functools import cmp_to_key
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "normalised_products.parquet"

# Version types we can order. Anything else is exact match only.
ORDERABLE = {"semver", "python", "maven", "release", "patch", None, "", "custom"}
RPM_LIKE = {"rpm", "deb"}
UNORDERABLE = {"git", "original_commit_for_fix", "commit", "date"}

NUMERIC_CHUNK = re.compile(r"(\d+|[a-z]+)", re.IGNORECASE)


def split_version(text: str) -> list:
    """Split into comparable chunks. Digits compare numerically, letters
    lexically, and a numeric chunk outranks a letter chunk so 1.0 beats
    1.0-beta."""
    parts = []
    for token in re.split(r"[.\-_+~:]", text.strip().lower()):
        for chunk in NUMERIC_CHUNK.findall(token):
            parts.append(int(chunk) if chunk.isdigit() else chunk)
    return parts


def compare_versions(a: str, b: str) -> int | None:
    """-1, 0, 1, or None when the two are not comparable."""
    if a is None or b is None:
        return None
    pa, pb = split_version(a), split_version(b)
    if not pa or not pb:
        return None

    for x, y in zip(pa, pb):
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return -1 if x < y else 1
        elif isinstance(x, str) and isinstance(y, str):
            if x != y:
                return -1 if x < y else 1
        else:
            # A numeric chunk sorts above a letter chunk: 1.0 > 1.0rc.
            return 1 if isinstance(x, int) else -1

    if len(pa) == len(pb):
        return 0
    # Trailing letter chunks mean a prerelease, so shorter is greater.
    tail = (pa if len(pa) > len(pb) else pb)[min(len(pa), len(pb)):]
    longer_is_pre = isinstance(tail[0], str)
    if len(pa) > len(pb):
        return -1 if longer_is_pre else 1
    return 1 if longer_is_pre else -1


def strip_rpm(text: str) -> str:
    """Drop the epoch and distribution release so 2:3.28.1-2.el7_9 compares as
    3.28.1. Crude, and it means two builds of the same upstream version look
    identical, which is the safer error here."""
    without_epoch = text.split(":", 1)[-1]
    return without_epoch.split("-", 1)[0]


def release_matches(candidate: str, trailing: str | None) -> bool | None:
    """Where a product name carried its release number, that number is the
    version constraint: "Red Hat Enterprise Linux 9" means release 9, and a
    user on 9.4 is in scope while one on 8 is not.

    Returns None when there is no release number to compare against."""
    if not trailing:
        return None
    user = split_version(candidate)
    rel = split_version(trailing)
    if not user or not rel:
        return None
    # Compare only as many leading chunks as the release number carries.
    return user[: len(rel)] == rel


def version_in_range(candidate: str, row: dict) -> tuple[bool, str]:
    """Does the user's version fall in this affected range?

    Returns the verdict and how confident we are in it."""
    vtype = (row.get("version_type") or "").lower()
    lower, upper = row.get("lower"), row.get("upper")

    # Many records carry no version detail but do name a release in the
    # product string. That release is the only constraint available.
    if lower is None and upper is None:
        verdict = release_matches(candidate, row.get("product_trailing_version"))
        if verdict is True:
            return True, "release_match"
        if verdict is False:
            return False, "release_mismatch"
        return False, "no_bounds"

    if vtype in UNORDERABLE:
        if lower and candidate.strip().lower() == lower.strip().lower():
            return True, "exact"
        return False, "unorderable"

    cand = candidate
    if vtype in RPM_LIKE:
        cand = strip_rpm(candidate)
        lower = strip_rpm(lower) if lower else None
        upper = strip_rpm(upper) if upper else None

    if lower is not None and upper is not None and lower == upper:
        cmp = compare_versions(cand, lower)
        if cmp is None:
            return False, "incomparable"
        return cmp == 0, "exact"

    if lower is not None:
        cmp = compare_versions(cand, lower)
        if cmp is None:
            return False, "incomparable"
        if cmp < 0 or (cmp == 0 and not row.get("lower_inclusive", True)):
            return False, "below_range"

    if upper is not None:
        cmp = compare_versions(cand, upper)
        if cmp is None:
            return False, "incomparable"
        if cmp > 0 or (cmp == 0 and not row.get("upper_inclusive", False)):
            return False, "above_range"
    else:
        return True, "unbounded_above"

    return True, "in_range"


def name_candidates(text: str) -> dict:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from normalise import slugify, compact, cpe_form, TRAILING_VERSION

    slug = slugify(text)
    keys = {"slug": slug, "compact": compact(text), "cpe": cpe_form(text)}

    # The stored side has the vendor prefix and trailing release stripped, so
    # the query needs the same treatment. The vendor is unknown here, so try
    # progressively dropping leading tokens: "red-hat-enterprise-linux" also
    # tries "hat-enterprise-linux" and "enterprise-linux". Longest first, and
    # never down to a single short token, which would match far too much.
    variants = []
    if slug:
        trimmed = TRAILING_VERSION.sub("", slug) or slug
        for candidate in dict.fromkeys([slug, trimmed]):
            parts = candidate.split("-")
            for start in range(len(parts) - 1):
                suffix = "-".join(parts[start:])
                if len(suffix) >= 4 and suffix not in variants:
                    variants.append(suffix)
    keys["variants"] = variants
    return keys


def find(df: pl.DataFrame, product: str, version: str | None,
         cpe_absent_only: bool = True) -> pl.DataFrame:
    keys = name_candidates(product)

    tiers = [
        ("product_slug_exact", pl.col("product_slug") == keys["slug"]),
        ("product_base_exact", pl.col("product_base") == keys["slug"]),
        ("package_slug_exact", pl.col("package_slug") == keys["slug"]),
        ("product_compact", pl.col("product_compact") == keys["compact"]),
        ("product_base_compact", pl.col("product_base_compact") == keys["compact"]),
    ]
    # A name written in two scripts, matched on its Latin words alone. Weaker
    # than the tiers above: those words can be the product ("UEditor - 百度编辑器")
    # or only the platform it runs on ("WordPress 淘宝客插件"). It is tried only
    # when nothing above matched, and the tier name is reported so a caller
    # can treat it with suspicion.
    if "product_latin" in df.columns:
        tiers.append(("latin_part", pl.col("product_latin") == keys["slug"]))
    # Looser, so it comes last: the query with leading tokens dropped.
    for variant in keys.get("variants") or []:
        tiers.append((f"variant:{variant}", pl.col("product_base") == variant))

    hits = None
    tier_used = None
    for name, expr in tiers:
        if keys["slug"] is None:
            break
        found = df.filter(expr)
        if not found.height:
            continue

        # Filter inside the loop, not after it. A tier can match rows that all
        # get filtered out, and stopping there would report nothing while a
        # looser tier still had real hits.
        if cpe_absent_only and "nvd_cpe_absent" in found.columns:
            found = found.filter(pl.col("nvd_cpe_absent"))
        # Entries marked unaffected describe safe versions, not vulnerable ones.
        found = found.filter(pl.col("status") == "affected")
        if not found.height:
            continue

        hits, tier_used = found, name
        break

    if hits is None or not hits.height:
        return pl.DataFrame()

    hits = hits.with_columns(pl.lit(tier_used).alias("match_tier"))

    if version is None:
        return hits.with_columns(
            pl.lit("no_version_supplied").alias("version_verdict"),
            pl.lit(True).alias("version_match"),
        )

    verdicts, matches = [], []
    for row in hits.iter_rows(named=True):
        ok, why = version_in_range(version, row)
        verdicts.append(why)
        matches.append(ok)

    return hits.with_columns(
        pl.Series("version_verdict", verdicts),
        pl.Series("version_match", matches),
    ).filter(pl.col("version_match"))


def _published_names(cna_cpes: str | None) -> set[tuple[str, str]]:
    """Vendor and product pairs from the CPEs a CNA published for an entry."""
    try:
        cpes = json.loads(cna_cpes or "[]")
    except json.JSONDecodeError:
        return set()
    published = set()
    for cpe in cpes if isinstance(cpes, list) else []:
        if not isinstance(cpe, str):
            continue
        parts = cpe.split(":")
        # cpe:2.3:a:vendor:product:...  or  cpe:/a:vendor:product:...
        if cpe.startswith("cpe:2.3:") and len(parts) > 4:
            published.add((parts[3].lower(), parts[4].lower()))
        elif len(parts) > 3:
            published.add((parts[2].lower(), parts[3].lower()))
    return published


def _bare(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def score_entries(truth: pl.DataFrame) -> pl.DataFrame:
    """Compare each entry's constructed names with the CPE its CNA published.

    Returns the comparable entries with six boolean columns: vendor, product
    and both, each strict and with separators ignored."""
    rows = []
    for row in truth.iter_rows(named=True):
        published = _published_names(row["cna_cpes"])
        if not published:
            continue
        v_ok = any(row["vendor_cpe"] == v for v, _ in published)
        p_ok = any(row["product_cpe"] == p for _, p in published)
        # Separators are stripped from BOTH sides. Comparing a stripped left
        # side against an unstripped right side was the bug that once made the
        # product column show no gain at all.
        v_ok_c = v_ok or any(_bare(row["vendor_compact"]) == _bare(v) for v, _ in published)
        p_ok_c = p_ok or any(
            _bare(row["product_compact"]) == _bare(p)
            or _bare(row["product_base_compact"]) == _bare(p)
            for _, p in published
        )
        first = sorted(published)[0]
        rows.append({
            "cna": row["cna"],
            "vendor_raw": row["vendor_raw"],
            "product_raw": row["product_raw"],
            "built": f"{row['vendor_cpe']}:{row['product_cpe']}",
            "published": f"{first[0]}:{first[1]}",
            "vendor_strict": v_ok, "product_strict": p_ok, "both_strict": v_ok and p_ok,
            "vendor": v_ok_c, "product": p_ok_c, "both": v_ok_c and p_ok_c,
        })
    return pl.DataFrame(rows, schema={
        "cna": pl.Utf8, "vendor_raw": pl.Utf8, "product_raw": pl.Utf8,
        "built": pl.Utf8, "published": pl.Utf8,
        "vendor_strict": pl.Boolean, "product_strict": pl.Boolean, "both_strict": pl.Boolean,
        "vendor": pl.Boolean, "product": pl.Boolean, "both": pl.Boolean,
    })


def _pct(frame: pl.DataFrame, column: str) -> float:
    return frame[column].mean() * 100 if frame.height else 0.0


def validate(df: pl.DataFrame, top: int = 15) -> pl.DataFrame | None:
    """Check name normalisation against CNA-supplied CPEs, which are the only
    ground truth available.

    Scores every entry that has one. An earlier version scored the first 4,000
    rows of the table, which made the result depend on the order the records
    happened to arrive in and on how many version specs each entry carried."""
    truth = df.filter(pl.col("has_cna_cpe") & pl.col("product_cpe").is_not_null())
    if not truth.height:
        print("no entries carry a CNA-supplied CPE")
        return None

    # The table holds one row per version spec. Count each affected entry
    # once, or an entry listing forty versions outweighs one listing a single
    # version forty to one.
    entry_key = ["cve_id", "vendor_raw", "product_raw"]
    truth = truth.unique(subset=entry_key, keep="first", maintain_order=True)
    scored = score_entries(truth)
    if not scored.height:
        print("nothing comparable")
        return None

    print("=" * 74)
    print("NAME NORMALISATION AGAINST CNA-PUBLISHED CPEs")
    print("=" * 74)
    print(f"affected entries with a CNA-supplied CPE:  {scored.height}\n")
    print(f"{'':22}{'strict':>10}{'with compact':>16}")
    for label, col in (("vendor matches:", "vendor"), ("product matches:", "product"), ("both match:", "both")):
        print(f"{label:<22}{_pct(scored, col + '_strict'):9.1f}%{_pct(scored, col):15.1f}%")
    print("\nThe compact column drops separators, which is the difference between")
    print("red_hat and redhat. The gap between the two columns is how much of the")
    print("mismatch is purely punctuation rather than genuinely different naming.")

    # The same question with every distinct name counted once, so a publisher
    # that repeats one product across thousands of CVEs counts once for it.
    names = scored.unique(subset=["vendor_raw", "product_raw"], keep="first", maintain_order=True)
    print(f"\ncounting each distinct vendor and product name once ({names.height} names):")
    print(f"{'both match:':<22}{_pct(names, 'both_strict'):9.1f}%{_pct(names, 'both'):15.1f}%")

    by_cna = (
        scored.group_by("cna")
        .agg(
            pl.len().alias("entries"),
            (pl.col("vendor").mean() * 100).round(1).alias("vendor_pct"),
            (pl.col("product").mean() * 100).round(1).alias("product_pct"),
            (pl.col("both").mean() * 100).round(1).alias("both_pct"),
        )
        .with_columns((pl.col("entries") / scored.height * 100).round(1).alias("share_pct"))
        .sort("entries", descending=True)
        .select(["cna", "entries", "share_pct", "vendor_pct", "product_pct", "both_pct"])
    )
    print("\n" + "-" * 74)
    print("BY CNA (with compact)")
    print("-" * 74)
    print("share_pct is how much of the test set each CNA supplies. Where two or")
    print("three CNAs supply most of it, the overall figure above mostly describes")
    print("them, so read the rows rather than the total.\n")
    with pl.Config(tbl_rows=top, tbl_width_chars=100, fmt_str_lengths=24,
                   tbl_hide_dataframe_shape=True, tbl_hide_column_data_types=True):
        print(by_cna.head(top))

    dominant = by_cna.filter(pl.col("share_pct") > 20)["cna"].to_list()
    if dominant:
        rest = scored.filter(~pl.col("cna").is_in(dominant))
        if rest.height:
            print(f"\nwithout {', '.join(dominant)} (each over 20% of the test set):")
            print(f"{'both match:':<22}{_pct(rest, 'both_strict'):9.1f}%{_pct(rest, 'both'):15.1f}%"
                  f"   across {rest.height} entries")

    # Where the test has nothing to say. A CNA that publishes no CPEs supplies
    # no ground truth, and those are the CNAs whose records NVD leaves bare.
    if "nvd_cpe_absent" in df.columns:
        gap = (
            df.filter(pl.col("nvd_cpe_absent").fill_null(False))
            .unique(subset=entry_key)
            .group_by("cna").agg(pl.len().alias("cpe_absent_entries"))
        )
        coverage = (
            gap.join(by_cna.select(["cna", pl.col("entries").alias("ground_truth_entries"), "both_pct"]),
                     on="cna", how="left")
            .with_columns(pl.col("ground_truth_entries").fill_null(0))
            .sort("cpe_absent_entries", descending=True)
        )
        total_gap = coverage["cpe_absent_entries"].sum()
        blind = coverage.filter(pl.col("ground_truth_entries") == 0)["cpe_absent_entries"].sum()
        print("\n" + "-" * 74)
        print("WHAT THIS TEST CANNOT SEE")
        print("-" * 74)
        print("CNAs ranked by affected entries on CVEs that NVD publishes without CPE,")
        print("with how much ground truth each one supplies. A zero means matching")
        print("accuracy for that CNA is unmeasured, not that it is good or bad.\n")
        with pl.Config(tbl_rows=top, tbl_width_chars=100, fmt_str_lengths=24,
                       tbl_hide_dataframe_shape=True, tbl_hide_column_data_types=True):
            print(coverage.head(top))
        if total_gap:
            print(f"\n{blind} of {total_gap} CPE-absent entries ({blind / total_gap * 100:.1f}%) come from "
                  f"CNAs with no ground truth at all.")

    print("\n" + "-" * 74)
    print("DISAGREEMENT EXAMPLES (at most two per CNA)")
    print("-" * 74)
    misses = names.filter(~pl.col("both"))
    shown: dict[str, int] = {}
    printed = 0
    for row in misses.iter_rows(named=True):
        if printed >= 12:
            break
        if shown.get(row["cna"], 0) >= 2:
            continue
        shown[row["cna"]] = shown.get(row["cna"], 0) + 1
        printed += 1
        print(f"  built {row['built'][:36]:<36} published {row['published'][:34]}")

    print("\nA low score does not mean the code is broken. CNAs choose CPE names")
    print("that often differ from their own vendor and product fields, so this")
    print("measures how far apart those two are. It is the ceiling on constructing")
    print("CPEs without a dictionary lookup.")
    return scored


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--product")
    parser.add_argument("--version")
    parser.add_argument("--limit", type=int, default=25)
    args = parser.parse_args()

    if not DATA.exists():
        raise SystemExit(f"{DATA} not found. Run normalise.py first.")
    df = pl.read_parquet(DATA)

    if args.validate:
        validate(df)
        return

    if not args.product:
        raise SystemExit("pass --product, or --validate")

    hits = find(df, args.product, args.version)
    if not hits.height:
        print(f"no CPE-absent CVEs matched {args.product!r}"
              + (f" at version {args.version}" if args.version else ""))
        return

    cves = hits["cve_id"].unique()
    print(f"\n{len(cves)} CVE(s) affect {args.product!r}"
          + (f" at {args.version}" if args.version else "")
          + " and carry no CPE data in NVD\n")

    cols = ["cve_id", "cna", "date_published", "product_raw",
            "product_trailing_version", "lower", "upper",
            "version_verdict", "match_tier"]
    with pl.Config(tbl_rows=args.limit, tbl_width_chars=140, fmt_str_lengths=26):
        print(hits.select(cols).head(args.limit))

    print("\nverdict counts:")
    for verdict, count in hits.group_by("version_verdict").len().sort("len", descending=True).iter_rows():
        print(f"  {verdict:<20} {count}")


if __name__ == "__main__":
    main()
