"""
Extract the product data CNAs supply, which NVD is no longer turning into CPE.

This is the raw material the matching engine needs. NVD tells you a CVE has no
CPE. The CNA's own record usually still names the vendor, product and affected
versions. That data is what makes a CPE-absent CVE findable.

Downloads the daily bulk archive rather than fetching records one at a time,
since the target set runs to tens of thousands.

Writes data/interim/cna_products.parquet, one row per affected entry, so a CVE
naming three products produces three rows.

Usage:
    python src/ingest_cve_list.py                 # CPE-absent records only
    python src/ingest_cve_list.py --all           # every record
    python src/ingest_cve_list.py --keep-archive  # do not delete the zip
"""

from __future__ import annotations

import argparse
import json
import os
import re
import zipfile
from pathlib import Path

import httpx
import polars as pl

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "interim" / "cves.parquet"
OUT = ROOT / "data" / "interim" / "cna_products.parquet"
CACHE = ROOT / "data" / "raw" / "cvelist"

RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
RELEASES_PAGE = "https://github.com/CVEProject/cvelistV5/releases"

# Declared explicitly. Several of these fields are null for tens of thousands
# of consecutive records, so letting polars infer types from the first rows
# locks in Null and then fails on the first real value.
SCHEMA = {
    "cve_id": pl.Utf8,
    "cna": pl.Utf8,
    "state": pl.Utf8,
    "date_published": pl.Utf8,
    "vendor": pl.Utf8,
    "vendor_is_unknown": pl.Boolean,
    "product": pl.Utf8,
    "package_name": pl.Utf8,
    "collection_url": pl.Utf8,
    "repo": pl.Utf8,
    "default_status": pl.Utf8,
    "platforms": pl.Utf8,
    "modules": pl.Utf8,
    "cpes": pl.Utf8,
    "cpe_count": pl.Int32,
    "versions_raw": pl.Utf8,
    "version_count": pl.Int32,
}


def _text(value) -> str | None:
    """CNAs occasionally put a list or a number where a string belongs."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    return json.dumps(value)

# The baseline asset is published under the hourly release tag, and its name
# carries a doubled extension: 2026-08-19_all_CVEs_at_midnight.zip.zip
BASELINE_MARKER = "all_CVEs_at_midnight"


def _find_via_api(client: httpx.Client) -> tuple[str, str, int] | None:
    headers = {}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for page in (1, 2, 3):
        r = client.get(RELEASES_API, params={"per_page": 50, "page": page},
                       headers=headers, timeout=60.0)
        if r.status_code == 403:
            print("  GitHub API rate limited, falling back to the releases page")
            return None
        r.raise_for_status()
        releases = r.json()
        if not releases:
            break
        for release in releases:
            for asset in release.get("assets") or []:
                if BASELINE_MARKER in asset.get("name", ""):
                    return asset["name"], asset["browser_download_url"], asset.get("size", 0)
    return None


def _find_via_page(client: httpx.Client) -> tuple[str, str, int] | None:
    """Scrape the releases listing. No API, so no rate limit."""
    r = client.get(RELEASES_PAGE, timeout=60.0)
    r.raise_for_status()
    tags = list(dict.fromkeys(re.findall(r"/releases/tag/(cve_[0-9\-]+_\d{4}Z)", r.text)))

    seen = []
    for tag in tags[:25]:
        seen.append(tag)
        frag = client.get(f"{RELEASES_PAGE}/expanded_assets/{tag}", timeout=60.0)
        if frag.status_code != 200:
            continue
        for href in re.findall(r'href="(/CVEProject/cvelistV5/releases/download/[^"]+)"', frag.text):
            if BASELINE_MARKER in href:
                url = "https://github.com" + href
                head = client.head(url, follow_redirects=True, timeout=60.0)
                size = int(head.headers.get("content-length", 0))
                return href.rsplit("/", 1)[-1], url, size
    print(f"  checked {len(seen)} release tags, none carried a baseline archive")
    return None


def find_baseline_archive(client: httpx.Client) -> tuple[str, str, int]:
    """Locate the most recent full archive of all CVE records."""
    found = _find_via_api(client) or _find_via_page(client)
    if not found:
        raise SystemExit(
            "could not locate a baseline archive. Check "
            f"{RELEASES_PAGE} by hand and pass the URL with --archive-url."
        )
    return found


def download(client: httpx.Client, url: str, dest: Path, size: int) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {dest.name} ({size / 1e6:.0f} MB)")
    done = 0
    with client.stream("GET", url, timeout=None, follow_redirects=True) as r:
        r.raise_for_status()
        with dest.open("wb") as fh:
            for chunk in r.iter_bytes(chunk_size=1 << 20):
                fh.write(chunk)
                done += len(chunk)
                if size and done % (50 << 20) < (1 << 20):
                    print(f"  {done / 1e6:.0f} / {size / 1e6:.0f} MB")
    print(f"  saved {dest.stat().st_size / 1e6:.0f} MB")


def extract_affected(record: dict) -> list[dict]:
    """One row per affected entry. Versions are kept as raw JSON because the
    shapes vary wildly: semver ranges, git hashes, single values, wildcards.
    Normalising them is the matching engine's problem, not ingestion's."""
    meta = record.get("cveMetadata", {}) or {}
    cna = (record.get("containers", {}) or {}).get("cna", {}) or {}
    cve_id = meta.get("cveId")
    if not cve_id:
        return []

    rows = []
    for entry in cna.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        versions = entry.get("versions") or []
        cpes = entry.get("cpes") or []
        vendor = _text(entry.get("vendor"))
        product = _text(entry.get("product"))

        rows.append({
            "cve_id": cve_id,
            "cna": _text(meta.get("assignerShortName")),
            "state": _text(meta.get("state")),
            "date_published": (meta.get("datePublished") or "")[:10] or None,
            "vendor": vendor,
            "vendor_is_unknown": (vendor or "").lower() in ("unknown", "n/a", ""),
            "product": product,
            "package_name": _text(entry.get("packageName")),
            "collection_url": _text(entry.get("collectionURL")),
            "repo": _text(entry.get("repo")),
            "default_status": _text(entry.get("defaultStatus")),
            "platforms": json.dumps(entry.get("platforms") or []),
            "modules": json.dumps(entry.get("modules") or []),
            "cpes": json.dumps(cpes),
            "cpe_count": len(cpes) if isinstance(cpes, list) else 0,
            "versions_raw": json.dumps(versions),
            "version_count": len(versions) if isinstance(versions, list) else 0,
        })
    return rows


def unwrap_archive(archive: Path) -> tuple[Path, bool]:
    """The published asset is a zip containing a single zip, hence the doubled
    .zip.zip extension. Unwrap it so the records are reachable.

    Returns the archive to read and whether it is a temporary extraction."""
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        inner = [n for n in names if n.lower().endswith(".zip")]
        has_records = any(n.endswith(".json") and "CVE-" in n for n in names)

        if has_records or not inner:
            return archive, False

        target = inner[0]
        extracted = archive.parent / Path(target).name
        if extracted.exists() and extracted.stat().st_size > 0:
            print(f"  using already extracted {extracted.name}")
            return extracted, True

        print(f"  archive is nested, extracting {target}")
        with zf.open(target) as src, extracted.open("wb") as dst:
            while chunk := src.read(1 << 22):
                dst.write(chunk)
        print(f"  extracted {extracted.stat().st_size / 1e6:.0f} MB")
        return extracted, True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="ingest every CVE, not just CPE-absent ones")
    parser.add_argument("--keep-archive", action="store_true")
    parser.add_argument("--archive-url", help="download URL, if auto-discovery fails")
    args = parser.parse_args()

    targets: set[str] | None = None
    if not args.all:
        if not DATA.exists():
            raise SystemExit(f"{DATA} not found. Run build_dataset.py first, or pass --all.")
        df = pl.read_parquet(DATA)
        targets = set(
            df.filter(~pl.col("is_rejected") & pl.col("cpe_absent"))["cve_id"].to_list()
        )
        print(f"targeting {len(targets)} CPE-absent records")

    with httpx.Client(follow_redirects=True) as client:
        if args.archive_url:
            url = args.archive_url
            name = url.rsplit("/", 1)[-1]
            size = int(client.head(url, follow_redirects=True, timeout=60.0)
                       .headers.get("content-length", 0))
        else:
            name, url, size = find_baseline_archive(client)
        archive = CACHE / name
        if archive.exists():
            print(f"using cached {name}")
        else:
            download(client, url, archive, size)

    print("extracting")
    inner_archive, is_temp = unwrap_archive(archive)

    rows: list[dict] = []
    seen = matched = 0

    with zipfile.ZipFile(inner_archive) as zf:
        members = [n for n in zf.namelist() if n.endswith(".json") and "CVE-" in Path(n).name]
        print(f"  {len(members)} records in archive")
        for i, member in enumerate(members, 1):
            cve_id = Path(member).stem
            seen += 1
            if targets is not None and cve_id not in targets:
                continue
            try:
                with zf.open(member) as fh:
                    record = json.loads(fh.read())
            except (json.JSONDecodeError, KeyError):
                continue
            extracted = extract_affected(record)
            rows.extend(extracted)
            if extracted:
                matched += 1
            if i % 50000 == 0:
                print(f"  {i}/{len(members)} scanned, {matched} matched")

    if not rows:
        raise SystemExit("nothing extracted, check the target set")

    out = pl.DataFrame(rows, schema=SCHEMA)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    out.write_parquet(OUT)

    print("\n" + "=" * 70)
    print("WHAT THE CNAs ACTUALLY SUPPLIED")
    print("=" * 70)
    print(f"records scanned:        {seen}")
    print(f"records with product data: {matched}")
    print(f"affected entries:       {out.height}")
    if targets:
        print(f"target coverage:        {matched}/{len(targets)}  ({matched / len(targets) * 100:.1f}%)")

    print(f"\nwith a CNA-supplied CPE:  {out.filter(pl.col('cpe_count') > 0).height:>7}")
    print(f"with a named vendor:      {out.filter(~pl.col('vendor_is_unknown') & pl.col('vendor').is_not_null()).height:>7}")
    print(f"vendor unknown or blank:  {out.filter(pl.col('vendor_is_unknown')).height:>7}")
    print(f"with version detail:      {out.filter(pl.col('version_count') > 0).height:>7}")
    print(f"with a package name:      {out.filter(pl.col('package_name').is_not_null()).height:>7}")

    print("\ntop CNAs by affected entries:")
    top = out.group_by("cna").agg(
        pl.len().alias("entries"),
        (pl.col("cpe_count") > 0).mean().mul(100).round(1).alias("pct_with_cpe"),
        pl.col("vendor_is_unknown").mean().mul(100).round(1).alias("pct_no_vendor"),
    ).sort("entries", descending=True)
    with pl.Config(tbl_rows=20, tbl_width_chars=80):
        print(top.head(20))

    print(f"\nwritten to {OUT}")

    if not args.keep_archive:
        archive.unlink(missing_ok=True)
        if is_temp:
            inner_archive.unlink(missing_ok=True)
        print("removed downloaded archives (pass --keep-archive to keep them)")


if __name__ == "__main__":
    main()
