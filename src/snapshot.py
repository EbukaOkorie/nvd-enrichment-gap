"""
Capture a dated snapshot of enrichment state for every CVE.

Why this exists: a single observation cannot separate processing lag from
permanent non-enrichment. Watching records over time can. This history cannot
be reconstructed later, so the job runs from now on regardless of whether the
analysis is ready to use it.

Storage: the first run writes a full baseline. Every run after writes only the
records whose state changed, plus records that are new. Full state at any date
is reconstructed by replaying the baseline and every delta up to that date.

Usage:
    python src/snapshot.py                 # capture today's snapshot
    python src/snapshot.py --reconstruct 2026-08-14   # rebuild full state
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

import httpx
import polars as pl

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000

ROOT = Path(__file__).resolve().parent.parent
SNAP_DIR = ROOT / "data" / "snapshots"
SUMMARY = SNAP_DIR / "summary.csv"
PARTIAL = SNAP_DIR / "partial"

# Columns that define a record's enrichment state. A change in any of these
# is what makes a record worth recording again.
STATE_COLS = ["vuln_status", "has_primary_cvss", "has_secondary_cvss", "cpe_match_count"]


def extract_state(record: dict) -> dict | None:
    cve = record.get("cve", {}) or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    metrics = cve.get("metrics", {}) or {}
    has_primary = has_secondary = False
    for key, entries in metrics.items():
        if not key.startswith("cvssMetric"):
            continue
        for entry in entries or []:
            if entry.get("type") == "Primary":
                has_primary = True
            else:
                has_secondary = True

    cpe_count = 0
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            cpe_count += len(node.get("cpeMatch", []) or [])

    return {
        "cve_id": cve_id,
        "published": (cve.get("published") or "")[:10],
        "assigner": cve.get("sourceIdentifier"),
        "vuln_status": cve.get("vulnStatus"),
        "has_primary_cvss": has_primary,
        "has_secondary_cvss": has_secondary,
        "cpe_match_count": cpe_count,
    }


def pull_current_state() -> pl.DataFrame:
    """Stream the whole corpus, keeping only state fields. Raw pages are not
    persisted: the backfill already holds those, and weekly copies would be
    mostly duplicate bytes.

    Checkpoints to disk every few pages. A network failure halfway through
    costs a rerun of the remaining pages, not the whole corpus."""
    api_key = (os.environ.get("NVD_API_KEY") or "").strip()
    if api_key:
        # An illegal header value raises LocalProtocolError on every attempt,
        # so catch a malformed key here rather than burning six retries on it.
        if not re.fullmatch(r"[A-Za-z0-9\-]{20,}", api_key):
            raise SystemExit(
                "NVD_API_KEY does not look like a valid key. Check for stray "
                "whitespace, quotes or line breaks in the value."
            )
    headers = {"apiKey": api_key} if api_key else {}
    sleep_for = 1.0 if api_key else 6.5
    if not api_key:
        print("WARNING: no NVD_API_KEY set, this will be slow", file=sys.stderr)

    PARTIAL.mkdir(parents=True, exist_ok=True)
    start_index = 0
    chunks = sorted(PARTIAL.glob("chunk_*.parquet"))
    if chunks:
        start_index = max(int(p.stem.split("_")[1]) for p in chunks) + PAGE_SIZE
        print(f"resuming from checkpoint at index {start_index} ({len(chunks)} chunks on disk)")

    rows: list[dict] = []
    total = None
    # Separate connect and read timeouts. NVD can be slow to first byte under
    # load, and a short read timeout is what broke the earlier run.
    timeout = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0)

    def flush(index: int) -> None:
        if rows:
            pl.DataFrame(rows).write_parquet(PARTIAL / f"chunk_{index:07d}.parquet")
            rows.clear()

    with httpx.Client(follow_redirects=True, timeout=timeout) as client:
        while True:
            params = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}

            payload = None
            for attempt in range(6):
                try:
                    r = client.get(API_URL, params=params, headers=headers)
                except httpx.LocalProtocolError as exc:
                    # Client-side error, usually a malformed header. Retrying
                    # cannot help, so stop immediately with a useful message.
                    raise SystemExit(
                        f"request rejected before sending: {exc}. "
                        f"This is almost always a malformed NVD_API_KEY."
                    ) from exc
                except httpx.RequestError as exc:
                    wait = min(90, 2 ** attempt * 5)
                    print(f"  {exc.__class__.__name__} at {start_index}, retry in {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    continue
                if r.status_code == 200:
                    payload = r.json()
                    break
                wait = min(90, 2 ** attempt * 5)
                print(f"  HTTP {r.status_code} at {start_index}, backing off {wait}s", file=sys.stderr)
                time.sleep(wait)

            if payload is None:
                flush(start_index - PAGE_SIZE)
                raise RuntimeError(
                    f"failed at startIndex {start_index} after 6 attempts. "
                    f"Progress is checkpointed, so rerunning resumes from here."
                )

            if total is None:
                total = payload.get("totalResults", 0)
                print(f"pulling {total} records")

            batch = payload.get("vulnerabilities", []) or []
            rows.extend(s for s in (extract_state(v) for v in batch) if s)

            # Checkpoint roughly every 10 pages.
            if len(rows) >= PAGE_SIZE * 10:
                flush(start_index)
                print(f"  checkpointed at {start_index + len(batch)}/{total}")

            start_index += len(batch)
            if not batch or start_index >= total:
                break
            time.sleep(sleep_for)

    flush(start_index)

    chunks = sorted(PARTIAL.glob("chunk_*.parquet"))
    df = pl.concat([pl.read_parquet(p) for p in chunks], how="vertical_relaxed")
    df = df.unique(subset=["cve_id"], keep="first")

    # Only clear checkpoints once the full frame is assembled.
    for p in chunks:
        p.unlink()
    return df


def snapshot_files() -> tuple[Path | None, list[Path]]:
    baseline = sorted(SNAP_DIR.glob("baseline_*.parquet"))
    deltas = sorted(SNAP_DIR.glob("delta_*.parquet"))
    return (baseline[0] if baseline else None), deltas


def reconstruct(as_of: str | None = None) -> pl.DataFrame:
    """Replay baseline plus deltas to get full state at a given date."""
    baseline, deltas = snapshot_files()
    if baseline is None:
        raise SystemExit("no baseline snapshot found, run snapshot.py first")

    state = pl.read_parquet(baseline).drop("change_type", strict=False)
    for path in deltas:
        stamp = path.stem.replace("delta_", "")
        if as_of and stamp > as_of:
            break
        delta = pl.read_parquet(path).drop("change_type", strict=False)
        state = (
            pl.concat([delta, state], how="vertical_relaxed")
            .unique(subset=["cve_id"], keep="first")
        )
    return state


def capture() -> None:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    current = pull_current_state()
    print(f"pulled {current.height} unique records")

    baseline, deltas = snapshot_files()

    if baseline is None:
        out = SNAP_DIR / f"baseline_{stamp}.parquet"
        current.with_columns(pl.lit("baseline").alias("change_type")).write_parquet(out)
        new_records = current.height
        changed = 0
        print(f"baseline written: {out.name} ({current.height} records)")
    else:
        previous = reconstruct()
        joined = current.join(previous, on="cve_id", how="left", suffix="_prev")

        is_new = pl.col("vuln_status_prev").is_null()
        differs = pl.any_horizontal(
            [pl.col(c) != pl.col(f"{c}_prev") for c in STATE_COLS]
        )

        delta = (
            joined.filter(is_new | differs)
            .with_columns(
                pl.when(is_new).then(pl.lit("new")).otherwise(pl.lit("changed")).alias("change_type")
            )
            .select(current.columns + ["change_type"])
        )

        new_records = delta.filter(pl.col("change_type") == "new").height
        changed = delta.filter(pl.col("change_type") == "changed").height

        out = SNAP_DIR / f"delta_{stamp}.parquet"
        delta.write_parquet(out)
        print(f"delta written: {out.name} ({new_records} new, {changed} changed)")

    live = current.filter(pl.col("vuln_status") != "Rejected")
    summary_row = pl.DataFrame([{
        "snapshot_date": stamp,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_records": current.height,
        "non_rejected": live.height,
        "new_records": new_records,
        "changed_records": changed,
        "pct_no_cpe": round((live["cpe_match_count"] == 0).mean() * 100, 2),
        "pct_no_nist_cvss": round((~live["has_primary_cvss"]).mean() * 100, 2),
        "pct_deferred": round((live["vuln_status"] == "Deferred").mean() * 100, 2),
    }])

    if SUMMARY.exists():
        existing = pl.read_csv(SUMMARY).filter(pl.col("snapshot_date") != stamp)
        summary_row = pl.concat([existing, summary_row], how="vertical_relaxed").sort("snapshot_date")
    summary_row.write_csv(SUMMARY)
    print(f"summary updated: {SUMMARY.name}")
    print(summary_row.tail(5))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reconstruct", metavar="YYYY-MM-DD", help="rebuild full state as of a date")
    args = parser.parse_args()

    if args.reconstruct:
        state = reconstruct(args.reconstruct)
        out = ROOT / "data" / "interim" / f"state_{args.reconstruct}.parquet"
        out.parent.mkdir(parents=True, exist_ok=True)
        state.write_parquet(out)
        print(f"reconstructed {state.height} records as of {args.reconstruct} -> {out}")
    else:
        capture()


if __name__ == "__main__":
    main()
