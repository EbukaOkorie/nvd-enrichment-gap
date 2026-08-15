"""
Collect CVE records from the NVD API 2.0.

Writes raw, unmodified API responses to data/raw/ as gzipped JSON, one file
per page. Nothing is parsed or reshaped here on purpose: the raw landing
zone is the thing you never regenerate, so it stays exactly as NVD sent it.

Resumable. If the run dies at page 90 of 150, rerun it and it picks up.

Usage:
    export NVD_API_KEY=...          # optional but strongly recommended
    python src/collect_nvd.py backfill
    python src/collect_nvd.py incremental --days 7
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD caps results per page at 2000.
PAGE_SIZE = 2000

# Published limits: 5 requests per 30s without a key, 50 per 30s with one.
# We sit well under both, because a 403 mid-backfill costs more than patience.
SLEEP_WITH_KEY = 1.0
SLEEP_WITHOUT_KEY = 6.5

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw"
STATE_FILE = ROOT / "data" / "collect_state.json"


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def fetch_page(client: httpx.Client, params: dict, api_key: str | None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}

    for attempt in range(5):
        try:
            response = client.get(API_URL, params=params, headers=headers, timeout=60.0)
        except httpx.RequestError as exc:
            wait = 2 ** attempt
            print(f"  network error ({exc.__class__.__name__}), retry in {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue

        if response.status_code == 200:
            return response.json()

        # 403 from NVD usually means rate limiting rather than auth failure.
        if response.status_code in (403, 429, 500, 502, 503, 504):
            wait = min(60, 2 ** attempt * 5)
            print(f"  HTTP {response.status_code}, backing off {wait}s", file=sys.stderr)
            time.sleep(wait)
            continue

        response.raise_for_status()

    raise RuntimeError("giving up after 5 attempts")


def write_page(payload: dict, run_tag: str, start_index: int) -> Path:
    out_dir = RAW_DIR / run_tag
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"page_{start_index:07d}.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


def collect(base_params: dict, run_tag: str) -> None:
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        print("No NVD_API_KEY set. This will be slow. Get a free key from NVD.", file=sys.stderr)
    sleep_for = SLEEP_WITH_KEY if api_key else SLEEP_WITHOUT_KEY

    state = load_state()
    start_index = state.get(run_tag, {}).get("next_index", 0)
    total = None

    with httpx.Client(follow_redirects=True) as client:
        while True:
            params = {**base_params, "resultsPerPage": PAGE_SIZE, "startIndex": start_index}
            payload = fetch_page(client, params, api_key)

            if total is None:
                total = payload.get("totalResults", 0)
                print(f"{run_tag}: {total} records to collect")

            path = write_page(payload, run_tag, start_index)
            got = len(payload.get("vulnerabilities", []))
            print(f"  {start_index:>7} + {got:<5} -> {path.name}")

            start_index += got
            state[run_tag] = {
                "next_index": start_index,
                "total_results": total,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            save_state(state)

            if got == 0 or start_index >= total:
                break

            time.sleep(sleep_for)

    print(f"{run_tag}: done, {start_index} records across {len(list((RAW_DIR / run_tag).glob('*.json.gz')))} pages")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    sub.add_parser("backfill", help="collect the entire corpus")

    inc = sub.add_parser("incremental", help="collect records modified recently")
    inc.add_argument("--days", type=int, default=7)

    args = parser.parse_args()

    if args.mode == "backfill":
        run_tag = "backfill_" + datetime.now(timezone.utc).strftime("%Y%m%d")
        collect({}, run_tag)
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=args.days)
        # NVD rejects windows longer than 120 days.
        if args.days > 120:
            raise SystemExit("window must be 120 days or fewer; run several windows instead")
        run_tag = "incr_" + end.strftime("%Y%m%dT%H%M%S")
        collect(
            {
                # httpx encodes these, so pass the literal offset, not %2B.
                "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            },
            run_tag,
        )


if __name__ == "__main__":
    main()
