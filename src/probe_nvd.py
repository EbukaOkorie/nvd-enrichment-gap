"""
Smoke test before the real collection run.

Pulls a handful of records and reports what the API actually returns, so we
can confirm the assumptions baked into collect_nvd.py and see what an
enriched vs unenriched record really looks like.

Costs 3 requests. Run this before the backfill.

Usage:
    export NVD_API_KEY=...
    python src/probe_nvd.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import httpx

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def call(client: httpx.Client, params: dict, label: str) -> dict | None:
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    print(f"\n[{label}]")
    print(f"  params: {params}")
    try:
        r = client.get(API_URL, params=params, headers=headers, timeout=60.0)
    except httpx.RequestError as exc:
        print(f"  FAILED: {exc}")
        return None
    print(f"  status: {r.status_code}")
    if r.status_code != 200:
        print(f"  body: {r.text[:300]}")
        return None
    data = r.json()
    print(f"  totalResults: {data.get('totalResults')}")
    print(f"  returned: {len(data.get('vulnerabilities', []))}")
    return data


def describe(record: dict) -> dict:
    """What enrichment does this record actually carry?"""
    cve = record.get("cve", {})
    metrics = cve.get("metrics", {}) or {}

    nist_scores, cna_scores = [], []
    for key, entries in metrics.items():
        # SSVC decision points live in this same object and are not CVSS
        # scores. Counting them was inflating the secondary score list.
        if not key.startswith("cvssMetric"):
            continue
        for entry in entries or []:
            src = entry.get("type", "?")
            (nist_scores if src == "Primary" else cna_scores).append(f"{key}:{src}")

    configs = cve.get("configurations", []) or []
    cpe_count = 0
    for config in configs:
        for node in config.get("nodes", []) or []:
            cpe_count += len(node.get("cpeMatch", []) or [])

    weaknesses = cve.get("weaknesses", []) or []
    cwe_ids = [
        d.get("value")
        for w in weaknesses
        for d in w.get("description", []) or []
        if d.get("value", "").startswith("CWE-")
    ]

    return {
        "id": cve.get("id"),
        "vulnStatus": cve.get("vulnStatus"),
        "published": cve.get("published", "")[:10],
        "primary_scores": nist_scores,
        "secondary_scores": cna_scores,
        "cpe_matches": cpe_count,
        "cwes": cwe_ids,
    }


def main() -> None:
    if not os.environ.get("NVD_API_KEY"):
        print("WARNING: no NVD_API_KEY set. This may still work but will be rate limited.\n")

    with httpx.Client(follow_redirects=True) as client:
        # 1. Does basic paging work, and how big is the corpus?
        basic = call(client, {"resultsPerPage": 5, "startIndex": 0}, "basic paging")
        if basic is None:
            sys.exit("basic call failed, stop here and check the endpoint")

        # 2. Do the incremental date params work as collect_nvd.py assumes?
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=2)
        call(
            client,
            {
                "resultsPerPage": 5,
                "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            },
            "incremental window",
        )

        # 3. Recent records, which is where the gap should show up.
        recent = call(
            client,
            {
                "resultsPerPage": 20,
                "pubStartDate": (end - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            },
            "recent 30 days",
        )

    print("\n" + "=" * 70)
    print("WHAT THE RECORDS ACTUALLY CONTAIN")
    print("=" * 70)

    sample = (recent or basic).get("vulnerabilities", [])
    statuses: dict[str, int] = {}
    no_score = no_primary = no_cpe = no_cwe = 0
    counted = 0

    for item in sample:
        d = describe(item)
        statuses[d["vulnStatus"]] = statuses.get(d["vulnStatus"], 0) + 1
        print(json.dumps(d))

        # Rejected records are not vulnerabilities, so they do not belong
        # in any denominator.
        if d["vulnStatus"] == "Rejected":
            continue
        counted += 1

        if not d["primary_scores"] and not d["secondary_scores"]:
            no_score += 1
        if not d["primary_scores"]:
            no_primary += 1
        if d["cpe_matches"] == 0:
            no_cpe += 1
        if not d["cwes"]:
            no_cwe += 1

    n = counted
    print("\n" + "-" * 70)
    print(f"sample size: {len(sample)} ({len(sample) - n} rejected, excluded below)")
    print(f"vulnStatus values seen: {statuses}")
    print(f"no CPE matches (headline):   {no_cpe}/{n}")
    print(f"no NIST-assigned CVSS:       {no_primary}/{n}")
    print(f"no CVSS from any source:     {no_score}/{n}")
    print(f"no CWE:                      {no_cwe}/{n}")
    print("-" * 70)
    print("\nThis is a tiny sample from a narrow date range, so treat it as a")
    print("shape check, not a finding. CPE absence in recently published")
    print("records may reflect processing lag rather than a permanent gap.")


if __name__ == "__main__":
    main()