# NVD Enrichment Gap Tracker

Measuring how many CVE records lack the product identifiers that vulnerability
scanners need in order to detect them, and which software ecosystems are
affected.

**Status: first analysis complete, findings provisional. Figures below come
from a single snapshot taken 14 August 2026 and have not been independently
reviewed.**

## Why this matters

When a CVE is published, the CVE Numbering Authority supplies a description and
often little else. NVD analysts historically added structured metadata on top: a
CVSS severity score, CPE strings identifying which products and versions are
affected, and a CWE weakness classification.

Scanners match vulnerabilities to installed software using CPE strings. A record
without them cannot be matched at all, so it never appears in scan results. This
is a detection failure rather than a prioritisation failure, which is why CPE
absence is the metric this project tracks. A CVE without a severity score can
still be seen and triaged by hand. A CVE without CPE strings is invisible.

## Findings

Based on 359,229 non-rejected CVE records published between October 1988 and
August 2026.

### The decline predates the April 2026 policy change

On 15 April 2026, NIST formally moved to risk-based enrichment, prioritising
CVEs in CISA's Known Exploited Vulnerabilities catalogue, those affecting
federal government software, and critical software as defined by Executive Order
14028. Commentary published since has generally treated that date as the point
at which coverage broke down.

The cohort data does not support that reading. CPE absence by publication month
was already between 30% and 50% throughout 2025, and December 2025 reached 49.6%,
higher than May or June 2026. The rise begins around late 2024, moving from 11.5%
in September 2024 to 41.0% by December 2024.

The April 2026 change appears to formalise a decline that was already several
years underway rather than to have caused it.

### The gap concentrates in specific ecosystems

This is the most actionable result. Among CNAs assigning 100 or more CVEs since
April 2026, CPE absence varies enormously:

| Assigning CNA | CVEs | No CPE |
|---|---|---|
| audit@patchstack.com | 1,581 | 100.0% |
| security@wordfence.com | 1,389 | 100.0% |
| contact@wpscan.com | 636 | 99.7% |
| cna@vuldb.com | 2,195 | 90.7% |
| disclosure@vulncheck.com | 2,544 | 72.6% |
| cve@mitre.org | 1,265 | 72.4% |
| secalert@redhat.com | 519 | 57.8% |
| security-advisories@github.com | 4,828 | 56.2% |
| secure@microsoft.com | 1,472 | 11.9% |
| security@apache.org | 527 | 10.1% |
| secalert_us@oracle.com | 1,483 | 3.3% |

The WordPress plugin ecosystem receives effectively no CPE data. Major
commercial vendors are largely unaffected.

The practical implication for a security team is that exposure depends on estate
composition. An environment weighted toward WordPress, plugins and
GitHub-tracked open source dependencies is close to blind. An environment
running mostly large commercial vendor software is not.

## Methodology

### Definition

A CVE is counted as CPE-absent if it carries zero CPE matches. Records with a
vulnStatus of Rejected are excluded from all denominators, since a rejected
record is not a vulnerability and its lack of enrichment is correct.

### Separating processing lag from permanent absence

CPE assignment lags publication, so recently published records show high absence
simply because they are young. A raw snapshot of recent months overstates the
permanent gap.

This is handled by comparing CPE absence against the deferral rate within the
same cohort. A vulnStatus of Deferred represents NVD stating it does not intend
to enrich the record, so deferral is a marker of a settled outcome rather than a
queue position.

For older cohorts the two rates converge. March 2024 shows 17.1% absence against
17.1% deferral. Where the two diverge sharply, the cohort has not settled. August
2026 shows 87.6% absence against 9.5% deferral, meaning most of that apparent gap
is records awaiting processing rather than records abandoned.

Reading the deferral rate as the settled estimate, mid-2026 cohorts sit at
roughly 38% to 41%, against roughly 35% to 40% across 2025. The change is a
modest worsening rather than a cliff.

**Assumption to be tested:** this treats deferral as the only route to permanent
non-enrichment. A record could in principle remain in Awaiting Analysis
indefinitely without ever being marked Deferred, which would cause this method to
understate the true gap. Longitudinal snapshots are required to test this.

### Ecosystem attribution

Vendor names are derived from CPE strings, so records lacking CPE carry no vendor
information by definition. The assigning CNA is used as a proxy, since CNAs map
closely onto software ecosystems. This is an approximation and does not capture
cases where a CNA assigns across multiple ecosystems.

### Status fields are not descriptive

Observed vulnStatus values are Modified (243,078), Analyzed (67,437), Deferred
(42,181), Received (3,475), Awaiting Analysis (2,380) and Undergoing Analysis
(678). Records marked Analyzed have been observed carrying no NIST-assigned
score, so enrichment state is derived from the presence of underlying fields
rather than from the status label.

## Data source

All data comes from the NVD API 2.0. Raw API responses are stored unmodified and
never edited, so every figure is reproducible from the raw responses by rerunning
the transformation code.

Pagination by index against a live corpus can skip or repeat records, so records
are deduplicated by CVE ID keeping the most recently modified copy. The 14 August
2026 collection produced no duplicates across 189 pages.

## Setup

    python -m venv .venv
    .venv\Scripts\Activate.ps1        # Windows
    source .venv/bin/activate         # macOS and Linux
    pip install -r requirements.txt

An NVD API key is strongly recommended. Without one the rate limit is five
requests per thirty seconds, which makes a full backfill impractical.

    $env:NVD_API_KEY = "your-key"     # Windows
    export NVD_API_KEY=your-key       # macOS and Linux

## Usage

    python src/probe_nvd.py           # verify API behaviour, costs 3 requests
    python src/collect_nvd.py backfill    # collect full corpus, resumable
    python src/build_dataset.py       # deduplicate and flag, writes parquet
    python src/analyse.py             # cohort tables and CNA breakdown

Raw responses land in `data/raw/` and are not committed.

## Limitations

Everything here rests on one snapshot. The lag correction described above uses
deferral as a proxy for a settled outcome, which is a reasonable assumption but
an untested one.

Weekly snapshots are being introduced so that enrichment state can be tracked per
record over time. That will allow the lag curve to be measured directly rather
than inferred, and it cannot be reconstructed retrospectively.

CNA-supplied CVSS scores have historically received less external scrutiny than
NIST-assigned ones. This project counts their presence and does not assess their
quality.

## Open items

- [ ] Weekly snapshot job, storing dated enrichment state per CVE
- [ ] Test whether records persist in Awaiting Analysis without being Deferred
- [ ] Map CNAs to ecosystem categories rather than leaving raw email identifiers
- [ ] Publication format and versioning scheme
- [ ] Zenodo deposit for citable DOI
- [x] Licence files

## Licence

Code in `src/` and `.github/` is MIT licensed. See `LICENSE`.

Data in `data/snapshots/` is licensed CC BY 4.0. See `LICENSE-DATA.md`, which
also sets out what the licence does and does not cover.

This product uses data from the NVD API but is not endorsed or certified by the
NVD. Files in `data/snapshots/` are derived from NVD records rather than copies
of them, and should not be attributed to the NVD as unmodified source data.
Figures published here carry no warranty and should not be the sole basis for a
security decision.
