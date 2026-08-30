# Licence and attribution for the data

This repository contains two different things under two different terms.

## Code

Everything in `src/` and `.github/` is released under the MIT Licence. See
`LICENSE`.

## Data

Everything in `data/snapshots/` is released under the Creative Commons
Attribution 4.0 International licence (CC BY 4.0).

Full text: https://creativecommons.org/licenses/by/4.0/legalcode
Summary: https://creativecommons.org/licenses/by/4.0/

You may share and adapt this data for any purpose, including commercially,
provided you give appropriate credit and indicate whether changes were made.

### What is actually being licensed

The underlying vulnerability records come from the U.S. National Vulnerability
Database and are in the public domain. Individual facts, such as whether a
given CVE carries CPE data, are not owned by anyone and this licence does not
attempt to claim them.

What CC BY 4.0 covers here is the compilation: the selection of fields, the
extraction and deduplication logic, the dated snapshot series, and the
derived state history. The point of applying a licence is to remove ambiguity
for organisations that need a clear answer before using the files, not to
restrict use of public facts.

### Suggested citation

    Okorie, C. (2026). NVD Enrichment Gap Tracker [Data set].
    https://github.com/EbukaOkorie/nvd-enrichment-gap

## Source attribution and disclaimers

### CVE Program

Product and version data in this project is derived from the CVE List,
maintained by the CVE Program. The CVE List may be freely downloaded, copied,
redistributed and analysed, provided CVE itself is not modified. Records here
have been reduced to selected fields and reorganised, so they are derived data
and are not the CVE List.

CVE and the CVE logo are registered trademarks of The MITRE Corporation. This
project is not endorsed by, affiliated with, or sponsored by the CVE Program or
MITRE. Authoritative records are at https://www.cve.org.

### NVD

This product uses data from the NVD API but is not endorsed or certified by
the NVD.

The data in `data/snapshots/` is derived from records retrieved through the
NVD API. It has been filtered, reduced to selected fields, deduplicated and
reorganised into a dated snapshot series. It is therefore not NVD data and
should not be attributed to the NVD as though it were unmodified. Anyone
needing the authoritative records should retrieve them directly from
https://nvd.nist.gov.

The NVD is provided by NIST as a public service on an "as is" basis, with no
warranty of any kind. NIST makes no representations regarding the correctness,
accuracy or reliability of the NVD, and users are solely responsible for
determining the appropriateness of their use of it.

The same applies to this project. The figures published here are provided
without warranty and may contain errors of collection, interpretation or
method. They should not be relied upon as the sole basis for any security
decision.

No endorsement by NIST, the NVD, or any CVE Numbering Authority named in this
data is implied or should be inferred.
