# Security-advisory-source roadmap

A catalogue of the **vulnerability advisory sources** a real SBOM-driven scanner
queries, marking which this repo has fitness-tested against its own
purl+version output and which remain to test. The end-goal bar is SBOMs that
drive **vulnerability scanning** (see [../CLAUDE.md](../CLAUDE.md)), so *which
source, keyed on which coordinate, actually returns the right CVEs for embedded
C* is a first-class research question — not an implementation detail deferred to
the generator.

This is the *advisory-source* roadmap. Sibling roadmaps: *components* to
research → [component-roadmap.md](component-roadmap.md); *fingerprint techniques*
→ [fingerprint-detection-roadmap.md](fingerprint-detection-roadmap.md). The
empirical tests behind the "tested" rows live in
[experiments/advisory-fitness](experiments/advisory-fitness/README.md).

## Why enumerate sources at all

The fitness tests showed the choice of source is **not** interchangeable for
embedded C: the same detected `mbedtls 2.28.0` returns version-accurate CVEs
from NVD/CPE, a version-inert historical pile from OSV, and nothing from GHSA.
Each source keys on a different coordinate (CPE 2.3, ecosystem purl, distro
package, GIT commit) and covers a different slice of the embedded-C universe. A
robust scanner maps identity onto **several** sources and fuses — the same
"independent producers → resolver" shape as the detection tiers
([sbom-generator-architecture.md](sbom-generator-architecture.md) recs. 3, 11).
This doc is the menu that mapping draws from.

## Status matrix

Legend — **Fit**: tested, returns version-accurate results for our output.
**Partial**: tested, usable only via a caveated/secondary path. **Unfit**:
tested, structurally can't serve embedded C. **TODO**: not yet tested, logged
below with a priority. **Out**: deliberately excluded.

| source | keys on | version matching | embedded-C coverage | status |
|---|---|---|---|---|
| **NVD** (CVE + CPE 2.3) | CPE 2.3 (`cpe:2.3:a:vendor:product:version`) | **real ranges** (@99.0.0 → 0) | mbedTLS ✓; FreeRTOS present but AWS-versioned; CMSIS `cmsis-rtos` only | **Fit (primary)** |
| **OSV.dev** | ecosystem purl / distro pkg / GIT commit | inert on bare name; GIT-range records are upstream-accurate | distro advisories only; FreeRTOS/CMSIS absent | **Partial** (GIT-range secondary) |
| **GHSA** (GitHub Advisory DB) | ecosystem package (npm/pip/go/maven/…) | n/a | none (no C/C++ ecosystem) | **Unfit** |
| **Distro security trackers** (Debian, Ubuntu USN, Alpine secdb, SUSE, Red Hat/Rocky, Mageia, Echo) | distro package + distro version | distro-versioned | broad but distro-shaped; largely mirrored into OSV | **TODO — low** |
| **Vendor/upstream advisories** (Mbed-TLS/TrustedFirmware, FreeRTOS, Espressif, NXP, ST PSIRTs) | per-vendor (upstream version) | authoritative for the exact upstream | high for the specific component; unstructured/heterogeneous | **TODO — medium** |
| **CVE.org / cvelistV5** (CVE 5.x JSON) | CVE record (CPE + versions in CNA container) | source-of-truth NVD/OSV derive from | grows as CNAs enrich; raw | **TODO — medium** |
| **EUVD** (ENISA EU Vuln DB) | its own IDs + CVE alias | emerging; NVD-like | unknown for embedded C | **TODO — low / watch** |
| **CISA KEV** (Known Exploited Vulns) | CVE ID | n/a (prioritization overlay) | enrichment, not identification | **TODO — low (enrichment)** |
| **Commercial KBs** (VulnDB, Snyk, Mend, Black Duck) | proprietary | proprietary | strong but paid/non-reproducible | **Out** |

## Tested sources — detail

**NVD/CPE (Fit, primary)** — CPE 2.3 match ranges are upstream version ranges, so
version discrimination works (mbedTLS @2.28.0 → 23 CVEs, @3.6.2 → 11, impossible
@99.0.0 → **0**). The mapping the generator needs is **canonical identity →
CPE 2.3**. Residual issues are all mapping-layer, not structural: FreeRTOS CVEs
are keyed to AWS-distribution versioning (our kernel semver 10.4.3 matches none),
and CMSIS has a CPE only for `cmsis-rtos` (the RTOS-classification gotcha).

**OSV.dev (Partial)** — the declared `pkg:github/…` purl returns 0; bare-name
matching is version-inert (impossible version → same 83 CVEs); FreeRTOS/CMSIS
absent. Its one upstream-accurate offering is raw CVE records with **GIT-commit
ranges**, usable *by us* because the reference DBs already mine per-release git
tags (tag→commit is free). Keep as a secondary via that path.

**GHSA (Unfit)** — no C/C++ ecosystem exists; package queries return 0; embedded-C
CVEs appear only as unreviewed CVE mirrors with empty ecosystem (findable only if
you already have the CVE ID). Not useful beyond a redundant mirror.

Full results, tables, and reproduction: [experiments/advisory-fitness](experiments/advisory-fitness/README.md).

## Untested sources — TODOs (ordered by expected value)

None is scheduled ahead of the current mapping-layer work; pick up when a
component or a gap makes one relevant.

- **Vendor/upstream advisories (medium)** — the most authoritative source for the
  *exact* upstream version, and the natural cross-check for NVD's version-scheme
  mismatches (e.g. Mbed-TLS's own published security advisories list affected
  version ranges directly). Heterogeneous/unstructured per vendor, so the value
  is per-component curation, not a single API. **Trigger**: a component where NVD
  version ranges are wrong or absent.
- **CVE.org / cvelistV5 (medium)** — the CVE 5.x JSON records (mirrored on GitHub
  as `CVEProject/cvelistV5`) are what NVD and OSV derive from; CNA containers
  increasingly carry CPE applicability and version ranges directly, sometimes
  fresher/richer than NVD's enrichment. **Trigger**: NVD enrichment lag or a
  CNA-rich component.
- **Distro security trackers (low)** — Debian/Ubuntu/Alpine/SUSE/Red Hat feeds are
  broad but distro-versioned and largely already mirrored into OSV (that's what
  OSV's mbedTLS coverage *is*). Direct querying adds little for upstream-vendored
  firmware. **Trigger**: a component only distros track.
- **EUVD (low / watch)** — ENISA's EU Vulnerability Database (2025) is an emerging
  NVD alternative; worth a coverage probe once it stabilizes, mainly for
  redundancy/resilience against NVD enrichment backlogs. **Trigger**: NVD
  reliability concerns or an EU-compliance requirement.
- **CISA KEV (low, enrichment)** — not an identification source; a prioritization
  overlay (is a matched CVE known-exploited?). Slots in *after* identification as
  a severity/urgency signal. **Trigger**: prioritization/triage features.

## Out of scope

Commercial vulnerability KBs (VulnDB, Snyk, Mend/WhiteSource, Black Duck KB) —
stronger curation but paid and non-reproducible, so unsuitable as a research
baseline. Noted for completeness; the reuse-first stance targets free/open
sources ([existing-fingerprint-datasets.md](existing-fingerprint-datasets.md)).

## Relationship to the architecture doc

The "map canonical identity onto each source's coordinate, don't reuse the SBOM
purl" conclusion — and the per-source coverage-metadata requirement (empty ≠ no
vulns) — are recommendation 11 in
[sbom-generator-architecture.md](sbom-generator-architecture.md). Keep the two in
sync: a source promoted from TODO to Fit/Partial here should be reflected as a
mapping target there.
