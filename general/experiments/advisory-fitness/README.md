# Advisory-source fitness — do our results drive standard vuln databases?

**Question**: this whole repo exists to produce SBOMs that drive **vulnerability
scanning**. Every prior experiment stopped at producing `purl + version` (or a
version *window*). This experiment feeds that output into the **standard
advisory sources a real scanner queries** and asks: do the right, real CVEs come
back? It is open item 2 in
[../../existing-fingerprint-datasets.md](../../existing-fingerprint-datasets.md),
designated next-up 2026-07-18. Sources covered so far (run **2026-07-22**):
[OSV.dev](https://osv.dev), [NVD](https://nvd.nist.gov)/CPE, and the
[GitHub Advisory Database](https://github.com/advisories) (GHSA). The full menu
of sources still to test is in
[../../advisory-source-roadmap.md](../../advisory-source-roadmap.md).

Three sub-questions per source: (1) does it recognize the coordinates we produce
(GitHub-flavored purl, upstream semver)? (2) does a **version** actually filter
the CVE set, or is matching inert? (3) which of our components does it **cover**?

Reproduce (read-only public APIs, no keys): `python osv_probe.py --json
osv_results.json`, `python nvd_probe.py --json nvd_results.json`,
`python ghsa_probe.py --json ghsa_results.json`. The `*_results.json` are
committed snapshots — CVE *counts* drift as sources ingest advisories; the
*shape* of the findings is the durable result.

## Comparative verdict — NVD/CPE is the primary fit source; GHSA is fit only via its per-repo feed; OSV is not

| source | mbedTLS coverage | version discrimination | FreeRTOS | CMSIS | our-coordinate that works |
|---|---|---|---|---|---|
| **NVD/CPE** | ✓ `arm:mbed_tls` | ✓ **real** (@99.0.0 → 0) | CVEs exist, AWS-versioned | `cmsis-rtos` only | **canonical identity → CPE 2.3** |
| **OSV.dev** | distro advisories only | ✗ **inert** (@99.0.0 → 83) | **absent** | **absent** | none upstream (distro purl / GIT-commit) |
| **GHSA (global feed)** | unreviewed CVE mirror, no ecosystem | ✗ none | ✗ absent via `affects=` | absent | none (no C/C++ ecosystem) |
| **GHSA (per-repo feed)** | ✗ upstream doesn't self-publish | ✓ **real** for self-publishers | ✓ **kernel-semver range** (CVE-2024-28115 `<=10.6.1`) | absent | **`{owner}/{repo}` → repo advisory feed** |

> **Correction (2026-07-23):** the original run (2026-07-22) tested only GHSA's
> *global* `/advisories` feed (`affects=`, `cve_id=`) and concluded GHSA was flatly
> "least fit." That missed a second access path — the per-repository
> `/repos/{owner}/{repo}/security-advisories` feed — where maintainers who self-publish
> carry **real, version-ranged** advisories keyed to the *upstream* version scheme. For
> FreeRTOS-Kernel this is materially better than NVD (see the GHSA section below). The
> global-feed findings stand; the "GHSA is useless for embedded C" conclusion does not.

The headline: **NVD/CPE gives the version-accurate matching the whole pipeline
was built to feed** — an impossible version returns 0 where OSV returns the
entire historical pile. The generator's vuln-lookup mapping should target
**CPE 2.3** as the primary coordinate, with OSV's GIT-commit CVE records as an
upstream-accurate secondary (usable because we already mine per-release tags),
and OSV package / GHSA queries as at-best coarse nets. Per-source detail below.

## OSV.dev — not directly fit for embedded C

The naive integration a reader would assume — declare a canonical upstream purl
+ version, query OSV, get that version's CVEs — **fails in three independent
ways**, each demonstrated below. Coverage is distro-repackaging-shaped, not
upstream-shaped; our own coordinates don't resolve; and the one query form that
returns anything is version-inert.

### Finding 1 — the declared (GitHub) purl returns nothing

| query | raw vulns | CVEs |
|---|--:|--:|
| **control** `pkg:pypi/django` @3.0.0 | 31 | 21 |
| `pkg:github/mbed-tls/mbedtls` @2.28.0 | **0** | **0** |
| `pkg:github/freertos/freertos-kernel` @10.4.3 | **0** | **0** |
| `pkg:github/arm-software/cmsis_5` @5.9.0 | **0** | **0** |
| `pkg:github/nanopb/nanopb` @0.3.9.3 | **0** | **0** |

The PyPI control returns 21 CVEs, so the purl-query technique is correct — the
zeros are a **real coverage gap**. OSV indexes ecosystem purls (`pkg:pypi/…`,
`pkg:npm/…`, `pkg:golang/…`, `pkg:deb/…`) but **not `pkg:github/…`**. Our
canonical attribution identity (rec. 7) — deliberately upstream/GitHub-flavored
so it's *correct* — is exactly the wrong key for OSV lookup. Identity and
vuln-lookup coordinate are **different keys**; the generator must map between
them, not assume the SBOM purl is queryable.

### Finding 2 — bare-name matching is version-inert (returns all history)

Dropping to a bare `name` (no ecosystem) *does* return results — but the same
CVE set regardless of version:

| query | raw vulns | distinct CVEs |
|---|--:|--:|
| `mbedtls` @2.28.0 (real) | 179 | **83** |
| `mbedtls` @3.6.2 (real, much newer) | 158 | **83** |
| `mbedtls` @99.0.0 (**impossible future**) | 125 | **83** |
| `mbedtls` @3.5.0 (TI `libmbedcrypto`) | 164 | **83** |
| `mbedtls` @2.22.0 (Wi-SUN EOL) | 179 | **83** |

An **impossible future version returns the same 83 CVEs** as a real one. Without
an ecosystem, OSV can't order versions, so name+version degenerates to "every
mbedtls advisory across every distro" (Alpine, Debian, Ubuntu, SUSE, Mageia,
Echo). A naive `name+version → OSV` integration would therefore report the
**identical CVE list for every version** — flagging a fully-patched build as
vulnerable and claiming a precision it does not have. This is the dangerous
failure mode for a tool whose output drives remediation. All the effort spent
pinning 2.22.0 vs 3.5.0 (the symbol-tier work) buys **nothing** on this path.

### Finding 3 — ecosystem-qualified queries discriminate, but need distro identity we don't have

Add a real ecosystem and version filtering partly wakes up:

| query | CVEs |
|---|--:|
| `mbedtls` + `Debian` @2.28.0-1 (real) | 49 |
| `mbedtls` + `Debian` @99.0.0 (impossible) | 43 |
| `pkg:deb/debian/mbedtls` @2.28.0 | 52 |

Better (49 ≠ 43), but (a) it needs **distro coordinates** (`Debian`,
`2.28.0-1`) our upstream detection never produces — and shouldn't, since the
firmware isn't running Debian's package; (b) even here the impossible version
returns 43, so it's still leaky; (c) it answers "what CVEs would Debian's
mbedtls package at this version have," a **different question** from "what CVEs
affect this vendored upstream source."

### Finding 4 — coverage is component-specific; FreeRTOS/CMSIS are invisible

- **FreeRTOS**: 0 under every coordinate tried (declared purl, `freertos`,
  `freertos-kernel`, `amazon-freertos`). A **known** FreeRTOS-Kernel CVE
  (`CVE-2021-31571`) is not even retrievable by ID from OSV. A Tier-1 component
  with **zero** OSV coverage.
- **CMSIS**: 0 under purl and bare name. (The umbrella-granularity question is
  moot — there's nothing to be granular about.)
- **nanopb**: declared purl 0, but bare `nanopb` → 5 CVEs (it has a PyPI
  presence). Partial, accidental coverage.

The generator must therefore track, **per component, which vuln source actually
covers it**, and treat an empty result as *"not covered"* — never silently as
*"no known vulnerabilities."* Those are opposite meanings and only per-component
coverage metadata distinguishes them.

## The one upstream-accurate path OSV does offer — and why *we* can use it

OSV *does* carry the raw CVE records for mbedTLS (e.g. `CVE-2024-45157`,
`CVE-2024-28960`), fetched by ID — but their affected ranges are **GIT-commit
ranges only** (`introduced`/`fixed` commit SHAs, no package name, no semver):

```
CVE-2024-45157  range GIT  introduced e483a77c… fixed 5e146ade…
                           introduced 3aef7670… fixed 71c569d4…
```

Unusable with a plain semver version in general — you'd need to resolve the
version to a commit and test range membership on the git DAG. **But this repo's
reference DBs already mine per-release *git tags*** (the version-fingerprint and
symbol-tier experiments check tags out by name), so a tag→commit map is free on
our side. That turns OSV's otherwise-unusable raw-CVE feed into a viable
**upstream-accurate** lookup: resolve our detected version to its release commit,
test membership in each CVE's introduced..fixed GIT range. Logged as the
concrete follow-up below, not built here.

## NVD/CPE — the fit source: real version-range discrimination

NVD is CPE-based, and CPE 2.3 match ranges are *upstream* version ranges. The
same matrix, via `virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>`:

| query (CPE `arm:mbed_tls`) | CVEs |
|---|--:|
| @2.28.0 (real) | 23 |
| @3.6.2 (real, newer) | 11 |
| @2.22.0 (Wi-SUN EOL, older) | 37 |
| @3.5.0 (TI `libmbedcrypto`) | 12 |
| **@99.0.0 (impossible)** | **0** |

This is exactly the discrimination OSV lacked: the impossible version returns
**0**, older versions carry more CVEs than newer (37 > 11), and every count is a
plausible per-version answer — genuine range matching against
`versionStartIncluding`/`versionEndExcluding`. **NVD/CPE is the upstream-accurate
path**, and the mapping the generator needs is **canonical identity → CPE 2.3**
(`pkg:github/mbed-tls/mbedtls` → `cpe:2.3:a:arm:mbed_tls`), with the detected
version tested against CPE ranges.

Coverage of the other components is more nuanced than OSV's flat zero:

- **FreeRTOS** *has* CPEs (`amazon:freertos` → 11 CVEs, `amazon:
  amazon_web_services_freertos` → 14) — unlike OSV, it's present. **But** these
  are the 2018 AWS-FreeRTOS TCP-stack CVEs keyed to **AWS-distribution
  versioning**, so our kernel semver `10.4.3` matches **0** of them. Coverage
  exists; the blocker is a **version-scheme mismatch** (kernel semver vs AWS
  distribution vs the FreeRTOS+TCP component) — a mapping/granularity problem,
  not an absence. This is the FreeRTOS instance of the component-granularity
  question already logged for CMSIS.
- **CMSIS**: only `arm:cmsis-rtos` has a CPE (0 CVEs at 5.9.0); Core/DSP/NN have
  none — the RTOS-classification gotcha documented in
  [../../README.md](../../README.md). Effectively uncovered, but for a
  *structural CPE-dictionary* reason, which is actionable (request/track CPEs)
  rather than a flat miss.

So NVD's failure modes are **mapping problems** (identity→CPE, version-scheme,
missing CPE names) — solvable in the mapping layer — whereas OSV's are
**structural** (no upstream feed, inert matching). That asymmetry is why NVD is
the primary target.

## GHSA — two access paths with opposite verdicts

GHSA has **two** query surfaces, and they behave completely differently for
embedded C. The first version of this experiment tested only the first and wrongly
concluded GHSA was useless.

### Path A — global `/advisories` feed: unfit (no C/C++ ecosystem)

The global feed is ecosystem-scoped and its ecosystems are npm / pip / go / maven /
rubygems / nuget / composer / … (confirmed: the 100 most-recent advisories are all
`{npm, pip, maven, composer}`, no C/C++) — **there is no C/C++ ecosystem**.
Consequences:

- `affects=mbedtls` → **0**, `affects=freertos` → **0**. No package-queryable
  coverage for any embedded-C component.
- A known mbedTLS CVE (`CVE-2024-45157`) *is* present as `GHSA-cvp8-hm87-hr8x`,
  but as an **unreviewed** advisory with an **empty ecosystem/package** — a bare
  CVE mirror with no version range. You can only retrieve it if you *already*
  have the CVE ID, which adds nothing over querying NVD directly. (Note: some
  repo-published advisories don't surface here at all — CVE-2024-28115 below returns
  **0** from the global feed even by `cve_id=`.)

### Path B — per-repository `/repos/{owner}/{repo}/security-advisories`: fit for self-publishers

Advisories a repo's *own maintainers* publish are reachable through the repository
endpoint, and these carry real version ranges — even under a **non-standard ecosystem
name** the global feed would never index:

| repo | advisories | version range (ecosystem / range) |
|---|--:|---|
| **FreeRTOS/FreeRTOS-Kernel** | 1 | `freertos-kernel` / **`<=10.6.1`**, patched `>=10.6.2` (CVE-2024-28115, HIGH) |
| FreeRTOS/FreeRTOS | 1 | `pip`-labelled / `202212.01, 202112.00` (AWS-distribution versioning) |
| FreeRTOS/coreMQTT | 1 | `v5.0.0` (CVE-2026-8686) |
| Mbed-TLS/mbedtls | **0** | — (mbedTLS self-publishes on its own advisory site + NVD, not GitHub) |

Two things make the FreeRTOS-Kernel row important, not a footnote:

1. **The range is keyed to kernel semver** (`<=10.6.1`) — *exactly the version scheme
   this repo's fingerprint detector outputs*. This is strictly better than NVD/CPE for
   FreeRTOS, where the CVEs use AWS-distribution versioning that our kernel semver
   `10.4.3` matches none of (the version-scheme mismatch logged for NVD). For a
   component whose maintainer self-publishes, the GHSA repo feed sidesteps the
   FreeRTOS version-scheme mapping problem entirely.
2. **It's only reachable via the repo endpoint.** GHSA-xcv7-v92w-gq6r returns **0**
   from the global `/advisories` feed even by `cve_id=CVE-2024-28115` — so a scanner
   querying only the standard global feed (as most do, and as our first run did) never
   sees it.

The catch is that Path B is **component-specific and non-uniform**: it works only for
components whose upstream is a GitHub repo *and* whose maintainers publish repository
advisories. FreeRTOS does; mbedTLS returns 0 (wrong source for it — use NVD).
So the GHSA repo feed is a **per-component opt-in source**, discovered from the
canonical identity's `{owner}/{repo}`, not a general fallback. This reinforces the
per-component coverage-metadata requirement: which source covers a component is itself
a mapped, per-component fact.

## Implications for the generator (feeds the metadata-mapping layer)

1. **SBOM identity ≠ vuln-lookup key.** The canonical upstream purl is right for
   attribution and wrong for OSV. A **mapping layer** from canonical identity to
   each vuln source's coordinate system is mandatory — captured as a new
   recommendation in
   [../../sbom-generator-architecture.md](../../sbom-generator-architecture.md).
2. **Target NVD/CPE first; add the GHSA per-repo feed as a per-component source;
   OSV.dev alone is insufficient for embedded C.**
   Confirmed empirically: **NVD/CPE gives version-accurate matching** (impossible
   version → 0), so the primary vuln-lookup coordinate is **CPE 2.3**. The **GHSA
   per-repository feed** is a real, version-ranged secondary for components whose
   maintainers self-publish (FreeRTOS-Kernel — and there its kernel-semver range is
   *better* than NVD's AWS-distribution versioning), discovered from the canonical
   identity's `{owner}/{repo}`. OSV's GIT-range CVE records are a further
   upstream-accurate secondary (via our tag→commit map); OSV package queries and the
   GHSA *global* feed are coarse or empty.
3. **Never emit version-inert results as if precise.** If only bare-name OSV is
   available for a component, the output is a version-independent CVE pile and
   must be labeled as such (or suppressed) — consistent with the per-finding /
   whole-scan provenance recommendation.
4. **The residual work is mapping, not more sources.** NVD's misses are all
   mapping-layer problems — identity→CPE, kernel-semver→AWS-distribution version,
   and missing CPE names for CMSIS sub-components — which is where the generator's
   effort should go, rather than adding ever more advisory feeds.

## Follow-ups queued (not started)

- ~~**NVD/CPE probe**~~ — **DONE 2026-07-22** (above): CPE version-range matching
  gives the discrimination OSV lacks; NVD/CPE is the fit source.
- **FreeRTOS version-scheme mapping**: work out how the kernel semver we detect
  (10.4.3) maps onto the AWS-FreeRTOS / FreeRTOS+TCP CPE versioning that the NVD
  CVEs actually use — the concrete instance of the component-granularity question
  for FreeRTOS. *Note (2026-07-23): the GHSA per-repo feed sidesteps this for the
  kernel specifically — its CVE-2024-28115 range is already in kernel semver
  (`<=10.6.1`) — so kernel-semver → GHSA-repo may be the shorter path than
  kernel-semver → AWS-distribution CPE. Weigh both.*
- **Per-component vuln-source map incl. the GHSA repo feed**: record, per component,
  its `{owner}/{repo}` and whether that repo self-publishes advisories (FreeRTOS-Kernel
  yes, mbedTLS no), so the mapping layer knows to query the repo feed for the
  self-publishers and skip it for the rest. Part of the per-component coverage metadata.
- **Tag→commit resolver over OSV GIT ranges**: prototype resolving a detected
  version to its release commit and testing membership in OSV CVE GIT ranges,
  using the tags the reference DBs already mine.
- **Remaining advisory sources**: the untested sources in
  [../../advisory-source-roadmap.md](../../advisory-source-roadmap.md) (distro
  trackers, vendor/upstream advisories, CVE.org/cvelistV5, EUVD, CISA KEV).
- **CVE-dedup cost of the OSSKB attribution gap** (the original framing): quantify
  how many *wrong* CVEs OSSKB's arbitrary-containing-repo attribution would feed
  in vs. our curated purl — now measurable with this harness.
