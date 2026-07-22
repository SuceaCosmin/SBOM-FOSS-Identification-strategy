# OSV.dev fitness test — does our purl+version output drive vuln scanning?

**Question**: this whole repo exists to produce SBOMs that drive **vulnerability
scanning**. Every prior experiment stopped at producing `purl + version` (or a
version *window*). This one feeds that output into [OSV.dev](https://osv.dev)
(Google's free open-source vulnerability API) and asks: do the right, real CVEs
come back? It is open item 2 in
[../../existing-fingerprint-datasets.md](../../existing-fingerprint-datasets.md),
designated next-up 2026-07-18, run **2026-07-22**.

Three sub-questions: (1) does OSV recognize the **GitHub-flavored purls** we
declare (`pkg:github/mbed-tls/mbedtls`)? (2) does a **version** actually filter
the CVE set, or is matching inert? (3) which of our components does OSV **cover**
at all?

Reproduce: `python osv_probe.py --json results.json` (read-only public API, no
key). `results.json` is a committed snapshot — CVE *counts* drift as OSV ingests
advisories; the *shape* of the findings is the durable result.

## Result: OSV.dev is **not** directly fit to consume our output for embedded C

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

## Implications for the generator (feeds the metadata-mapping layer)

1. **SBOM identity ≠ vuln-lookup key.** The canonical upstream purl is right for
   attribution and wrong for OSV. A **mapping layer** from canonical identity to
   each vuln source's coordinate system is mandatory — captured as a new
   recommendation in
   [../../sbom-generator-architecture.md](../../sbom-generator-architecture.md).
2. **OSV.dev alone is not sufficient for embedded C.** For upstream-accurate
   results the fit sources are **NVD/CPE** (mbedTLS and FreeRTOS have CPEs with
   proper upstream version ranges) and/or **OSV's GIT-range CVE records via our
   tag→commit map**. OSV's package queries are, at best, a coarse distro-flavored
   net.
3. **Never emit version-inert results as if precise.** If only bare-name OSV is
   available for a component, the output is a version-independent CVE pile and
   must be labeled as such (or suppressed) — consistent with the per-finding /
   whole-scan provenance recommendation.

## Follow-ups queued (not started)

- **NVD/CPE probe**: repeat this matrix against NVD's CPE API for mbedTLS
  (`cpe:2.3:a:arm:mbed_tls:*`) and FreeRTOS — does CPE version-range matching
  give the version discrimination OSV's package queries lack? This is the
  natural next fitness test and directly informs the metadata-mapping layer.
- **Tag→commit resolver over OSV GIT ranges**: prototype resolving a detected
  version to its release commit and testing membership in OSV CVE GIT ranges,
  using the tags the reference DBs already mine.
- **CVE-dedup cost of the OSSKB attribution gap** (the original framing): quantify
  how many *wrong* CVEs OSSKB's arbitrary-containing-repo attribution would feed
  in vs. our curated purl — now measurable with this harness.
