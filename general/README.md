# General research notes

Cross-cutting principles that apply across components, extracted while researching
specific ones. Per-component folders (`components/<name>/README.md`) should link back
here instead of restating these — if a principle turns out to be wrong or incomplete for
a new component, update it here rather than forking it.

Topic-specific general docs in this folder:

- [existing-fingerprint-datasets.md](existing-fingerprint-datasets.md) — survey +
  empirical test (against this repo's ground-truth corpus) of reusable precomputed
  fingerprint/hash datasets (SCANOSS OSSKB, Software Heritage, ClearlyDefined,
  PurlDB/MatchCode, CENTRIS). Bottom line: excellent recall, unusable-as-is
  attribution. Stance: **reuse-first** — whether the attribution gap can be closed on
  top of reused data (instead of curated per-component DBs) is the doc's open
  investigation list for future sessions.
- [fingerprint-detection-roadmap.md](fingerprint-detection-roadmap.md) — catalogue of
  every fingerprint-based detection *technique* (exact hash, winnowing, file/tag-set,
  symbol-set, AST, constant-table, function-level, fuzzy, binary CFG, …), marking
  which are covered here and logging the uncovered ones as **low-priority TODOs**.
  The technique counterpart to [component-roadmap.md](component-roadmap.md).
- [sbom-generator-architecture.md](sbom-generator-architecture.md) — durable handoff
  of architectural recommendations for the (separate) SBOM generator, grounded in
  this repo's findings: curated-KB backbone, two-tier distribution,
  evidence-producer/resolver split, selectable profiles, per-finding provenance, the
  metadata-vs-disassembly legal boundary, canonical attribution, version windows,
  identity→vuln-source coordinate mapping. Detection-core modelling only — output
  serialization stays out of scope.
- [advisory-source-roadmap.md](advisory-source-roadmap.md) — catalogue of the standard
  vulnerability advisory sources a scanner queries (NVD/CPE, OSV.dev, GHSA, distro
  trackers, vendor advisories, CVE.org, EUVD, CISA KEV), marking which are
  fitness-tested against this repo's purl+version output and which remain. Bottom
  line: **NVD/CPE is the fit source** for embedded C; OSV/GHSA are not. Backed by
  [experiments/advisory-fitness](experiments/advisory-fitness/README.md).

## Maturity caveat: the fingerprints here are POC-scoped, not consolidated

**The fingerprint reference sets described throughout this repo are deliberately
minimal — sized to *prove a technique is feasible*, not to *cover a component
completely*.** They must be consolidated before any of this feeds an actual
development effort. Concretely, across the experiments the reference DBs cover only a
characteristic subset of each component's files (e.g. FreeRTOS-Kernel's core `.c`
files, not the `portable/<compiler>/<arch>/port.c` + `mpu_wrappers` layer where several
real CVEs actually live; mbedTLS/CMSIS scoped to a subset of releases and files), the
winnowing gram/window parameters were taken from literature convention rather than tuned
for C, and the "is this the component at all" similarity thresholds are calibrated
against only a handful of negative controls.

None of this invalidates the findings — the point of a POC is to establish that the
*approach* works, which it does — but a production reference corpus needs, per
component: the full file set that matters for identification *and* vulnerability
mapping (including port/arch layers), broader release coverage, and empirically-tuned
thresholds. Treat every "reference DB" / "fingerprint set" in this repo as a seed to be
grown, not a finished artifact. This is a scope decision, recorded so a future session
doesn't mistake POC coverage for completeness.

## Component granularity

A "component" for SBOM purposes should map to an **independently-versioned upstream
repo/release**, not to a marketing/brand name. Brand names often bundle several
separately-versioned things (e.g. a kernel plus a set of libraries plus a
distribution-bundle concept) — collapsing all of it into one SBOM entry loses version
accuracy and independent CVE exposure. When a detector finds a recognizable
brand-labeled integration, it should ask "how many independently-versioned upstream
repos does this actually correspond to?" rather than emitting one entry per brand.

First observed in: [components/freertos](../components/freertos/README.md#2-kernel-vs-libraries-vs-umbrella-repo--component-granularity).

**A brand can be fragmented at *multiple nested levels* simultaneously, not just
"brand vs. repo."** CMSIS turned out to have three separate, simultaneously-meaningful
version numbers for what looks like "one" vendored thing: (1) each sub-component's own
repo/version line (CMSIS-Core, CMSIS-DSP, CMSIS-NN, CMSIS-RTOS2/RTX, CMSIS-Driver, etc.
are independently versioned repos, confirmed via GitHub tags — e.g. CMSIS-DSP's `v1.x`
line and CMSIS-NN's `v7.x` line are numerically unrelated to CMSIS_6's `v6.x` line), (2)
an umbrella **pack version** that bundles a snapshot of several sub-component versions
together (Arm's `ARM.CMSIS.pdsc` release notes translate one pack version, e.g. `5.9.0`,
into the real per-component versions it contains — Core 5.6.0, DSP 1.10.0, NN 3.1.0,
etc. — a distro-release model layered on top of the independently-versioned repos), and
(3) an in-source version macro that tracks only one specific sub-component
(`cmsis_version.h`'s macros track CMSIS-Core specifically, and are numerically unrelated
to both the pack version and that release's own Core sub-version string). A detector
needs to know *which* of these three number spaces a given string/macro/tag belongs to
before treating it as an answer to "what version is this."

First observed in: [components/cmsis](../components/cmsis/README.md#2-component-granularity-cmsis-is-fragmented-at-three-nested-levels-not-one).

## SBOM identifiers: PURL and CPE disagree on granularity

Two real-world vulnerability-database ecosystems exist, and they don't always agree on
what a "component" is:

- **PURL-based / OSV / GitHub Security Advisories** — keyed to the specific upstream
  repo. Current CVEs are increasingly published this way. Always derivable for any
  component with a known upstream repo, so treat PURL as the identifier that should
  *always* be emitted when a repo/release is known.
- **CPE / NVD** — a curated dictionary, not automatically derived from repos. Coverage
  is inconsistent: some components get their own dedicated CPE, related components under
  the same brand sometimes don't, and CPE granularity does not necessarily match PURL
  granularity (a brand-wide CPE and a repo-specific PURL can point at different scopes
  of "the same" software). **Don't assume a CPE exists for a given component** — look it
  up per-component and fall back to PURL-only if none is found.

**Gotcha**: CPE has a `part` field (`o` = operating system, `a` = application,
`h` = hardware). Don't assume `a` for anything that looks like a library — check the
actual dictionary entry, since real-world CPEs sometimes classify RTOS-adjacent software
as `o`.

**Practical rule**: emit both identifiers when available; treat PURL as the reliable
default and CPE as best-effort supplementary coverage for legacy NVD-based scanners.

**Correction (2026-07-28), from the advisory-source fitness tests** — the sentence above
is right for *attribution* and misleading for *vulnerability lookup*, and the two are
different jobs:

- The PURL we emit (`pkg:github/…`) is **not queryable** in OSV, which indexes
  ecosystem purls (`pkg:pypi/…`, `pkg:deb/…`); it returns 0. And OSV's bare-name fallback
  is **version-inert** — an impossible version returns the same CVE pile.
- **CPE/NVD is the source that actually discriminates by version** for these components,
  so for vuln lookup it is *primary*, not supplementary. The GHSA **per-repository** feed
  is a real second path for components whose maintainers self-publish (its ranges are in
  the upstream scheme, which can beat NVD — FreeRTOS-Kernel is the case).
- So: **emit PURL as the canonical identity, and treat every vuln source's coordinate as
  a separate, mapped key** — with per-component coverage metadata, so an empty result
  reads as "not covered by this source", never "no known vulnerabilities".

Where this stops: emitting the right identifiers (at a granularity the advisories key on)
is the job; deciding whether a matched CVE actually impacts a project is **triage**, which
belongs to the SBOM's consumer and its VEX process — see
[sbom-generator-architecture.md](sbom-generator-architecture.md) rec. 11–13 and
[experiments/advisory-fitness](experiments/advisory-fitness/README.md).

First observed in: [components/freertos](../components/freertos/README.md#5-naming-a-detected-freertos-component-in-an-sbom);
corrected by [experiments/advisory-fitness](experiments/advisory-fitness/README.md).

## Detection technique patterns

- **Structural fingerprint first**: a component's characteristic file set/naming
  (specific filenames, directory layout) is a cheap first-pass filter to flag candidates
  before any content-level matching is attempted.
- **In-source version strings survive modification**: version macros or string literals
  embedded in source (e.g. a `"Vx.y.z"`-style constant) often survive local
  modification even when the surrounding code is patched, and are worth checking
  specifically rather than relying only on whole-file hashing.
- **Copyright header era as a coarse heuristic**: when a project changes governance or
  maintainership, copyright header wording tends to shift at a specific point in time.
  That wording shift is a cheap, coarse version-era signal — not precise, but useful as
  a fast layer on top of fingerprint/content matching.

First observed in: [components/freertos](../components/freertos/README.md#6-detection-implications).

- **Sanctioned extension points have a recognizable patch *shape*, even when they don't
  show up as a whole-file swap.** Some upstream projects define an official override
  convention (a macro-gated "replace this behavior" mechanism) so vendors can add
  hardware-accelerated or platform-specific code paths without freeform patching. In
  principle this can show up as a whole upstream file being *absent*, replaced by a
  vendor-authored companion file. In practice, checking real vendor repos (not just
  vendor documentation) found the far more common shape is **in-place, localized edits
  to the upstream file itself**: the vendor wraps the existing implementation in
  `#if !defined(MODULE_ALT) ... #endif` and adds their own code in the `#else`/adjacent
  branch, often with an explicit attribution comment (e.g. `/* NXP added ... */`) marking
  exactly what they touched. This is still a structurally distinct, recognizable pattern
  from arbitrary hand-patching — small, localized, macro-gated diffs clustered around
  specific functions, frequently with an inline vendor-name comment — and worth reporting
  as its own category ("vendor extension via sanctioned override point") rather than
  generic "modified/forked," but a detector should look for *this shape*, not for file
  absence, since three independent vendors checked all used the in-place form.

First observed in: [components/mbedtls](../components/mbedtls/README.md#6-detection-implications)
(confirmed via real diffs against Espressif's ESP-IDF fork, ST's `stm32-mw-mbedtls`, and
NXP's `mbedtls` fork — all three patch in place with inline `_ALT` guards rather than
omitting a file).

- **A vendor's re-licensing of a dual-licensed component can be invisible to
  comment-stripped content matching — check the license text unnormalized.** When a
  component is dual-licensed (e.g. Apache-2.0 OR GPL), a vendor is free to redistribute
  it under just one of the options, and doing so only requires editing the SPDX header
  line inside each file's license comment block (plus the top-level `LICENSE` file) — no
  functional code changes at all. A detector that strips comments before hashing (see
  "in-source version strings" above) will report such files as an **exact match** to the
  original dual-licensed release, which is correct for version/provenance identification
  but silently misses a real difference that matters for license compliance. If license
  accuracy is a goal (not just "which version is this"), the license header/file needs a
  separate, unnormalized check — don't assume a vendored copy's license matches its
  content-matched upstream release.

First observed in: [components/mbedtls](../components/mbedtls/README.md#5-licensing-can-diverge-from-upstream-in-a-vendored-copy-without-any-content-change)
(ST's `stm32-mw-mbedtls` drops the GPL option project-wide by rewriting the
`SPDX-License-Identifier` line in every file header, while the surrounding code — and
thus the comment-stripped fingerprint — is byte-identical to upstream).

- **A vendor-authored changelog naming the exact upstream version and listing applied
  patches, when present, is a stronger signal than any fingerprinting** — check for one
  before falling back to content-based matching. Some vendors ship a plain-text
  provenance file alongside a vendored copy (e.g. `st_readme.txt`) that states "moved to
  upstream vX.Y.Z" plus a bullet list of exactly what was changed and why. This is
  effectively free, human-authored ground truth when it exists; fingerprint/similarity
  matching remains necessary for the (common) case where no such file is present or it's
  gone stale, but a detector should check for this class of file first.

First observed in: [components/mbedtls](../components/mbedtls/README.md#3-what-layers-typically-stack-on-top)
(`stm32-mw-mbedtls/st_readme.txt`, which enumerates every upstream version bump and
ST-specific patch since 2019).

## Attribution: vendored integrations are often multiple stacked components

A single embedded project that appears to contain "one" recognizable open-source
component frequently actually contains **several stacked, separately-attributable**
pieces: the upstream component itself, a vendor's adaptation/integration layer around
it (often vendor-copyrighted, not upstream), and sometimes a portability/wrapper layer
on top of that. Detection logic should not assume "found a known signature" implies
"exactly one component" — it needs to separate what's genuinely upstream from what a
distributor bolted on around it, and emit them as distinct SBOM entries.

First observed in: [components/freertos](../components/freertos/README.md#3-what-layers-typically-stack-on-top-of-the-kernel).

**A vendor layer can sit inside a directory path and file-header comment that literally
names the upstream component, while containing zero code owned by that component.**
Confirmed directly by diffing real files: every MCU vendor's CMSIS "Device" tree (e.g.
STMicroelectronics's `cmsis-device-f4`, vendored at
`Drivers/CMSIS/Device/ST/STM32F4xx/...` in `STM32CubeF4`) contains vendor-authored,
vendor-copyrighted register-definition headers and startup files that *instantiate* an
upstream-defined template contract (Arm's CMSIS-Core ships only a generic
`Template/Device_M` skeleton) but contain no Arm-owned code at all — yet the files live
under a path and carry header comments that say "CMSIS" throughout. A detector keying off
directory-name or in-comment keyword matching alone would misattribute this content to
the upstream component's PURL/CPE/supplier instead of the vendor's own. The genuinely
upstream-authored files (e.g. `core_cm4.h`) sit in a *sibling* directory in the same
checkout and must be told apart from the vendor's own instantiation next to them.

First observed in: [components/cmsis](../components/cmsis/README.md#the-device-specific-layer-is-not-cmsis-at-all-despite-living-in-a-folder-named-cmsis).

**Upstream components themselves vendor other components — the stacking goes down, not
just up.** lwIP ships a reduced copy of **PolarSSL 0.10.1-bsd** (`src/netif/ppp/polarssl/`:
`md5.c`, `sha1.c`, `des.c`, `arc4.c`, `md4.c`, still carrying PolarSSL/XySSL copyright
headers) and a heavily-reduced fork of **pppd 2.4.5** (`src/netif/ppp/`), both documented
in-tree by upstream itself. So a project that vendors one component has transitively
vendored three. Two failure modes to avoid, in opposite directions: reporting "Mbed TLS
detected" because a content matcher fired on PolarSSL-derived files that are only there as
part of lwIP (over-reporting a component that is not independently present), and
suppressing the match entirely (under-reporting 2009-era crypto with its own CVE history).
The correct output is a **contained-component relationship**, and it has a direct
vulnerability consequence: the nested component's advisories are keyed to *its* identity
and are unreachable from the outer component's — a pppd CVE with a version range that
brackets the vendored 2.4.5 is invisible to any query made as "lwIP".

First observed in: [components/lwip](../components/lwip/README.md#2-component-granularity).

**Tested 2026-07-29, and the rule as stated was not enough.** Running this repo's own
detection against that nested case produced a *confident wrong answer*: a 309-file lwIP
2.2.1 tree containing zero Mbed TLS was reported by the curated KB as **"CONSISTENT:
mbed-tls 2.28.8–2.28.10, Apache-2.0"** — wrong component, wrong version by 15 years, and
wrong license (the files are BSD-3-Clause PolarSSL 0.10.1 lineage). Two causes, both
general:

- **No minimum-evidence rule.** The tree verdict intersected the release sets of the files
  that *matched* and treated 308 `NO MATCH` files as no evidence rather than as
  counter-evidence, so one file's match became a whole-tree component claim. A single-file
  match in a large tree is a **snippet** finding, never a **component** finding — the
  distinction needs a match-ratio floor, and negative evidence has to count.
- **The one match was constant tables, not code.** lwIP's `des.c` scores 0.794 against
  Mbed TLS on hex constants alone and 0.071 on the code with constants stripped: DES's
  S-boxes are fixed by FIPS 46 and are identical in every implementation of the algorithm.
  Shared standard tables identify *an algorithm*, never a project or a version.

Also: correct attribution wasn't reachable anyway, since PolarSSL 0.10.1 (2009) predates
the upstream git history entirely (earliest tag `mbedtls-1.3.10`) — a tag-mined KB is
*structurally* unable to name it, so "known-OSS content, origin not in coverage" needs to
be an expressible verdict.

First observed in: [general/experiments/nested-component-attribution](experiments/nested-component-attribution/README.md).

## Git tags are not release artifacts — validate one against the other before mining

A reference DB mined from an upstream repo's tags silently assumes each tag *is* the
release. That assumption is false often enough to matter, and the failure is quiet: the
DB ends up with a correctly-named entry whose content nobody ever shipped.

lwIP is the demonstration. Tags `STABLE-2_0_2_RELEASE` and `STABLE-2_0_2_RELEASE_VER` are
two commits differing in exactly one line — the first still declares
`LWIP_VERSION_REVISION 1`, i.e. **the commit tagged 2.0.2 says it is 2.0.1**. Upstream
noticed and re-tagged. Downloading the official `lwip-2.0.2.zip` settles which one shipped
(the `_VER` one, byte-identical across all tracked files). Related shapes already seen:
FreeRTOS's tag zoo (packaging suffixes, `-LTS-Patch-N` maintenance branches, date-scheme
tags), and Mbed TLS's 537 tags for 116 real release commits.

Practical rules: (1) prefer the published artifact where a project releases by archive
(lwIP releases zips on Savannah; FatFs has *no* git upstream at all); (2) when both exist
and disagree, the artifact wins; (3) **don't prune the odd tag** — keep it and let
cross-file intersection disambiguate, which it does for free, since a phantom differing in
one file is eliminated the moment a second tracked file is compared.

First observed in: [components/lwip](../components/lwip/experiments/version-fingerprint/README.md#finding-1-upstreams-tag-set-contains-a-phantom-release).

## Locate tracked files by path suffix, not by basename

Fingerprint matchers here scan a target tree for tracked filenames. Keying on the bare
basename breaks as soon as a vendor's integration layer reuses an upstream basename, and
it breaks *silently and in the wrong direction*: ST's shipped lwIP middleware contains its
own port header `system/arch/init.h` next to upstream's `src/include/lwip/init.h`, and
that ST file scores **0.000** similarity against every lwIP release. A basename-keyed scan
that walked into `system/` first would report NOT_THIS_COMPONENT for a tree whose lwIP core
is byte-identical to upstream 2.1.3 — a false negative on a real, shipping vendor tree.
Matching on a path suffix (`lwip/init.h`, `core/init.c`) disambiguates that case and the
upstream-internal `lwip/init.h` vs `core/init.c` collision at the same time. Cheap to do,
and the cost of not doing it is invisible until it fires.

First observed in: [components/lwip](../components/lwip/experiments/version-fingerprint/README.md#files-are-located-by-path-suffix-not-basename).

## Architecture-tied standards are gated by CPU core choice, not by vendor

Some "components" (CMSIS is the clearest example so far) aren't independent software a
vendor chooses to adopt — they're the standardized interface layer that comes attached to
licensing a specific CPU architecture. CMSIS-Core specifically is gated to the **Arm
Cortex-M profile** (confirmed against Arm's own CMSIS_6 docs: M0/M0+/M1/M3/M4/M7/M23/M33/
M35P/M52/M55/M85, SecurCore SC000/SC300, Arm China's STAR-MC1/MC3 — no Cortex-A or
Cortex-R). A silicon vendor licenses Arm cores for *some* product lines and not others, so
the same company can sit on both sides of "does this ship CMSIS" depending on which of
their chips a given source tree targets — this is a per-product-line fact, not a
per-vendor one.

Confirmed directly (this session) across three vendors, each showing the identical split:

- **NXP**: `legacy-mcux-sdk`'s `arch/` folder lists `arm`, `riscv`, `dsp56800`, and
  `xtensa` siblings — CMSIS-Core only under the `arm` tree.
- **Infineon**: the XMC family (Cortex-M0/M4) ships an explicit CMSIS folder; the AURIX
  family (TriCore, Infineon's own proprietary architecture, unrelated to Arm) has zero
  CMSIS across seven public repos checked.
- **Renesas**: the RA family (Cortex-M23/M33/M4, M85 on newer parts) ships CMSIS-Core
  device files in the same Device-pack shape as ST's `cmsis-device-f4`; the RX family
  (Renesas' own proprietary architecture, descended from pre-merger Hitachi/Mitsubishi
  lines) has no real CMSIS presence.

**Practical rule**: before applying a CMSIS (or any other architecture-tied standard)
heuristic, determine whether the specific product line's core is actually the tied
architecture — from a part-number/datasheet lookup, not from the vendor's name or brand.
"Vendor X uses CMSIS" is not a safe inference merely because a different product line from
the same vendor does; and vendors with **no** known Arm-based lines can be deprioritized
for this heuristic entirely.

First observed in: [components/cmsis](../components/cmsis/README.md#7-detection-implications).

## Multi-file components need cross-file corroboration, not per-file matching

For a component made of several core files, presence and version identity can't be
confirmed from any single file in isolation — a detector needs to find the component's
*characteristic file set together* (e.g. in the same directory) before treating a match
as confirmed, and then check whether the files **agree** with each other, not just
report each one's best match independently. Three distinct outcomes matter, and should
be surfaced differently rather than collapsed into one:

- All core files resolve to the *same* release → confirmed, single version.
- All core files resolve to *exact* matches, but to *different* releases → a real,
  actionable finding: the integration was assembled or upgraded piecemeal (e.g. one file
  patched, others left on an older release). Report this explicitly rather than picking
  one file's answer and discarding the rest.
- Some files exact-match, others don't → likely a genuine fork that only modified part
  of the component (a real file may be left untouched while others are heavily
  rewritten). The unmodified file(s) can still help pin down a plausible base version for
  the modified ones, by checking whether the modified files' closest fuzzy match falls
  within the unmodified files' exact-match range.

First observed in: [components/freertos/experiments/version-fingerprint](../components/freertos/experiments/version-fingerprint/README.md).

## Reference DB size scales with component shape, not a fixed constant

A winnowing-fingerprint reference DB's size is driven by
`file_count × file_size × distinct_content_versions_tracked × bytes_per_stored_hash` —
not a fixed per-component cost. On FreeRTOS-Kernel (3 files, 58 tracked release tags,
~12 years of history) an unoptimized version cost 4.7 MB; two cheap, lossless-for-matching
changes cut that to 1.2 MB (−75%) with no change in match results:

- **Deduplicate by content, not by tag.** Patch/rc releases frequently leave a given
  file byte-identical to a prior release (49% of tag entries were pure duplicates for
  FreeRTOS-Kernel) — store one fingerprint per unique `(filename, content-hash)`, plus a
  small tag → content-hash index, instead of one fingerprint per tag.
- **Shrink the hash width.** This isn't a security context — fuzzy-matching fingerprint
  hashes only need to be collision-*unlikely*, not collision-*resistant*. 32-bit hashes
  at the fingerprint densities involved (~1-2k hashes/file) keep birthday-collision
  probability well under 0.1%, and a stray collision only nudges a similarity score
  fractionally, never flips a verdict.

A further ~90% reduction (packed binary instead of JSON decimal integers) is possible
if a bundled tool ever needs it, at the cost of losing plain-JSON inspectability.

**This does not generalize to a flat "X MB per component" estimate** — a
single-header library with a short release history could cost far less; a large
single-file amalgamation (e.g. an SQLite-style amalgamated build) could cost *more* than
FreeRTOS-Kernel's three modest files despite being "one file," because cost tracks total
historical source volume, not file count. Before committing a component to an offline
bundle, its reference DB should be built and measured, not assumed from another
component's numbers.

### Recommended default: offline-first, online as an additive fallback

The target deployment (embedded source trees, sometimes in air-gapped/CI contexts)
should not *require* network access. Recommended shape for the eventual generator,
two-tier:

1. **Tier 1 (always bundled, tiny)** — cheap structural/metadata signals per supported
   component: characteristic filenames, version-macro patterns, distinctive strings.
   KB-scale per component (general notes above: "Detection technique patterns"). This
   alone answers "is component X present" and often "roughly which version," fully
   offline, for every supported component regardless of how large its full reference DB
   would be.
2. **Tier 2 (bundled where the size is reasonable; online lookup as a fallback)** — the
   winnowing fingerprint reference DB, for exact/fuzzy version pinning and modification
   detection. Bundle it offline for components where the measured size is acceptable;
   for components too large or numerous to justify permanent bundling (or for deeper
   version coverage than what's bundled), allow an *optional* lookup against a centrally
   hosted copy of the same data — same format, just not shipped locally. Tier 1 must
   keep working with zero network access; Tier 2's online path is strictly additive,
   never a requirement for basic detection.

Open question, not yet decided: what total offline-bundle size budget the eventual
rollout target (CLI tool / CI plugin / IDE extension) should be designed around — this
determines how many components can realistically sit in Tier 2's offline set versus
being deferred to the online fallback.

First observed in: [components/freertos/experiments/version-fingerprint](../components/freertos/experiments/version-fingerprint/README.md#reference-db-size).
