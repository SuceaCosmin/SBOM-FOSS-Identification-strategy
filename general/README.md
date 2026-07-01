# General research notes

Cross-cutting principles that apply across components, extracted while researching
specific ones. Per-component folders (`components/<name>/README.md`) should link back
here instead of restating these — if a principle turns out to be wrong or incomplete for
a new component, update it here rather than forking it.

## Component granularity

A "component" for SBOM purposes should map to an **independently-versioned upstream
repo/release**, not to a marketing/brand name. Brand names often bundle several
separately-versioned things (e.g. a kernel plus a set of libraries plus a
distribution-bundle concept) — collapsing all of it into one SBOM entry loses version
accuracy and independent CVE exposure. When a detector finds a recognizable
brand-labeled integration, it should ask "how many independently-versioned upstream
repos does this actually correspond to?" rather than emitting one entry per brand.

First observed in: [components/freertos](../components/freertos/README.md#2-kernel-vs-libraries-vs-umbrella-repo--component-granularity).

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

First observed in: [components/freertos](../components/freertos/README.md#5-naming-a-detected-freertos-component-in-an-sbom).

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

## Attribution: vendored integrations are often multiple stacked components

A single embedded project that appears to contain "one" recognizable open-source
component frequently actually contains **several stacked, separately-attributable**
pieces: the upstream component itself, a vendor's adaptation/integration layer around
it (often vendor-copyrighted, not upstream), and sometimes a portability/wrapper layer
on top of that. Detection logic should not assume "found a known signature" implies
"exactly one component" — it needs to separate what's genuinely upstream from what a
distributor bolted on around it, and emit them as distinct SBOM entries.

First observed in: [components/freertos](../components/freertos/README.md#3-what-layers-typically-stack-on-top-of-the-kernel).

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
