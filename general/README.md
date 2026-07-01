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
