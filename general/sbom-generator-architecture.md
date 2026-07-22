# SBOM-generator architecture — recommendations from this research

**Purpose and scope.** This repo is research-only; the SBOM generator is built in a
separate repository (see [CLAUDE.md](../CLAUDE.md)). This document is a **durable
handoff**: architecturally-relevant conclusions the research has already forced, so
the generator team doesn't re-derive them. Scope was deliberately widened to include
this doc on 2026-07-22.

What this **is**: recommendations on how to model the detection/identification core
— evidence producers, the identity/version resolver, attribution, provenance, and
the legal boundary. What this is **not**: a design spec, and specifically **not**
output serialization — CycloneDX/SPDX format design remains out of scope here (that
lives with the generator). Each recommendation cites the finding that produced it, so
it can be re-examined if that finding is ever overturned.

Everything below is a *hint grounded in evidence*, not a mandate — flag it if a new
finding contradicts one.

## 1. Curated per-component KB is the attribution backbone

Make a **curated per-component knowledge base** the primary substrate;
reused/public datasets (SCANOSS OSSKB, its CC0 offline tables) are a *subordinate*
recall/routing net, and any hosted API at most a freshness fallback.

- **Why**: the bar is attribution (correct purl/version/license to drive vuln
  scanning), and the reused-data attribution gap is *structural* — raw output names
  an arbitrary containing repo with that repo's wrong versions/licenses, and the
  offline CC0 dataset has no purl/license/version and no URL list to fix it on.
  The curated KB gets attribution **by construction** (declared metadata round-trips
  into every match). Coverage — the curated KB's weakness — closes linearly over a
  small, stable embedded-C component universe.
- **Source**: the 2026-07-16 Decision in
  [existing-fingerprint-datasets.md](existing-fingerprint-datasets.md); the
  minr-self-mining experiment (attribution-by-construction confirmed).
- **Flip condition**: revisit only if scope becomes arbitrary/unbounded codebases
  (general audit tooling) rather than a standard scanner for known embedded projects.

## 2. Two-tier distribution: thin bundled artifact + central full KB

Ship a **compact identification artifact** embedded in the scanner (validated:
~48 MB gzipped JSON for 3 components; extrapolates to ~100–300 MB for the roadmap),
backed by a **central full KB** consulted for evidence/detail on demand.

- **Why**: the thin artifact makes the common scan fully offline and fast and is
  enough to produce identity + version + purl; the full KB holds the heavier
  evidence tiers (source snippets, license/copyright detections) that are only
  needed to justify a finding. Validated end-to-end: `validate_export.py`
  reproduced all 12 corpus ground truths from the artifact alone.
- **Source**: the lightweight-export prototype in
  [experiments/minr-self-mining](experiments/minr-self-mining/README.md).
- **Note**: distribute the KB itself as a *versioned, pulled artifact* (rationale in
  the same experiment README) so scans are reproducible against a pinned KB version.

## 3. Model each fingerprint tier as an independent evidence producer

Structure detection as a set of **evidence producers** (one per technique in the
[fingerprint-detection-roadmap](fingerprint-detection-roadmap.md)) feeding a
**separate identity/version resolver**. Producers emit `(candidate component,
version-window, supporting evidence, confidence)`; the resolver fuses them.

- **Why**: the techniques key on different properties and fail on different
  transformations, so they're additive; keeping them decoupled from the resolver is
  what makes them swappable and individually selectable (recommendation 4), and lets
  a new tier drop in without touching fusion logic.
- **Source**: the tiered-pipeline finding in
  [experiments/static-lib-identification](experiments/static-lib-identification/README.md)
  ("tiered pipeline mirrors the source-side design"); the roadmap's "why enumerate"
  section.

## 4. Expose selectable detection criteria as named profiles

Let the operator choose *which* tiers run, but expose it as **named profiles**, not
a bag of raw toggles, with power-user override underneath. Suggested profiles:

- `fast` — exact-hash + member-name + symbol tiers only (skip winnowing/AST).
- `thorough` — all source + binary metadata tiers.
- `compliance-safe` — metadata tiers only (see recommendation 6); never disassembly.
- `high-precision` — exact + symbol only, drop noisy snippet matching.

- **Why**: three independent drivers demand it — *legal* (must be able to switch off
  binary-similarity per artifact), *cost* (winnowing/AST are expensive; a fast pass
  should skip them), *precision* (snippet matching is the noisiest tier; a
  high-confidence mode should exclude it). This need was surfaced independently by
  the research before it was requested as a feature.
- **Source**: the no-disassembly finding (recommendation 6); the OSSKB snippet
  attribution-noise findings.

## 5. Record provenance per finding — and the scan profile itself

Every SBOM entry must carry **which tier(s) supported it** and a confidence; the SBOM
as a whole must record **which profile/tiers were run**.

- **Why (per-finding)**: downstream trust and filtering, and compliance audit —
  proving no restricted technique touched a restricted artifact (recommendation 6).
- **Why (whole-scan)**: disabling tiers silently lowers recall, so an *incomplete*
  scan can be mistaken for a *complete* one — dangerous when the SBOM drives vuln
  scanning. Recording the profile makes "we didn't look" distinguishable from "it
  isn't there."
- **Source**: the tier-boundary/audit reasoning in the static-lib doc; the
  vuln-scanning end-goal bar in [CLAUDE.md](../CLAUDE.md).

## 6. The legal tier boundary: metadata vs. disassembly

Default to **metadata-only** detection; gate binary-similarity (disassembly/
decompilation) behind **explicit per-artifact opt-in**; record which tier touched
which file.

- **The line**: reading `ar` member tables, ELF symbol tables, and literal strings
  consumes structures the format *declares for third-party consumption* (the linker
  reads them during normal licensed use) and reconstructs nothing copyrightable —
  distinct from disassembly/decompilation. Vendor licenses can forbid the latter
  outright.
- **Why it maps cleanly onto the architecture**: the tier boundary in the
  fingerprint roadmap (tiers 1–7 metadata vs. tier 13 disassembly) *coincides* with
  the legal boundary, so `compliance-safe` (recommendation 4) is a well-defined,
  auditable mode rather than a judgment call.
- **Caveat**: the broader term "reverse engineering" in restrictive clauses is a
  gray zone needing real legal review in the product context — this is an
  engineering boundary, not legal advice.
- **Source**: the TI `ecc` no-disassembly-clause finding in the static-lib doc.

## 7. Attribution output must be canonical, not "containing repo"

The resolver must emit a **canonical identity** (upstream purl, version, SPDX
license), never the raw "some repo that contains this file" that public snippet APIs
return.

- **Why**: the empirically-demonstrated failure mode — an Espressif-patched mbedTLS
  file attributed to Realtek's `ameba-rtos`; verbatim GPLv2 files reported as MIT
  under the FreeRTOS umbrella repo. Wrong purls feed wrong CVEs. The curated KB
  (recommendation 1) gives canonical identity by construction; if a reused-data tier
  is ever consulted, its output must be *mapped through* the KB, not passed through.
- **Source**: the OSSKB empirical tests in
  [existing-fingerprint-datasets.md](existing-fingerprint-datasets.md).

## 8. Version output is a window, not a point — carry it through

Detectors emit a **version window** (a set/range of consistent releases), not a
single version. Preserve that shape through the resolver and into the SBOM; let the
cross-file/cross-tier consistency logic narrow it by intersection.

- **Why**: real matches are window-shaped — the symbol tier lands 3–4 releases wide,
  snippet matches land on near-neighbors, and release-shared content is genuinely
  ambiguous. Collapsing to a point too early invents false precision. Window width is
  a function of **reference-DB tag coverage**, not just the technique — widening the
  mbedTLS DB with pre-2.28 tags collapsed a Wi-SUN match from a 3-release window to
  exactly `mbedtls-2.22.0`. Downstream vuln matching must accept ranges anyway (OSV
  ranges), so keep the window.
- **Source**: symbol-window results and the DB-widening arbitration in the
  static-lib doc; the cross-file consistency design across the component experiments.

## 9. Vendor manifests are corroboration, never ground truth

Harvest vendor-supplied manifests/SBOMs (component hints, upstream repo+tag pointers,
embedded upstream SPDX with per-file hashes) as **inputs**, but always run
independent detection, and treat **manifest-vs-detected discrepancies as a
first-class output**.

- **Why**: on a single shipping SDK, the vendor manifest exhibited three distinct
  error classes — an entirely undeclared embedded component (nanopb hidden in a
  proprietary blob), a wrong version for a declared one (Mbed-TLS declared 3.4.0,
  binary is 3.5.x), and a component declared under an umbrella product's version
  number (embedded mbedTLS 2.22.0 declared as "Mbed-OS mbedtls 5.15.7"). The bundled
  source tree's *own* version header was even self-contradictory. A discrepancy is
  exactly the kind of finding an SBOM tool exists to surface.
- **Source**: the vendor-manifest and Wi-SUN findings in the static-lib doc.

## 10. Distinguish "present on disk" from "built into the artifact"

SBOM semantics should separate a component found **as source in the tree** from one
proven **compiled into the delivered binary** (member/symbol evidence from a `.a`).

- **Why**: the `.a`/symbol tier answers a question source scanning can't — what's
  actually linked into firmware — and that's closer to the deployed artifact's true
  bill of materials. A source tree can contain unbuilt/vendored-but-unused code.
- **Source**: the "present as source ≠ built into firmware" implication in the
  static-lib doc.

## Keeping this doc honest

These recommendations track findings, not preferences. If a future component or
artifact overturns one (e.g. a curated-KB coverage explosion that flips
recommendation 1, or a corpus that finally forces AST/binary tiers), update the
recommendation here and note the finding that moved it — the same way the component
docs update the cross-cutting principles in [README.md](README.md).
