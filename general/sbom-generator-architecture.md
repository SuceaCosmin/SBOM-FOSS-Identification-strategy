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
- **Realized (2026-07-22)**: the lightweight-export artifact is now
  tier-labeled — a shared canonical `releases` table plus a `tiers` map where
  each tier declares its roadmap technique number (`exact`=1, `winnowing`=2,
  `symbol`=4). The symbol tier was folded in this way as a proof that a producer
  drops in without touching the others or the resolver, and that a profile can
  select tiers by loading a subset of `tiers`. See
  [experiments/minr-self-mining](experiments/minr-self-mining/README.md#tier-labeled-artifact--symbol-tier-fold-in-schema-2-2026-07-22).

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
- **Extended 2026-07-29: canonical is necessary, not sufficient — the resolver also needs
  an evidence threshold.** A curated KB run against an lwIP tree emitted a *perfectly
  canonical* identity (`pkg:github/mbed-tls/mbedtls`, 2.28.8–2.28.10, Apache-2.0) that was
  entirely wrong, because the resolver promoted a single file's snippet match in a
  309-file tree to a whole-tree component claim, intersecting only the *matched* files and
  discarding 308 non-matches as "no evidence". Attribution-by-construction did its job;
  the resolver believed evidence it should have rejected. Required: (a) a **match ratio**
  with a floor below which the answer is "no component detected", not a version;
  (b) **negative evidence counts** — files that fail to match are counter-evidence for a
  whole-tree claim; (c) a **snippet finding and a component finding are different
  outputs** and must not share a verdict vocabulary; (d) an expressible
  "known-OSS content, origin outside coverage" result, since the true origin here
  (PolarSSL 0.10.1, 2009) predates the upstream git history and cannot be in a tag-mined
  KB at all. See also rec. 14 on mining artifacts rather than tags.
- **Source**: [experiments/nested-component-attribution](experiments/nested-component-attribution/README.md).

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
- **Carry the window's *semantics*, not just its members** (added 2026-07-28): a set of
  releases means one of two different things, and consumers can't tell them apart from
  the set alone. **Candidates** = the tree is *one of* these (content-identical releases,
  a partially-modified fork's base) — ambiguity to be narrowed. **Coexisting** = files
  from several releases are *simultaneously present* (a mixed-version tree) — not
  ambiguity at all. The end-to-end vuln spike proved this changes the answer: under
  "candidates" a partly-affected set is `POSSIBLY_AFFECTED` (tighten detection), under
  "coexisting" the same set is a definite `AFFECTED` (the vulnerable file really is
  there). Label the window with which it is.
- **Source**: symbol-window results and the DB-widening arbitration in the
  static-lib doc; the cross-file consistency design across the component experiments;
  the window-semantics finding in
  [experiments/advisory-fitness](experiments/advisory-fitness/README.md).

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

## 11. The vuln-lookup coordinate is a separate key from the SBOM identity — map, don't reuse

The canonical upstream identity the resolver emits (rec. 7) is the right key for
*attribution* and the **wrong key for vulnerability lookup**. Model the
identity→vuln-source mapping as its own layer, per source, with **per-component
coverage metadata**; never assume the SBOM purl is directly queryable.

- **Why**: the advisory-source fitness tests (OSV.dev, NVD/CPE, GHSA) found the
  source is **not** interchangeable for embedded C. Our declared `pkg:github/…`
  purls return **0** from OSV (which indexes `pkg:pypi/…`, `pkg:deb/…`, not
  `pkg:github/…`; a PyPI control worked, isolating the gap), and OSV's only
  bare-name match is **version-inert** (impossible version → same 83 CVEs); GHSA's
  *global* feed has no C/C++ ecosystem at all. **NVD/CPE is the fit source** — CPE
  2.3 ranges give real version discrimination (impossible version → 0) — so the
  primary mapping target is **canonical identity → CPE 2.3**. A second, *per-component*
  fit path exists: **GHSA's per-repository advisory feed**
  (`/repos/{owner}/{repo}/security-advisories`), which for maintainers who
  self-publish carries real version ranges keyed to the *upstream* scheme — for
  FreeRTOS-Kernel, `<=10.6.1` in **kernel semver**, i.e. *better* than NVD's
  AWS-distribution versioning for that component (mbedTLS self-publishes elsewhere, so
  its repo feed is empty — the path is opt-in per component). Coverage is thus
  component-specific (FreeRTOS/CMSIS absent from OSV; FreeRTOS present in NVD but
  AWS-distribution-versioned; CMSIS only `cmsis-rtos`; FreeRTOS-Kernel best served by
  its GHSA repo feed), so an empty result means "not covered," not "no known vulns" —
  a distinction only per-component coverage metadata preserves.
- **Two failure modes added 2026-08-18 by zlib, both silent.**
  (a) **A deprecated CPE is a total, silent miss.** The NVD dictionary carries both the
  live `cpe:2.3:a:zlib:zlib` and a fully deprecated `cpe:2.3:a:gnu:zlib` (zlib is not a
  GNU project). Querying the deprecated one returns **0 for every version** — so a
  mapping layer that takes the first `keywordSearch` hit issues a clean bill of health
  for every zlib ever shipped. The mapping must record the *specific, non-deprecated*
  CPE and re-validate it, not resolve a name at query time.
  (b) **A CPE in a CVE's configuration does not mean the CVE is *about* that product.**
  NVD marks each `cpeMatch` with `vulnerable: true|false`; a `false` entry inside an
  `AND` node means the product is the **environment/precondition** for someone else's
  flaw. `CVE-2025-0725` is a **libcurl** integer overflow whose configuration is
  `AND(curl <8.12.0 [vulnerable], libcurl <8.12.0 [vulnerable], zlib <=1.2.0.3 [NOT
  vulnerable])` — yet `virtualMatchString=cpe:2.3:a:zlib:zlib:1.1.4` returns it, because
  the query API matches on CPE *presence*, not on role. Ignoring the flag reports a curl
  vulnerability against zlib. This one is not a source defect: NVD models it correctly
  and the consumer must read it. (Found by, and fixed in, `nvd_vuln_lookup.py`, which had
  been capturing the flag without consulting it.)
- **Consequences for the architecture**: (a) the resolver's canonical identity
  feeds a **mapping step** that produces each vuln source's own coordinate
  (CPE for NVD, ecosystem purl / GIT commit for OSV) — this is where the
  detected version must be translated into the source's version model; (b)
  **NVD/CPE** (proper upstream version ranges) and **OSV's GIT-commit-range CVE
  records** (resolvable because our reference DBs already mine per-release git
  tags → tag→commit is free) are the upstream-fit paths; OSV package queries are
  a coarse distro-flavored net at best; (c) a version-inert or uncovered result
  must be **labeled as such** via the provenance layer (rec. 5), never emitted as
  precise.
- **Source**: [experiments/advisory-fitness](experiments/advisory-fitness/README.md);
  the source menu is [advisory-source-roadmap.md](advisory-source-roadmap.md).
- **Note on scope**: this is detection/identification-core adjacent — the
  *mapping* of identity to a vuln coordinate is in scope as an architectural
  boundary; building the vuln-scanning integration itself belongs to the
  generator/consumer, not this research.
- **Refined 2026-07-29 (lwIP): the mapping is one-to-many, not one-to-one.** Advisories
  for a vendored component are frequently filed against the **carrier distribution**
  rather than the upstream project: of six NVD CVEs describing lwIP flaws, three are bound
  to `lwip_project:lwip`, one to `microchip:advanced_software_framework`, one to
  `espressif:esp-idf`, and one to no CPE at all. A correct upstream identity misses the
  carrier-indexed ones entirely. So the resolver must attach, per finding, **the upstream
  coordinate plus the coordinate of whichever vendor distribution the evidence says this
  copy is** — which makes carrier/fork identification a vuln-relevant detection output,
  not cosmetic provenance. (Cheap discriminators exist: one Espressif-only file,
  `ip4_napt.c`, present in no upstream release, identifies the carrier.) Note the honest
  limit: ESP-IDF's CVE-2026-45160 is in a file that lives in *esp-idf itself*, outside
  even Espressif's lwIP fork — no component-tree fingerprint reaches it; only recognizing
  the carrier does.
- **Also**: a source's own placeholders must be classified, not evaluated. NVD binds
  CVE-2020-22283 to the literal CPE version `-` ("no version information"), which no
  version can match — a naive range test therefore returns "not affected" for *every*
  version. Same class as GHSA's non-conforming range grammars (rec. 11 above): emit
  UNDETERMINED with the reason, never a boolean the source did not support.

## 12. Identity + version does not decide applicability — carry the advisory's condition

A matched advisory has a third input beyond identity and version: an **applicability
condition** (which port, which build config, which feature flag). Model it explicitly
and let a finding be `AFFECTED (conditional)` rather than silently over-claiming.

- **Why**: the first end-to-end detection→CVE run pinned FreeRTOS-Kernel CVE-2024-28115
  by version range correctly — but the CVE only applies to *"ARMv7-M MPU ports and
  ARMv8-M ports with MPU support enabled"*. That condition exists **only in the
  advisory's prose summary**; no source tested (NVD, OSV, GHSA) exposes it
  machine-readably. A version-only verdict is therefore knowingly over-broad: the same
  kernel built for a non-MPU port isn't vulnerable. The detection-side answer is
  component-layer granularity (detecting *which port* is vendored), which is why
  port/`mpu_wrappers` consolidation is the paired next step.
- **Consequences**: (a) surface the advisory's scope text with every affected finding so
  a human can adjudicate; (b) treat "which sub-layer/port/config is present" as
  first-class detection output, not a detail — it is what makes a vuln verdict precise;
  (c) never let an unevaluated condition silently read as "condition met".
- **Validated 2026-07-28** by the FreeRTOS
  [port-layer experiment](../components/freertos/experiments/port-layer/README.md), which
  supplies the missing condition input for CVE-2024-28115 and changes real verdicts (a
  real ESP-IDF fork: AFFECTED → NOT_AFFECTED; an ARMv8-M tree flips either way on
  `configENABLE_MPU` alone). Three rules keep it from becoming triage: the refinement
  **only narrows** (evidence may withdraw or suspend a finding, never create one); **absent
  evidence suspends rather than clears** (no port detected ⇒ POSSIBLY_AFFECTED); and the
  condition itself is **curated advisory metadata carrying its source quote**, not inferred
  from code. Cost, measured: covering the port layer took ~4× the reference-DB size of the
  core kernel files (6.6 MB vs 1.7 MB) — granularity is not free, and is worth budgeting
  per component against which advisories actually key on it.
- **Generalized 2026-08-18 by zlib** — the pattern is not a FreeRTOS quirk. zlib has
  **two** CVEs where a `contrib/` sub-component's flaw is bound machine-readably to the
  *core* zlib CPE while the record's own prose disclaims the core: `CVE-2023-45853`
  (MiniZip; *"NOTE: MiniZip is not a supported part of the zlib product"*) and
  `CVE-2026-22184` (`contrib/untgz`; *"limited to the standalone demonstration utility
  and does not affect the core zlib compression library"*). Two independent instances on
  one component make this a recurring property of CVE records, not an outlier — and here
  the condition axis is **which files were vendored**, not which port, so the evidence is
  cheap (sub-component file presence, no fingerprint DB needed). Two refinements to the
  rules above came out of it:
  (a) **"absent" is a claim that needs its own evidence.** A scanner sees only what it
  was given; "no `unzip.c` found" is meaningless if the tree is an extract rather than a
  complete distribution. `end_to_end_zlib.py` therefore gates ABSENT on a completeness
  check (full core source set + a build entry point) and reports UNKNOWN otherwise —
  making rule 2 operative rather than nominal.
  (b) **The refinement narrows the CVE list even when it can't flip the verdict.** On
  zlib the tree verdict stayed AFFECTED both ways, because a genuine *core* CVE
  (`CVE-2026-27171`) applies at the same version — but the core-only tree's finding list
  went from 3 CVEs to 1, each exclusion carrying its advisory quote. Precision in the
  finding list is the deliverable; flipping the top-level verdict is a bonus, not the
  measure of success.
- **Source**: the end-to-end spikes in
  [experiments/advisory-fitness](experiments/advisory-fitness/README.md)
  ("Closing the loop", Finding 2; and the zlib section).

## 13. Where the generator's job ends: identity and composition, not triage

**Decision (2026-07-28).** The generator's deliverable is a component inventory precise
enough that a *dedicated* vulnerability tool can do its job unaided. It emits: canonical
identity, version window (with its semantics), the **lookup coordinates** each advisory
source needs (CPE 2.3, ecosystem purl, `{owner}/{repo}`, release commit), per-component
coverage metadata, evidence/provenance, and composition facts. It does **not** decide
whether a reported CVE actually impacts the project — no exploitability scoring, no
reachability analysis, no CVE dispositions. If the identifiers are right, its job is done.

- **Why the split is the right one**:
  - **Different data, different lifecycles.** Advisory data changes daily; an SBOM is a
    point-in-time artifact of a build. Folding triage into generation makes the artifact
    stale on arrival and its output non-reproducible — the same tree would "change" as
    feeds update, when nothing about the software changed.
  - **Triage needs project knowledge the generator doesn't have**: build configuration,
    threat model, compensating controls, whether the affected path is reachable in *this*
    firmware. That is a project-evaluation activity.
  - **The ecosystem already separates them**, and the separation has a standard artifact:
    SBOM (CycloneDX/SPDX) → scanner (Grype/Trivy/Dependency-Track) → **VEX**
    (CycloneDX VEX / OpenVEX / CSAF) carrying statuses like
    `vulnerable_code_not_present` and `vulnerable_code_not_in_execute_path`. Triage output
    belongs in VEX, authored by the SBOM's consumer.
  - **What only the generator can supply is upstream identity for copy-pasted code.** No
    downstream scanner can reconstruct that a vendored, modified `tasks.c` is
    FreeRTOS-Kernel 10.5.1 — there is no package manager to ask. That is this project's
    scarce capability, and it's where the effort belongs.
- **The one refinement that keeps this from being a cop-out**: "identity is enough" is
  true only at the **granularity the advisories discriminate at**. CVE-2024-28115 applies
  to FreeRTOS's ARMv7-M/ARMv8-M *MPU port*, not to "FreeRTOS-Kernel" as a whole (rec. 12).
  If the SBOM names only the coarse component, every downstream consumer must
  independently investigate a question the generator could have answered cheaply while it
  had the source tree in hand. So the boundary is **not** "emit the coarsest identity and
  stop" — it's *emit identity, composition and build-inclusion facts at the granularity
  the advisory ecosystem actually keys on, then stop*. Precision in the inventory is
  in-scope work; judgement about impact is not.
- **Consequences for the architecture**: (a) ship the vuln-source coordinates and coverage
  metadata *as part of the output*, not as an afterthought (rec. 11); (b) surface an
  advisory's applicability condition verbatim if the tool reports matches at all — never
  evaluate it (rec. 12); (c) prefer emitting **facts that feed a VEX decision** (this
  port is present; this component is not linked into the artifact — rec. 10) over
  emitting the decision; (d) any CVE-listing convenience feature must be a clearly
  separated layer over the same data, never load-bearing in the core.
- **Consequence for this repo**: end-to-end vuln work here stays a **fitness check** —
  "do our identifiers drive the standard tools correctly?" — and stops at verdict +
  coverage. See the scope guard in the `research-component` skill's phase 3.
- **Source**: scope decision recorded 2026-07-28, prompted by the end-to-end spike in
  [experiments/advisory-fitness](experiments/advisory-fitness/README.md).

## 14. Mine release artifacts, not just git tags — and validate one against the other

The reference KB's release entries should be traceable to **what upstream actually
published**. Where a project releases by archive rather than by tag, mine the archive, or
at minimum verify the tag against it before treating the tag as a release.

- **Why**: lwIP tags `STABLE-2_0_2_RELEASE` and `STABLE-2_0_2_RELEASE_VER` are different
  commits differing in one line — the first still declares `LWIP_VERSION_REVISION 1`, i.e.
  **the commit tagged 2.0.2 says it is 2.0.1**. Downloading the official `lwip-2.0.2.zip`
  settles it: the shipped artifact matches `..._VER`. A tag-mined KB (ours, or any `minr`
  self-mined one) therefore carries a **phantom release** no artifact ever matched, keyed
  under the right-looking name. Upstream tag sets are curated by humans and contain
  mistakes, re-tags, packaging suffixes and maintenance branches.
- **Consequences**: (a) record the artifact a release entry was derived from (archive URL
  and digest, or tag + commit), as provenance rec. 5 already requires for findings;
  (b) when both exist and disagree, the **published artifact wins**; (c) do not prune the
  odd tag out of the KB — keep it and let cross-file intersection disambiguate, which it
  does for free: lwIP's release-zip corpus tree resolves to `..._VER` alone because six
  tracked files match both tags and the seventh matches only one.
- **Bearing on other components**: FatFs (roadmap) has *no* git upstream at all — zip
  archives only — so this stops being an edge case there and becomes the whole mining
  strategy.
- **Source**: [components/lwip/experiments/version-fingerprint](../components/lwip/experiments/version-fingerprint/README.md)
  "Finding 1".

## Keeping this doc honest

These recommendations track findings, not preferences. If a future component or
artifact overturns one (e.g. a curated-KB coverage explosion that flips
recommendation 1, or a corpus that finally forces AST/binary tiers), update the
recommendation here and note the finding that moved it — the same way the component
docs update the cross-cutting principles in [README.md](README.md).
