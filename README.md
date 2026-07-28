# SBOM FOSS Identification Strategy

Research on identifying known C open-source components that have been copy-pasted /
vendored into embedded projects (firmware, RTOS, AUTOSAR-style toolchains) without a
package manager. Findings here will inform an SBOM generator built in a separate repo —
this repo is **research only**; it does not build the generator or design SBOM output
formats.

See [CLAUDE.md](CLAUDE.md) for the full scope, priorities, decisions, and working
conventions. The status below is a snapshot as of 2026-07-29.

## Current status

**Components researched** (each: distribution landscape + a validated version-fingerprint
experiment):
- [FreeRTOS](components/freertos/README.md) — kernel/libraries/umbrella granularity;
  exact-hash + winnowing with cross-file version consistency.
- [mbedTLS](components/mbedtls/README.md) — governance/4.0 repo split; vendor integration
  layers; a licensing-divergence finding; validated against real Espressif/ST/NXP forks.
- [CMSIS](components/cmsis/README.md) — the most fragmented component (three simultaneous
  version numbers); architecture-tied-standard gating; vendor "CMSIS/Device" trees are
  vendor-authored despite the path.
- [lwIP](components/lwip/README.md) — four real vendor forks, four different shapes (ST
  verbatim, Espressif/NXP heavily patched, Xilinx version-in-path); lwIP is itself a
  vendoring carrier (reduced PolarSSL 0.10.1 + pppd 2.4.5 inside it); a **phantom release
  tag**; advisories filed against the carrier distribution rather than upstream.
- nanopb entered via the static-library work (below), not as a standalone study.

**Detection techniques** — full catalogue and priorities in
[general/fingerprint-detection-roadmap.md](general/fingerprint-detection-roadmap.md):
- *Covered/validated*: exact & normalized file-hash, token-winnowing, file/tag-set +
  cross-file version consistency, **symbol-set** (defined globals of `.a`, mineable from
  headers), `ar` member-name metadata.
- *Corroboration*: version-string/macro & license-header heuristics; vendor-manifest
  harvest (discrepancies treated as output, not ground truth).
- *Logged TODOs*: AST/structure-normalized (top), constant/data-table, function-level,
  fuzzy/MinHash; binary CFG/BSim parked (legal + out-of-corpus).

**Static libraries** ([general/experiments/static-lib-identification](general/experiments/static-lib-identification/README.md)) —
the prebuilt-`*.a`+headers case, validated against a real TI SimpleLink SDK: symbol-set
version fingerprinting works (found nanopb hidden in a proprietary blob and 30 undeclared
Wi-SUN mbedTLS copies), compiler-independent, zero false positives across 588 libs.

**Reference corpus / KB** ([general/existing-fingerprint-datasets.md](general/existing-fingerprint-datasets.md)) —
reuse-first survey (SCANOSS OSSKB, Software Heritage, ClearlyDefined, PurlDB). Decision:
a **curated per-component KB is the attribution backbone** (attribution-by-construction),
because public datasets have a structural attribution gap. Industrialized by self-mining
with SCANOSS `minr` ([general/experiments/minr-self-mining](general/experiments/minr-self-mining/README.md)),
exported to a compact, **tier-labeled** scanner artifact (~48 MB for 3 components) that
carries the exact, winnowing, and symbol tiers over one canonical release table.

**Advisory-source fitness** ([general/experiments/advisory-fitness](general/experiments/advisory-fitness/README.md),
[general/advisory-source-roadmap.md](general/advisory-source-roadmap.md)) — does the
purl+version output actually drive vuln scanning? Tested against OSV.dev, NVD/CPE, GHSA.
**NVD/CPE is the fit source** (real version-range matching); OSV is version-inert for
embedded C and GHSA's *global* feed has no C/C++ ecosystem — but its **per-repository**
feed carries real kernel-semver ranges for maintainers who self-publish. The SBOM
identity is *not* the vuln-lookup key.

**Loop closed for FreeRTOS** (2026-07-28, same experiment folder) — the first
**end-to-end SBOM→vuln result**: vendored tree → fingerprint detection → GHSA per-repo
advisory range → CVE verdict. All three corpus ground truths resolve correctly
(NXP V11.2.0 → not affected; esp-idf fork and the mixed tree → CVE-2024-28115). Findings:
a version *set* means either "candidates" or "coexisting" and the verdict differs;
version membership is necessary but **not sufficient** (this CVE applies only to MPU
ports — a prose-only condition); GHSA's documented range grammar isn't reliably honored;
"not covered" is a first-class result.

**Port layer identified — the verdict made precise** (2026-07-28,
[components/freertos/experiments/port-layer](components/freertos/experiments/port-layer/README.md)) —
a second, independent detector answering *which port* (content-based: upstream path names
are unreliable, ESP-IDF's ports live at `portable/xtensa/`), with MPU as a three-valued
classification and `configENABLE_MPU` read from the tree as build evidence. It changes
real answers: a real ESP-IDF fork goes AFFECTED → **NOT_AFFECTED** (Xtensa port, not an
ARM MPU port), and an ARMv8-M tree flips either way on one build macro. Safety rules: the
refinement **only narrows**, absent evidence **suspends rather than clears**, and the
applicability condition is curated advisory metadata carrying its source quote.

**Architecture handoff** ([general/sbom-generator-architecture.md](general/sbom-generator-architecture.md)) —
durable, evidence-grounded recommendations for the separate generator's detection core:
curated-KB backbone, two-tier distribution, evidence-producer/resolver split, selectable
profiles, per-finding provenance, the metadata-vs-disassembly legal boundary, canonical
attribution, version windows, identity→vuln-source coordinate mapping, and where the
generator's job ends (identifiers and composition facts — triage/VEX is the consumer's).

**Second loop closed, through NVD/CPE** (2026-07-29, lwIP phase 3) — `nvd_vuln_lookup.py`
+ `end_to_end_lwip.py`, all 8 corpus trees correct (1.4.1 → AFFECTED by CVE-2014-4883;
modern trees NOT_AFFECTED; negative control NOT_QUERYABLE). Findings: **identity→CPE is
one-to-many** — advisories for vendored code are often filed against the *carrier*
(`espressif:esp-idf`, `microchip:advanced_software_framework`) rather than upstream; a CPE
bound to the literal version `-` matches nothing and must report UNDETERMINED, not
"not affected"; and **git tags are not release artifacts** (lwIP's `STABLE-2_0_2_RELEASE`
is a phantom that no shipped zip matches).

**Nested components — the attribution rule tested, and it failed**
([general/experiments/nested-component-attribution](general/experiments/nested-component-attribution/README.md),
2026-07-29) — lwIP vendors a reduced PolarSSL 0.10.1 and pppd 2.4.5 inside itself, so the
long-asserted "stacked components" rule finally had a real case. The curated KB scanned a
309-file lwIP tree containing **zero** Mbed TLS and reported `CONSISTENT: mbed-tls
2.28.8–2.28.10, Apache-2.0` — wrong component, era and license, at top confidence. Causes:
the tree verdict has **no minimum-evidence rule** (one match promoted to a whole-tree
claim; 308 non-matches discarded), and that one match is **constant tables, not code**
(0.794 similarity on hex constants, 0.071 on code — DES S-boxes are fixed by FIPS 46).
A mandatory caveat now rides with the roadmap's planned constant-table tier.

**Next up (designated 2026-07-29)**: **the resolver's evidence rule** — match ratio +
floor, negative evidence counted, snippet-vs-component verdicts split, and an
"origin outside coverage" result, then re-validate every corpus. It is the direct fix for
the nested-component failure above, and it should land *before* the other item that pass
created (**carrier/fork identification** — recognizing *Espressif's* lwIP rather than
generic lwIP 2.2.0, so the carrier's CPE can be queried), since carrier ID feeds more
single-signal evidence into the same resolver. Details in [CLAUDE.md](CLAUDE.md).

**Then**: breadth — the next component (**FatFs**, the adversarial
no-git-upstream case) via the
`research-component` skill, which now includes advisory-source mapping as phase 3. Still
paused: the rest of the **vuln-source mapping layer** (identity→CPE, FreeRTOS
version-scheme reconciliation, a tag→commit resolver over OSV GIT ranges) — see the
backlog item in [CLAUDE.md](CLAUDE.md); its per-component coverage-metadata and
GHSA-repo-map sub-tasks are now done. Roadmaps: [components](general/component-roadmap.md),
[techniques](general/fingerprint-detection-roadmap.md),
[advisory sources](general/advisory-source-roadmap.md).

## Layout

- [general/](general/) — cross-cutting principles that apply across components (SBOM
  identifier strategy, detection technique patterns, attribution rules), the roadmaps,
  the architecture handoff, and cross-cutting `experiments/` (self-mining, static-lib,
  advisory-fitness, OSSKB dataset).
- [components/](components/) — one folder per researched component (e.g.
  `components/freertos/`), each with a `README.md` of findings and, once there's
  content, `experiments/` (prototype scripts) and `corpus/` (ground-truth examples)
  subfolders.
