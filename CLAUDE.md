# Purpose of this repository

This is a **research-only** repository. There is no product code to ship from here.
The goal is to research techniques for identifying known C open-source (FOSS) components
that have been integrated into embedded projects via **copy-paste / vendoring**, i.e.
*without* a package manager (no Conan, no vcpkg, no CMake FetchContent tracking, no git
submodules with clean provenance). The findings from this repo will later inform an SBOM
generator built in a **separate** repository — do not implement a generator here, only
the detection research and prototypes that will inform it.

**Scope note (widened 2026-07-22)**: capturing *architectural recommendations/hints*
for how the eventual generator should be modelled — grounded in this repo's findings,
as a durable handoff — is now **in scope**, collected in
[general/sbom-generator-architecture.md](general/sbom-generator-architecture.md).
This does **not** change the two hard exclusions: don't build the generator here, and
don't design output serialization (CycloneDX/SPDX) here (see "SBOM output format").

When you (Claude) start a session in this repo, treat the scope below as settled context
established with the user — don't re-ask these questions, but do flag if new
findings suggest revisiting a decision.

## Current status

- **Researched**: [FreeRTOS](components/freertos/README.md) — distribution landscape,
  SBOM naming/identifier strategy, and a working version-fingerprinting experiment
  (exact-hash + winnowing similarity, with cross-file consistency checking to catch
  mixed-version integrations).
- **Researched**: [mbedTLS](components/mbedtls/README.md) — governance/licensing
  history, the 4.0/TF-PSA-Crypto repo split and its component-granularity implications,
  vendor integration layers (confirmed by diffing real Espressif/ST/NXP forks against
  upstream, correcting an initial docs-only hypothesis), a licensing-divergence finding
  (ST re-licenses to Apache-2.0-only via a header-line edit invisible to comment-stripped
  matching), and a working version-fingerprinting experiment validated against three real
  vendor forks plus mixed-version and negative-control cases.
- Added a reusable **`research-component` skill** (`.claude/skills/research-component/`)
  codifying this two-phase workflow (distro-landscape research verified against real
  source, then a version-fingerprint experiment) plus ready-to-copy fingerprinting/
  reference-DB/matcher script templates, so the next component doesn't re-derive the
  process from scratch.
- **Researched**: [CMSIS](components/cmsis/README.md) — both phases complete. Confirmed
  the most fragmented component researched so far: sub-components (Core, DSP, NN,
  RTOS2/RTX, Driver, DAP, View, Zone, Stream, Compiler) are independently versioned/repo'd,
  with a further umbrella "pack version" layer bundling snapshots of them and an in-source
  `cmsis_version.h` macro tracking Core specifically — three distinct, simultaneously
  meaningful version numbers. Also found that vendor "CMSIS/Device/<vendor>" trees (e.g.
  STMicroelectronics's `cmsis-device-f4`) are 100% vendor-authored/copyrighted despite
  living in a path and file headers that say "CMSIS" — confirmed by diffing real
  STM32CubeF4 files against upstream Arm CMSIS_5 (Core files byte-identical; device
  headers wholly ST's own). NVD has a CPE only for `cmsis-rtos` (type `o`, matching the
  general RTOS-classification gotcha); no CPE for Core/DSP/NN/Driver/the overall pack.
  Separately confirmed (session after Phase 1) that CMSIS is gated by **CPU architecture
  licensing, not by vendor identity** — Infineon (XMC/Cortex-M ships CMSIS, AURIX/TriCore
  doesn't) and Renesas (RA/Cortex-M ships CMSIS, RX's proprietary architecture doesn't)
  show the identical split already found for NXP, now generalized into
  [general/README.md](general/README.md#architecture-tied-standards-are-gated-by-cpu-core-choice-not-by-vendor).
  **Phase 2** (version-fingerprint experiment,
  [components/cmsis/experiments/version-fingerprint](components/cmsis/experiments/version-fingerprint/README.md)):
  tracks `cmsis_version.h` plus `core_cm0.h`/`core_cm4.h`/`core_cm33.h`, reference DB spans
  both `CMSIS_5` (13 releases) and `CMSIS_6` (4 releases), validated against a real ST
  fork, a real NXP fork (found to be a west-managed external dependency, not a static
  copy-paste, correcting a Phase 1 gap — both real forks turned out **byte-identical to
  upstream**, i.e. verbatim vendoring, not patched), a synthetic mixed-version case, and a
  negative control.
- **Researched (cross-cutting)**: existing precomputed fingerprint datasets/knowledge
  bases ([general/existing-fingerprint-datasets.md](general/existing-fingerprint-datasets.md)) —
  surveyed SCANOSS OSSKB (free winnowing-fingerprint API + CC0 downloadable dataset +
  GPL-2.0 self-hostable mining stack), Software Heritage, ClearlyDefined,
  PurlDB/MatchCode, CENTRIS; then tested OSSKB empirically against this repo's
  ground-truth corpus. Result: recall is excellent (all real vendor-fork files matched;
  a synthetically modified file existing in no public repo still matched at 84% via
  snippets), but raw attribution names *an arbitrary containing repo* with that repo's
  versions/licenses (an Espressif-patched mbedTLS file attributed to Realtek's
  `ameba-rtos`; the modified file attributed to the Rebol3 interpreter with a
  completely wrong license list). Follow-up (2026-07-13, documented in the same file):
  free-API availability is fine for batched, paced scans — ~930 FreeRTOS-repo files
  scanned with zero 503s via `scanoss-py` — but the 503 "Rate limit exceeded" was
  reproduced with SBOM Workbench 1.26.1 (a full 11.5k-file tree at ~4.6 files/request,
  ~8 req/s), which exhausted the shared per-location bucket and locked the IP out for
  ~5 hours (`retry_after` ≈ 18,900 s, confirmed shared when `scanoss-py` subsequently
  503'd on the same countdown). Proper `scanoss-py` batching config (post-size/threads/
  offline-fingerprint split) is documented in the same file. Same scans added a
  worse attribution case: *verbatim* GPLv2 Reliance-Edge files inside the FreeRTOS
  umbrella repo reported as `pkg:github/freertos/freertos`, license MIT. Second
  follow-up (2026-07-13, same day): the **CC0 open dataset was downloaded and
  inspected** (open item 3 resolved — see
  [general/experiments/osskb-open-dataset](general/experiments/osskb-open-dataset/README.md)):
  ~1.2 TiB of LDB shards, snapshot ~9.5 months behind the live KB; each `file-url`
  record is `path, one-exemplar-URL, count-of-containing-URLs` with **no
  purl/license/version metadata and no full URL list** — so attribution
  post-processing can't be built on the offline data, though the count field is a
  new routing signal (count 1 → exemplar is likely the true origin). A clean-room
  Python LDB reader lives in that experiment folder. A company-scale feasibility
  assessment (free/sponsored/dataset-only tiers for a 50+-project standard scanner)
  is documented in the same file's "Feasibility" section. Third follow-up
  (2026-07-16): the **`wfp` (winnowing) table was also inspected** — one 4.4 GiB
  shard downloaded, fixed-record LDB variant cracked clean-room
  (`hash → (file MD5, line)` inverted index, record layout validated against
  locally generated `scanoss-py` fingerprints), and **offline snippet matching
  proven end-to-end**: the Espressif-modified `tasks.c`, absent from the snapshot
  as an exact file, was pinned to its own esp-idf lineage by snippet-hash voting
  (`wfp_lookup.py`/`wfp_pipeline.py` in the same experiment folder). So the
  offline dataset can serve both verbatim and modified-copy detection;
  attribution remains its gap.
- **Roadmap**: a prioritized, automotive-first list of candidate components to research
  next lives in [general/component-roadmap.md](general/component-roadmap.md) (written
  2026-07-08) — consult it when picking a new component instead of re-deriving candidates.
- **Technique roadmap** (added 2026-07-22):
  [general/fingerprint-detection-roadmap.md](general/fingerprint-detection-roadmap.md)
  catalogues every fingerprint *technique* (covered vs. not) and logs the uncovered
  ones — AST-normalized (top), constant/data-table, function-level, fuzzy/MinHash,
  binary CFG (parked) — as **low-priority TODOs**. Consult before proposing a "new"
  detection idea.
- **Architecture handoff** (added 2026-07-22, per the scope widening):
  [general/sbom-generator-architecture.md](general/sbom-generator-architecture.md)
  collects architectural recommendations for the separate generator, each traced to a
  finding (curated-KB backbone, two-tier distribution, evidence-producer/resolver
  split, selectable profiles, per-finding provenance, metadata-vs-disassembly legal
  boundary, canonical attribution, version windows). Detection-core modelling only.
- **In progress**: the **self-mining (`minr`) investigation** (open item 4 in
  [general/existing-fingerprint-datasets.md](general/existing-fingerprint-datasets.md))
  — **started 2026-07-18**, first results in
  [general/experiments/minr-self-mining](general/experiments/minr-self-mining/README.md):
  the full GPL stack (ldb/minr/engine) built and run in Docker; 13 FreeRTOS-Kernel
  releases mined with declared metadata and imported in 5m24s;
  **attribution-by-construction confirmed** (declared purl/version/license
  round-trip into every match — the arbitrary-repo failure mode is structurally
  impossible in a curated KB); verbatim (NXP → V11.2.0) and mixed-version corpus
  trees matched exactly; the modified esp-idf fork detected via snippets (93–99%)
  but version-pinned to a near-neighbor point release (bespoke matcher's
  version-window output remains better for that); raw-MD5 exact matching shown
  fragile to header-comment edits (Espressif's `list.c`); LDB disk = ~21 GB/table
  zero-filled-map preallocation floor (103 GB for one component), **resolved** by
  hole-punching (`fallocate --dig-holes`: 103 GB → 408 MB allocated, scan results
  identical — copies must be sparse-aware). **mbedTLS baseline also done
  (2026-07-18)**: 12 releases mined into the same KB in 3m25s (KB → 1.4 GB
  allocated, wfp-dominated); attribution again perfect across all four real/
  synthetic trees and the cJSON negative control returned no match; NXP's heavily
  modified 2.28.10 fork version-pinned *exactly* via snippets, while ST's tree
  showed the raw-MD5 fragility finding at full scale (the SPDX-header edit pushes
  the whole tree to snippet path) and release-shared content showed the engine's
  arbitrary version tie-break (3.6.0 files reported as 3.6.1). **CMSIS baseline
  also done (2026-07-18)**: 7 releases across the CMSIS_5/CMSIS_6 repo split in
  1m44s (KB → 2.0 GB); attribution perfect, negative control clean, synthetic
  mix's rogue `core_cm4.h` isolated — but the verbatim-5.9.0 vendor trees came
  out looking like 5.8/5.9 mixes (per-file tie-breaks on release-shared content),
  i.e. **engine output can't distinguish a verbatim tree from a mixed tree**;
  and the **containing-URL-list subtask resolved by construction**: the `file`
  table natively stores one record per containing release (verified: shared
  `core_cm0.h` hash → both 5.8.0 and 5.9.0 records), so the bespoke
  tag-set/window/consistency logic ports as a thin post-processor over the KB
  (ldb CLI or the osskb experiment's clean-room Python reader). **Lightweight-export prototype done (2026-07-18)**:
  the whole 3-component KB exported clean-room to one **48 MB gzipped JSON**
  (`export_lightweight.py`), and `validate_export.py` reproduced all 12 corpus
  ground truths from the artifact alone — fixing the engine's fake-mix problem
  (verbatim CMSIS trees → CONSISTENT 5.9.0 via release-set intersection) and
  improving modified-fork version assignment (NXP mbedTLS → exactly 2.28.10);
  extrapolates to ~100–300 MB for the full roadmap → two-tier rollout model
  validated (thin bundled artifact + central full KB for evidence; the
  KB-as-versioned-pulled-artifact distribution strategy is documented in the
  experiment README). Known refinements: widen snippet-tier sets to windows
  before intersecting (coherent heavy forks over-trigger MIXED), and the
  normalized-hash tier for header-only edits. Remaining subtasks: hybrid
  curated-first/CC0-fallback lookup path; **plain-JSON artifact feasibility**
  (queued 2026-07-18 — evaluate pretty-printed inspectable JSON as the
  canonical export format, compression as transport-only, likely hybrid with
  per-component splits; auditability rationale + measurement plan in the
  experiment README).
- **In progress (promoted and started 2026-07-21): the static-library
  (`*.a` + headers) identification investigation** — the open topic queued
  2026-07-16, promoted over the OSV.dev fitness test by explicit decision
  2026-07-21 (the pipeline isn't at the vuln-scanning stage yet; a real-world
  TI encounter made this scenario concrete). **First triage session done
  (2026-07-21)**, findings in
  [general/experiments/static-lib-identification](general/experiments/static-lib-identification/README.md):
  surveyed the locally installed TI SimpleLink CC13xx/CC26xx SDK 8.33.00.16
  (684 archives, 1.4 GB; gcc/IAR/ticlang × several cores). All four cheap
  signals validated with stock Cygwin binutils: `ar` member names preserve
  upstream filenames (FatFs/mbedTLS member sets unmistakable and even
  version-indicative); `nm` defined-symbol sets readable for both GCC and
  IAR ELF and are the natural port of the tag-set fingerprinting approach;
  `strings` is **confirm-only** (mbedTLS's `"3.5.0"` literal got compiled
  into instruction immediates — absence proves nothing); bundled
  source/headers often make the binary question moot (mbedTLS/FatFs/SPIFFS
  ship full source next to the libs). Headline case: **nanopb embedded
  wholesale and unannounced inside the proprietary 10.5 MB
  `sidewalk_fsk_ble.a`** (members + `pb_*` symbols, no license strings) —
  the opaque-carrier scenario proven on a shipping SDK. Also: TI's
  `third_party\ecc` is TI-proprietary with a **no-disassembly license
  clause** (limits how deep binary-similarity tiers may legally go —
  metadata-tier signals must carry the load), and IAR `freertos.a` contains
  only `portasm.s.o` (archive names mislead in both directions). **Vendor
  SBOM/manifest reuse checked (2026-07-21, same README)**: TI ships a real
  per-component manifest HTML at the SDK root and upstream SBOMs ride along
  in vendored trees (AWS's `sbom.spdx` for FreeRTOS v10.5.1 with per-file
  SHA1s), but the manifest is demonstrably unreliable on this very SDK
  (nanopb entirely undeclared; Mbed-TLS declared 3.4.0 while shipped
  headers say 3.5.0), and Code Composer Studio has no SBOM-generation
  capability (it only ships ScanCode-generated SPDX for TI's compiler RTS) —
  so vendor manifests are a harvest/corroboration tier, not a substitute
  for detection. **Symbol-set version-fingerprint prototype built and
  validated (2026-07-21, same README)**: clean-room ar+ELF32/64 extractor,
  source-only reference mining (git tag checkout + header prototype
  patterns — the no-compiler thesis confirmed), and a subset-tolerant
  window matcher. All ground truths hit: both nanopb copies (labeled
  prebuilt *and* the hidden copy inside the proprietary sidewalk blob) →
  window {0.3.9…0.3.9.3} containing the true 0.3.9.3; `libmbedcrypto.a` →
  window {v3.5.0–v3.5.2} containing the true 3.5.0, **positively excluding
  the manifest's claimed 3.4.0 from binary evidence alone**; both negative
  controls NO MATCH. Bonus finding: `libmbedcrypto.a` is an x86-64 *host*
  build shipped in the ARM SDK (build detritus — scanners must be
  arch-agnostic). Windows are 3–4 point releases wide (coarser than source
  hashing, as expected; same window-shaped output the consistency logic
  handles). **De-risking sweeps done (2026-07-22)**, findings in the same
  README: (a) compiler-independence **verified empirically** — component
  symbol sets identical across gcc/IAR/ticlang and across cores for every
  multi-flavor lib in the SDK (only diffs: IAR-internal `__iar_cc..`
  helpers, filterable by prefix, and one genuine build-content difference —
  ticlang fatfs bundles an extra TI `ffcio` shim member); (b) batch-scan
  of all 588 TI-authored libs (`batch_scan.py`): **zero false positives**
  (556 NO MATCH) and 32 hits all genuine — the 2 known Sidewalk/nanopb
  carriers plus a **new headline finding: all 30 `ti_wisunfan`
  `wisun_*_mbed_ns_tls_lib_*.a` libs embed a full mbedTLS**, which four
  sources version four ways (manifest: "Mbed-OS mbedtls 5.15.7"; shipped
  tree VERSION.txt: 2.22.0; that tree's version.h: number says 2.16.0 but
  string says 2.22.0; symbols: after widening the reference DB with 7
  pre-2.28 tags, the window collapsed to **exactly mbedtls-2.22.0** — a
  long-EOL release, pinned by 2.22-era PSA internals absent both before
  and after). Lessons: reference-DB tag coverage, not technique, sets
  window width; even shipped version headers can self-contradict.
  **Symbol tier folded into the lightweight-export artifact (2026-07-22,
  step 1 done)**: the artifact is now **tier-labeled schema 2** — a shared
  canonical `releases` table plus a `tiers` map where each tier declares its
  fingerprint-roadmap technique number (`exact`=1, `winnowing`=2, `symbol`=4).
  `symbol_tier.py` (in the minr-self-mining experiment) builds a symbol-tier
  fragment from the mined `*_ref_symbols.json` DBs and merges it into the
  export, **reconciling by `(component, version)`**: mbedTLS's 8 KB-overlapping
  versions reused existing release-ids, its 17 pre-2.28 versions and all 26
  nanopb versions minted with `source_tier: "symbol"` (nanopb enters the
  artifact purely via this tier; cost +0.2 MB on 48 MB). `symbol_tier.py match`
  reproduced every static-lib ground truth **from the merged artifact alone**
  (both nanopb carriers → 0.3.9.3 window; `libmbedcrypto` → {3.5.0–3.5.2},
  excluding the manifest's 3.4.0; Wi-SUN → exactly 2.22.0; TI-authored negative
  control → NO MATCH), each resolving to a canonical purl — attribution by
  construction in the symbol domain too. This realizes architecture recs. 3–4
  (tiers as independently-selectable producers over one resolver). Details in
  [general/experiments/minr-self-mining/README.md](general/experiments/minr-self-mining/README.md)
  "Tier-labeled artifact + symbol-tier fold-in". **Next step (2)**: the
  deferred OSV.dev fitness test reclaims the next-up slot, with two fresh
  test inputs: the manifest-says-3.4.0/binary-says-3.5.x mbedTLS case and
  the Wi-SUN embedded 2.22.0 (EOL, misdeclared as "5.15.7").
  Deferred as polish: data-symbol mining, member-name normalization
  policy, stripped/LTO hard tier (parked until a real artifact).
- **Researched (cross-cutting): the OSV.dev vulnerability-scanning fitness
  test** — open item 2, **RUN 2026-07-22**, findings in
  [general/experiments/osv-fitness](general/experiments/osv-fitness/README.md).
  Result: **OSV.dev is not directly fit to consume our upstream purl+version
  output for embedded C**, three independent ways: (a) the GitHub-flavored purls
  we declare (`pkg:github/mbed-tls/mbedtls`, …) return **0** for all four
  components — OSV indexes ecosystem purls (`pkg:pypi/…`, `pkg:deb/…`), not
  `pkg:github/…` (a `pkg:pypi/django` control returned 21 CVEs, proving the
  query technique) — so **identity and vuln-lookup coordinate are different
  keys**; (b) the fallback bare-`name` query is **version-inert** (mbedTLS
  @2.28.0, @3.6.2, and an *impossible* @99.0.0 all return the same 83 CVEs — it
  degenerates to every distro advisory), so a naive `name+version → OSV`
  integration reports the identical CVE list for every version and the whole
  version-pinning effort buys nothing on that path; (c) **coverage is
  component-specific** — FreeRTOS 0 under every coordinate (a known FreeRTOS CVE
  isn't even in OSV), CMSIS 0, nanopb only accidental PyPI coverage — so empty
  must mean "not covered," never "no known vulns." The one upstream-accurate
  path OSV offers (raw CVE records with **GIT-commit ranges**) is usable *by us*
  because the reference DBs already mine per-release git tags (tag→commit is
  free). Net: **reinforces the metadata-mapping open item** — a mapping layer
  from canonical identity to each vuln source's coordinate system is mandatory;
  captured as recommendation 11 in
  [general/sbom-generator-architecture.md](general/sbom-generator-architecture.md).
  Reusable probe harness: `osv_probe.py`. **Next-up now**: the NVD/CPE
  fitness probe (does CPE version-range matching give the discrimination OSV's
  package queries lack?) is the natural continuation and directly feeds the
  mapping layer. Runner-up alternatives if breadth is preferred:
  lwIP as the fourth component (roadmap Tier 1 #1 — now cheap via the minr
  pipeline, stresses the port-layer-vs-core question), or FatFs as the
  adversarial no-git-upstream case.
  The 2026-07-16 decision (see the Decision paragraph in the reference-corpus
  section below) upgrades this task's framing: minr is no longer "an alternative
  to explore" but **the industrialization of the chosen backbone** (curated
  attribution-by-construction), with the bespoke per-component DBs as its
  validation ground truth. Other open items remain (attribution post-processing —
  now known to require online/mined data since the offline dataset lacks the URL
  list; the OSV.dev vuln-scanning fitness test; metadata-mapping layers). The
  CC0-dataset inspection item is done (2026-07-13, wfp table included 2026-07-16).
  Picking a wholly new component to research remains the alternative. See
  "Low-priority deferred follow-ups" below for CMSIS/mbedTLS loose ends that are
  explicitly parked, not forgotten.
- **Open topic (queued 2026-07-16, not started)**: **identifying OSS components
  delivered as prebuilt static libraries (`*.a`/`*.lib`) plus public headers** —
  a common vendor-SDK distribution shape (e.g. closed-source middleware wrapping
  OSS, silicon-vendor binary blobs bundling FreeRTOS/mbedTLS/lwIP builds) that
  all of this repo's current techniques miss, since they assume vendored
  *source*. The investigation, when picked up, should survey candidate signals
  without presuming one: the headers themselves (still source — current
  fingerprinting applies directly); archive-level metadata (`.a` is an `ar`
  archive of `.o` members — member names often preserve upstream source
  filenames); embedded strings (version banners like `FreeRTOS V10.x`,
  `MBEDTLS_VERSION_STRING`, license text, panic/assert format strings with
  source paths); symbol tables (`nm`-visible function-name sets are a
  high-signal fingerprint of a component and its version surface); and
  function-level binary similarity for stripped/LTO cases (the hard end:
  compiler/flag variance — candidate tools to evaluate include Ghidra BSim,
  FunctionSimSearch/binary CFG hashing). Note this **partially revises the
  "binary analysis out of scope" line** in the problem scope below — scoped to
  static-library + header bundles, not general firmware-image analysis.
  **Re-raised 2026-07-21 with a concrete real-world case**: encountered in
  practice in **Texas Instruments SDKs associated with Bluetooth Low Energy**
  (the SimpleLink CC13xx/CC26xx family — the BLE stack ships as prebuilt
  static libraries bundled with public headers, with only a thin app/profile
  layer in source). This makes the topic no longer hypothetical, and the
  artifact is obtainable: SimpleLink SDKs are freely downloadable from ti.com,
  so the survey signals (ar member names, nm symbol tables, embedded strings,
  header fingerprinting) can be run against the real thing locally — though
  TI's license terms likely preclude checking the binaries into this repo as
  corpus, so findings would be recorded as docs + scripts rather than
  redistributable corpus files. **Promoted and started 2026-07-21** — see the
  "In progress" bullet above and
  [general/experiments/static-lib-identification](general/experiments/static-lib-identification/README.md).

## Low-priority deferred follow-ups

These are known, explicitly-deprioritized gaps — not urgent, not blocking, revisit only
when there's time to spare or a new finding makes one suddenly relevant. Listed here so a
future session doesn't have to re-derive that they're low priority from scratch.

- **CMSIS**: a genuinely *modified* real CMSIS-Core fork was never found — both real forks
  diffed (ST, NXP) turned out byte-identical/verbatim. Renesas's `renesas/fsp`
  (`ra/fsp/src/bsp/cmsis/Device/RENESAS/Include/`) is an untried third candidate if a
  modified case is ever needed to stress-test the PARTIALLY MODIFIED matcher path.
- **CMSIS**: CMSIS-NN's date-based-to-semver tag-scheme bucketing decision is documented
  ([experiments/version-fingerprint README](components/cmsis/experiments/version-fingerprint/README.md#cmsis-nn-tag-scheme-decision-documented-not-implemented---cmsis-nn-is-out-of-this-experiments-scope))
  but not implemented — only relevant if CMSIS-NN itself is ever brought into detection
  scope (it currently isn't; header/macro CMSIS sub-components were prioritized over the
  optional/opt-in DSP/NN libraries).
- **CMSIS**: CMSIS-Zone, CMSIS-Toolbox, CMSIS-Stream, and CMSIS-View were only confirmed
  as separate repos, not investigated for a real vendoring footprint — current read is
  they're host-side tooling/debug components, unlikely to show up copy-pasted into
  firmware source trees, but not exhaustively ruled out.
- **CMSIS**: whether Device Family Pack repos (e.g. `cmsis-device-f4`, `STM32U5xx_DFP`)
  should become their own first-class detection targets (separate from both "CMSIS" and
  the vendor's HAL) is an open policy question, not a research gap — needs a decision,
  not more investigation.
- **mbedTLS**: the experiment's reference DB and corpus are scoped to 2.x/3.x only —
  extending to cover the 4.0/TF-PSA-Crypto split (where `bignum.c`/`ecp.c`/`aes.c`/
  `ecdsa.c` move to a separate repo) would need its own reference DB build, deferred since
  Phase 1/2 already validated the approach on the 2.x/3.x era.

## Problem scope

- **Target language: C only.** C++ is explicitly out of scope.
- **Target environments:** bare-metal / RTOS firmware. Specifically:
  - FreeRTOS-based projects
  - Vendor HALs/SDKs (STM32 HAL, ESP-IDF, NXP MCUXpresso, etc.)
  - AUTOSAR-style architectures with proprietary OS/toolchains (e.g. Vector)
  - General bare-metal C source trees
- **Integration patterns to detect** (in priority order):
  1. **Vendored source that has been locally modified** — exact hash matching will fail;
     needs fuzzy/similarity matching that tolerates patches, renamed identifiers, and
     reformatting.
  2. **Amalgamated / single-header libraries** — e.g. stb_*.h-style or amalgamated builds
     of larger projects dropped in as one or two files.
- Snippet-level copies and unmodified verbatim vendoring are secondary/background cases
  worth noting but are not the primary detection targets.

## Detection approaches under research

The full catalogue of fingerprint techniques — covered vs. not, with priorities —
lives in
[general/fingerprint-detection-roadmap.md](general/fingerprint-detection-roadmap.md);
consult it before proposing a "new" technique. The high-level families:

1. **File/hash-based matching** — normalized-content hashing against known OSS file
   versions (ScanCode/ORT-style). *(Covered.)*
2. **Fingerprint/similarity matching** — token or AST-level fingerprints (winnowing,
   MinHash, fuzzy hashing) to catch modified copies. This is the highest-priority
   technique given the "locally modified" focus above. *(Token-winnowing covered;
   AST/MinHash/fuzzy are logged as low-priority TODOs in the roadmap — AST is the
   top uncovered one, targeting the identifier-rename case winnowing half-misses.)*
3. **Metadata/string heuristics** — license headers, version macros, distinctive
   `#define`s, author comments, embedded identifiers. *(Used as a confirm-only
   corroboration layer.)*
4. **Symbol-set / static-library tier** — defined-symbol and `ar` member-name
   fingerprints for prebuilt `*.a` + header bundles (the 2026-07-16 scoped exception
   to "binary out of scope", promoted and validated 2026-07-21/22). Constant/data-
   table fingerprinting and binary CFG/BSim similarity are the uncovered/parked
   binary tiers in the roadmap.
5. General firmware-image binary analysis remains out of scope — source-level plus
   the static-library-bundle exception only.

## Reference corpus question — stance settled, fitness investigation open

Researched empirically on 2026-07-08 — findings, tradeoffs, and open items in
[general/existing-fingerprint-datasets.md](general/existing-fingerprint-datasets.md).

**Settled stance (2026-07-08)**: **reuse-first** — prefer existing datasets/knowledge bases
(SCANOSS OSSKB and its CC0 open dataset, Software Heritage, ClearlyDefined, PurlDB)
over building our own wherever possible; we can't match the effort the OSS community
has already invested in mining. Building our own artifacts (e.g. the curated
per-component reference DBs from this repo's experiments) is the gap-filler for what
existing datasets demonstrably can't do, not the default. *(Refined 2026-07-16 — see
the Decision paragraph below: reuse-first survives for recall, but for attribution
the relationship inverted.)*

**The bar**: the end goal is efficiently identifying components *and mapping their
associated information* (canonical identity/PURL, version, license) well enough to
generate SBOMs that can drive **vulnerability scanning**. The empirical test showed
existing datasets fully cover recall/identification, but their raw attribution output
(arbitrary containing repo + that repo's versions/licenses) would feed wrong purls to a
vuln scanner. Whether that gap can be closed *on top of* reused data is now
partially answered: it demonstrably **cannot** be closed on the offline CC0 dataset
(no URL list, no metadata — proven by direct inspection 2026-07-13/16), leaving
online or self-mined data as the only substrate; the remaining paths are the
open-items list in the doc above.

**Decision (2026-07-16)** (full rationale in
[general/existing-fingerprint-datasets.md](general/existing-fingerprint-datasets.md),
"Decision" section): comparing the two approaches explored so far, the **curated
per-component reference-DB approach is the backbone**, because the bar is attribution
and OSSKB's attribution gap is structural (unfixable on free data at any effort
level), while the curated approach's coverage gap closes linearly over a small,
stable embedded-C component universe. OSSKB's offline tables remain a *subordinate*
recall/routing net (recall is commodity; the `count` field routes; "known OSS, not a
supported component" findings feed the roadmap), the hosted API at most a freshness
fallback. The queued `minr` investigation is the industrialization of curation
(attribution-by-construction), where the two approaches converge. Flip condition:
revisit only if scope becomes arbitrary/unbounded codebases (audit tooling) instead
of a standard scanner for known embedded projects.

## SBOM output format

Both **CycloneDX** and **SPDX** are eventual targets, but format design is out of scope
for this repo — the generator (and its format handling) lives elsewhere. Don't spend
research effort on output *serialization* here.

Note the boundary against the 2026-07-22 scope widening: capturing *architectural*
recommendations for the generator's **detection/identification core** (evidence
producers, resolver, attribution, provenance, tier selection) is now in scope
([general/sbom-generator-architecture.md](general/sbom-generator-architecture.md)) —
but the *serialization format* is still not. Architecture of how identity is decided:
in scope. How it's written to CycloneDX/SPDX bytes: out of scope.

## Repository layout

The repo is organized **component-first**, not by artifact type:

- `general/README.md` — cross-cutting principles that apply across components (SBOM
  identifier/naming strategy, detection technique patterns, multi-component attribution
  rules). When a finding while researching one component turns out to be generally
  applicable, extract it here and have the component doc link back to it instead of
  restating it.
- `components/<name>/` — one folder per researched component (e.g.
  `components/freertos/`). Each contains:
  - `README.md` — the findings doc for that component. Keep it as a single doc per
    component rather than splitting into many small files.
  - `experiments/` — small prototype scripts (Python or C) testing a detection idea
    against that component specifically, e.g. running fuzzy hashing against a modified
    vendored copy. Throwaway/exploratory, not production code. Only create this
    subfolder once there's an actual experiment to put in it.
  - `corpus/` — curated real-world (or realistic) example source with **known ground
    truth** of what was vendored in, used to validate detection techniques against that
    component. Only create this subfolder once there's an actual example to put in it.

Don't create empty `experiments/`/`corpus/` subfolders as scaffolding — add them when
there's real content.

## Working conventions

- This repo has no build system and no CI — it's notes and small scripts.
- Prefer Markdown docs that state findings and tradeoffs plainly over long narrative
  writeups.
- When adding a prototype experiment, briefly note in its README what question it was
  trying to answer and what the result was, so it doesn't become an unexplained script.
- When citing external tools/projects, name them explicitly (e.g. "ScanOSS", "TLSH",
  "ssdeep") rather than vague references — this repo is meant to be a durable reference.
- **JSON files checked into this repo must be pretty-printed** (indented, one field
  per line), never single-line blobs — they're read by humans browsing findings, not
  just by scripts. When a tool emits compact JSON (e.g. `scanoss` scan output), pipe
  it through `jq .` / `python -m json.tool` before saving.
