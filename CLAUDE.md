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
- **Researched (cross-cutting): advisory-source fitness tests** (OSV.dev,
  NVD/CPE, GHSA) — open item 2, **RUN 2026-07-22**, findings in
  [general/experiments/advisory-fitness](general/experiments/advisory-fitness/README.md);
  the full menu of sources still to test is catalogued in the new
  [general/advisory-source-roadmap.md](general/advisory-source-roadmap.md).
  **Headline: NVD/CPE is the primary fit source; GHSA is fit only via its
  per-repository advisory feed (per-component); OSV is not.**
  **NVD/CPE** gives real version-range discrimination — mbedTLS
  (`cpe:2.3:a:arm:mbed_tls`) @2.28.0 → 23 CVEs, @3.6.2 → 11, older @2.22.0 → 37,
  and an *impossible* @99.0.0 → **0** — so the generator's primary vuln-lookup
  mapping is **canonical identity → CPE 2.3**; its misses are all mapping-layer
  (FreeRTOS CVEs exist but are AWS-distribution-versioned so our kernel semver
  10.4.3 matches none; CMSIS has a CPE only for `cmsis-rtos`). **OSV.dev is not
  directly fit for embedded C**, three ways: (a) the GitHub-flavored purls we
  declare return **0** (OSV indexes `pkg:pypi/`/`pkg:deb/`, not `pkg:github/`; a
  `pkg:pypi/django` control returned 21, proving the technique) — **identity and
  vuln-lookup coordinate are different keys**; (b) bare-`name` matching is
  **version-inert** (mbedTLS @2.28.0/@3.6.2/impossible-@99.0.0 all → the same 83
  CVEs), so a naive `name+version → OSV` reports identical CVEs for every
  version; (c) FreeRTOS/CMSIS absent entirely. OSV's only upstream-accurate
  offering — raw CVE records with **GIT-commit ranges** — is usable *by us*
  because the reference DBs already mine per-release git tags (tag→commit is
  free). **GHSA has two access paths with opposite verdicts** (corrected 2026-07-23;
  the original run tested only the first): its *global* `/advisories` feed is
  unfit — no C/C++ ecosystem, `affects=mbedtls`/`affects=freertos` → 0, embedded-C
  CVEs only as unreviewed mirrors with empty ecosystem — **but** the
  *per-repository* `/repos/{owner}/{repo}/security-advisories` feed carries real,
  version-ranged advisories for maintainers who self-publish: FreeRTOS-Kernel's
  CVE-2024-28115 → range `<=10.6.1` in **kernel semver** (better than NVD's
  AWS-distribution versioning for FreeRTOS, and only reachable via the repo endpoint —
  the global feed returns 0 for it even by `cve_id`), while `Mbed-TLS/mbedtls` → 0 (it
  self-publishes elsewhere). So GHSA is a **per-component opt-in source** keyed off the
  canonical identity's `{owner}/{repo}`, not a flat miss. Net: a mapping layer from
  canonical identity to each source's coordinate is mandatory (empty ≠ "no vulns" —
  must mean "not covered"), captured as recommendation 11 in
  [general/sbom-generator-architecture.md](general/sbom-generator-architecture.md).
  Reusable probe harnesses: `osv_probe.py`, `nvd_probe.py`, `ghsa_probe.py`.
  Runner-up alternatives if breadth is preferred:
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
- **FreeRTOS re-review done (2026-07-23), with a prioritized next-step list.** Prompted
  by two correct user observations, the FreeRTOS work was revisited: (a) the
  version-fingerprint reference DB was widened **3 → all 7 core kernel `.c` files**
  (added `timers`/`event_groups`/`stream_buffer`/`croutine`) with an **anchor-quorum**
  matcher design (tasks/queue/list confirm presence; other present core files tighten
  the version intersection), rebuilt and re-validated with no corpus regression; (b) the
  **GHSA advisory-fitness finding was corrected** — GHSA's *global* feed is unfit as
  before, but its **per-repository** feed (`/repos/{owner}/{repo}/security-advisories`)
  carries real version-ranged advisories for self-publishing maintainers:
  FreeRTOS-Kernel's CVE-2024-28115 → `<=10.6.1` **in kernel semver** (better than NVD's
  AWS-distribution versioning for FreeRTOS; mbedTLS self-publishes elsewhere → 0). All
  three reference DBs (FreeRTOS/mbedTLS/CMSIS) were also converted from one-line blobs to
  **pretty-printed JSON** (leaf-array-inline `pretty_json()` in each `build_reference_db.py`),
  and a repo-wide **"fingerprints are POC-scoped, not consolidated"** caveat was added to
  [general/README.md](general/README.md#maturity-caveat-the-fingerprints-here-are-poc-scoped-not-consolidated).
  **Prioritized next steps (documented 2026-07-23):** steps 1 and 2 are **DONE
  2026-07-28** (see the two bullets below); only step 3 remains.
  1. ~~**Close the vuln loop for FreeRTOS**~~ — **DONE 2026-07-28**, see below.
  2. ~~**Consolidate FreeRTOS's port/`mpu_wrappers` layer**~~ — **DONE 2026-07-28**, see
     below. Original framing:
     CVE-2024-28115 actually lives, so it's what lets a detection point at that CVE's
     file. Needs a reference set indexed by `(tag, arch, compiler)` and new corpus —
     the natural pairing with step 1, and would make FreeRTOS the first fully-
     consolidated (POC→production) component. Also owed: the 21 `include/` headers and
     empirically-tuned winnowing thresholds. **Now the next-up item, and reinforced by
     step 1's result**: the end-to-end verdict pins CVE-2024-28115 by version but
     *over-claims*, because that CVE applies only to ARMv7-M/ARMv8-M **MPU ports** — a
     condition stated in prose only, in every advisory source tested. Port-layer
     detection is what makes the verdict precise.
  3. ~~**Lower priority:** a new component (lwIP or FatFs) via the `research-component`
     skill for breadth~~ — **lwIP DONE 2026-07-29** (see the lwIP bullet below). Still
     open: **FatFs** as the adversarial no-git-upstream case (now better motivated — the
     lwIP pass showed git tags can disagree with released artifacts even when a git
     upstream *does* exist); or apply the POC-consolidation lens to mbedTLS/CMSIS (same
     minimal-scope shape, no fresh finding pushing them).
- **Vuln loop CLOSED for FreeRTOS (2026-07-28)** — step 1 of the re-review's next-step
  list, the repo's **first end-to-end SBOM→vuln result**: vendored source tree →
  fingerprint detection → GHSA per-repo advisory range → CVE verdict. Two new scripts in
  [general/experiments/advisory-fitness](general/experiments/advisory-fitness/README.md)
  ("Closing the loop" section): `ghsa_vuln_lookup.py` (canonical identity →
  `{owner}/{repo}` → cached advisory feed → range parse → membership → verdict; feed
  cached in `ghsa_repo_advisories.json`, `--refresh` to re-fetch) and
  `end_to_end_freertos.py` (chains the two halves over the corpus). `match_target.py`
  gained a print-free `resolve_group()`/`scan_tree()` API for this (CLI output unchanged,
  re-verified on all three corpus trees). **All three ground truths resolve correctly**:
  NXP verbatim V11.2.0 → NOT_AFFECTED; esp-idf fork (PARTIALLY_MODIFIED → V10.5.1/V10.6.0)
  → AFFECTED by CVE-2024-28115; mixed synthetic → AFFECTED. Five findings, all about the
  *interface* between detection and advisories, not the sources: (1) a version **set**
  means either **candidates** (one of these — partly-affected ⇒ POSSIBLY_AFFECTED, tighten
  detection) or **coexisting** (MIXED — the vulnerable file really is present ⇒ AFFECTED);
  conflating them turns "unknown" into a false yes/no (now architecture rec. 8's
  window-semantics clause); (2) **version membership is necessary, not sufficient** —
  CVE-2024-28115 applies only to ARMv7-M/ARMv8-M MPU ports, a condition in *prose only*
  in every source tested (now architecture rec. 12; the direct argument for next step 2);
  (3) GHSA's documented `vulnerable_version_range` grammar **isn't reliably honored** —
  of three FreeRTOS-org advisories only one is well-formed; the others are an enumeration
  (`202212.01, 202112.00`, unsatisfiable if ANDed as documented) and a bare version, so
  the parser classifies conjunction/enumeration/exact/unparseable rather than
  mis-evaluating; (4) the upstream **tag zoo** needs classification, not forcing —
  `-kernel-only` is packaging, `-LTS-Patch-N` is a maintenance branch a mainline range
  can't express (flagged), `V202110.00-SMP` is date-scheme ⇒ **UNDETERMINED**, `rcN`
  sorts before its release; (5) **"not covered" is a first-class result** — mbedTLS →
  NOT_COVERED *with the right alternative* (NVD/CPE), unresolved version → NOT_QUERYABLE
  ("a detection gap, not a clean bill of health"). `COMPONENT_MAP` there is the miniature
  of the paused mapping layer's sub-tasks 1 and 4 for this one source.
  **Made repeatable (2026-07-28)**: advisory-source mapping is now **phase 3 of the
  `research-component` skill** — every component researched from here on gets one, not
  just FreeRTOS. The skill carries the steps (identity → per-source coordinate,
  impossible-version control, version-scheme comparison, coverage-with-reasons, one
  loop-closing run over the corpus, write up interface findings not CVE counts), plus a
  new `templates/end_to_end.py.template`; `templates/match_target.py.template` gained the
  note to split the matcher into a print-free `resolve_*`/`scan_tree` API first.
  `ghsa_vuln_lookup.py` is component-generic — a new component is one `COMPONENT_MAP` entry.
- **FreeRTOS port layer DONE (2026-07-28)** — step 2 of the re-review list, and the
  answer to the loop-closing spike's over-claim problem. New experiment
  [components/freertos/experiments/port-layer](components/freertos/experiments/port-layer/README.md):
  a second, independent detector answering *which port* (the core-file DB answers *which
  release*), with its own **(port, tag)-indexed** reference DB — 62 tags × 176 port
  directories, 6.6 MB, two tiers (44 MPU-relevant ports fingerprinted fully; 132 others on
  `port.c`/`portmacro.h` only, enough to identify them and rule the CVE out). **MPU is a
  three-valued classification**: `always` (5 dedicated `*_MPU` ports), `optional` (39
  ARMv8-M ports where `configENABLE_MPU` decides at build time — so the tree's
  `FreeRTOSConfig.h` is read as evidence, reported with its path), `none` (132).
  **Identification is by content, never path** — ESP-IDF's ports live at
  `portable/xtensa/`, a path that exists nowhere upstream. `end_to_end_freertos.py` now
  prints **both** verdicts, version-only and port-refined, and the refinement changes real
  answers: **esp-idf-fork AFFECTED → NOT_AFFECTED** (Xtensa port, not an ARM MPU port — a
  false positive removed on evidence, on a real vendor fork), a new
  `armv8m-config-synthetic` corpus entry (coherent V10.5.1 tree) **AFFECTED →
  NOT_AFFECTED** on `configENABLE_MPU 0` and back to AFFECTED when flipped to 1, and
  `mixed-version-synthetic` **AFFECTED → POSSIBLY_AFFECTED** (no port files ⇒ undecidable).
  NXP's `ARM_CM4_MPU` port independently resolves to V11.2.0, cross-checking the core-file
  result. Three safety rules (now in architecture rec. 12): the refinement **only narrows**;
  **absent evidence suspends, never clears**; the applicability condition is **curated
  advisory metadata with its source quote**, not inferred. Also: unidentified ports get a
  **negative-evidence** rule (no MPU-capable port above the 0.30 floor *and* no MPU wrapper
  files ⇒ NOT_SUPPORTED), calibrated against this repo's own data — the modified ESP-IDF
  `tasks.c` still scored 0.56 against upstream, so ~0.0 means different code, not modified
  code. Measured cost of the granularity: **~4× the core-file DB** (6.6 MB vs 1.7 MB).
  Pitfall recorded: a **blobless clone is the wrong tool** for bulk mining (lazy per-blob
  fetches hang `cat-file --batch`); full clone is ~150 MB / ~25 s.
- **Researched: [lwIP](components/lwip/README.md) — all three skill phases, 2026-07-29.**
  The fourth component, picked as roadmap Tier 1 #1 for the port-layer-vs-core question.
  **Phase 1** verified four real vendor forks by diff against the matching upstream tag,
  and found four *different* shapes: **ST** `stm32-mw-lwip` is byte-identical to upstream
  2.1.3 (2.2.0 differs only by 4 doxygen comment lines) and adds its port layer under
  `system/` — a path that exists nowhere upstream; **Espressif** patches 54 files
  (+3446/−257, incl. a whole NAPT feature) and flips `LWIP_VERSION_RC` to
  `LWIP_RC_DEVELOPMENT`; **NXP** patches 102 files and superimposes `MCUX_*` SDK tags on
  the upstream tag set; **AMD/Xilinx** declares the version in the directory path
  (`lwip220/src/lwip-2.2.0/`) while 7 of 20 core `.c` files differ from it. Also:
  **lwIP is itself a vendoring carrier** — `src/netif/ppp/` is a reduced fork of pppd
  2.4.5 and `src/netif/ppp/polarssl/` is a reduced copy of **PolarSSL 0.10.1-bsd** (the
  direct ancestor of the Mbed TLS already researched), both documented in-tree by
  upstream; canonical VCS is Savannah with GitHub as an official *mirror*, releases are
  zips (no amalgamation); ST's tree carries **two contradictory license statements** (root
  `LICENSE.md` BSD-3-Clause vs. `st_readme.txt`'s own header, an ST five-clause license
  with a "STMicroelectronics devices only" field-of-use restriction), while ST-authored
  port files carry *upstream's* SICS copyright and no ST copyright at all.
  **Phase 2** ([experiments/version-fingerprint](components/lwip/experiments/version-fingerprint/README.md)):
  7 tracked files chosen by *measured* per-file discrimination across releases (plus
  `pbuf.c` for being untouched by all four forks — the prediction held; it pins the base
  in two of three modified-fork cases), 17 release tags → 792 KiB DB, validated on 8
  corpus trees with every ground truth correct (2 CONFIRMED verbatim, 3
  PARTIALLY_MODIFIED real forks, 1 MIXED, 1 negative control at 0.000, 1 release-zip).
  Two generalizable findings: **git tags are not release artifacts** — lwIP's
  `STABLE-2_0_2_RELEASE` is a **phantom** whose `init.h` still declares 2.0.1, while the
  shipped `lwip-2.0.2.zip` matches only `STABLE-2_0_2_RELEASE_VER`, and cross-file
  intersection eliminates the phantom *for free*; and **locate tracked files by path
  suffix, not basename** — ST ships `system/arch/init.h` next to `lwip/init.h`, scoring
  0.000, so basename keying would report NOT_THIS_COMPONENT for a verbatim 2.1.3 tree.
  **Phase 3** (in [general/experiments/advisory-fitness](general/experiments/advisory-fitness/README.md)):
  the repo's **second end-to-end loop, closed through NVD/CPE** this time (FreeRTOS's went
  through GHSA), requiring a new reusable **`nvd_vuln_lookup.py`** + `end_to_end_lwip.py`;
  all 8 corpus trees produce the expected verdict (1.4.1 → AFFECTED by CVE-2014-4883 via
  range `<=1.4.1`; the mixed tree → AFFECTED by CVE-2020-22284 under *coexisting*
  semantics; modern trees NOT_AFFECTED; negative control NOT_QUERYABLE). Headline finding:
  **advisories for a vendored component are often filed against the carrier** — of 6 NVD
  CVEs describing lwIP flaws, 3 are bound to `lwip_project:lwip`, one to
  `microchip:advanced_software_framework`, one to `espressif:esp-idf`, one to no CPE at
  all — so **identity → CPE is one-to-many** (now architecture rec. 11's carrier clause);
  plus a CPE bound to the literal version `-` that no version can match (→ UNDETERMINED,
  never "not affected"), a CPE dictionary that stops at 2.1.2, and the nested pppd's CVE
  reachable only via a nested identity. **Port-layer detector judged unnecessary for
  lwIP** on this evidence: no advisory is scoped to a port or `lwipopts.h` macro — the
  applicability axis is *which distribution*, so carrier/fork identification is the
  granularity worth sharpening here.
- **Researched (cross-cutting): nested-component attribution — DONE 2026-07-29**,
  [general/experiments/nested-component-attribution](general/experiments/nested-component-attribution/README.md).
  The lwIP pass produced the repo's first real nested case (lwIP vendors a reduced
  **PolarSSL 0.10.1-bsd** and **pppd 2.4.5** inside itself), so the long-asserted
  "vendored integrations are multiple stacked components" rule was finally *tested*
  rather than assumed. **It failed, confidently**: the curated KB export scanned against a
  309-file lwIP 2.2.1 tree containing zero Mbed TLS reported **`CONSISTENT` →
  `pkg:github/mbed-tls/mbedtls` 2.28.8–2.28.10, Apache-2.0** — wrong component, wrong era
  by 15 years, wrong license (the files are BSD-3-Clause PolarSSL lineage). Four findings:
  (1) **no minimum-evidence rule** — the tree verdict intersects only the files that
  *matched* and discards 308 `NO MATCH` files as no evidence, so one file's snippet match
  becomes a whole-tree component claim (a snippet finding and a component finding must not
  share a verdict vocabulary; negative evidence must count); (2) **the single match is
  constant tables, not code** — lwIP's `des.c` scores **0.794** against Mbed TLS on hex
  constants alone but **0.071** on the code with constants stripped, because DES's S-boxes
  are fixed by FIPS 46 and identical in every implementation; recorded as a mandatory
  caveat on the roadmap's planned constant/data-table tier (standard algorithm tables
  identify an *algorithm*, never a project or version); (3) **correct attribution was
  unreachable anyway** — PolarSSL 0.10.1 (2009) predates the upstream git history
  (earliest tag `mbedtls-1.3.10`) and exists only as a tarball, so a tag-mined KB is
  structurally unable to name it and needs an expressible "known-OSS content, origin
  outside coverage" verdict; (4) the **bespoke** per-component matchers are blind to this
  by construction (they track 5 version-discriminating files, no crypto primitives) — the
  false positive is a property of the broad KB, not of fingerprinting. Fed into
  architecture rec. 7 (evidence threshold clause),
  [general/README.md](general/README.md#attribution-vendored-integrations-are-often-multiple-stacked-components),
  the fingerprint roadmap's TODO-9, and a defect note in the minr-self-mining README.
- **Backlog / next-up — PAUSED 2026-07-23 (was designated 2026-07-22): the full
  vuln-source mapping layer** — explicitly deprioritized by the user on 2026-07-23 in
  favor of the FreeRTOS re-review above; resume later. Note step 1 above is a narrow,
  already-fit slice of this — the rest (CPE mapping, OSV GIT-range resolver) stays
  paused. It remains
  the concrete follow-up the advisory-fitness tests exposed, and the last piece
  between the pipeline's validated purl+version output and actual vuln scanning.
  The tests proved the SBOM identity is *not* the vuln-lookup key: the mapping
  is what's missing. Scoped sub-tasks (all research/prototype, not generator
  build): (1) a **canonical identity → CPE 2.3** map (`pkg:github/mbed-tls/
  mbedtls` → `cpe:2.3:a:arm:mbed_tls`), the confirmed primary path — validate the
  detected version against NVD CPE ranges end-to-end for the corpus ground
  truths; (2) **FreeRTOS version-scheme reconciliation** — the NVD CVEs are keyed
  to AWS-distribution / FreeRTOS+TCP versioning, so the detected kernel semver
  (10.4.3) matches none; work out the kernel-semver → CPE-version mapping (the
  FreeRTOS instance of the component-granularity question); (3) a **tag→commit
  resolver over OSV's GIT-range CVE records** — resolve a detected version to its
  release commit (the reference DBs already mine per-release tags) and test
  membership in each CVE's introduced..fixed GIT range, unlocking OSV's only
  upstream-accurate feed; (4) **per-component coverage metadata** so an empty
  result reads as "not covered," never "no known vulns" — *done for the GHSA repo
  source 2026-07-28 (`COMPONENT_MAP`); still owed for NVD/OSV*. Grounded in
  [general/experiments/advisory-fitness](general/experiments/advisory-fitness/README.md)
  and architecture recommendation 11
  ([general/sbom-generator-architecture.md](general/sbom-generator-architecture.md));
  the untested advisory sources (vendor/upstream advisories, CVE.org/cvelistV5,
  EUVD, CISA KEV) are catalogued with priorities in
  [general/advisory-source-roadmap.md](general/advisory-source-roadmap.md).
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

## Vulnerability handling — where this repo's (and the generator's) job ends

**Settled 2026-07-28.** The generator's job is to identify components and emit the
**right identifiers** — canonical purl, version window, and each advisory source's own
lookup coordinate (CPE 2.3, `{owner}/{repo}`, release commit) with per-component coverage
metadata — so that *dedicated* vulnerability tools can do their job unaided. It is **not**
the generator's job to decide whether a reported CVE actually impacts a project: no
exploitability scoring, no reachability analysis, no CVE dispositions. That is
vulnerability **triage**, a project-evaluation activity whose standard output is a **VEX**
statement authored by the SBOM's consumer.

Two consequences for research here:

- **Vuln work in this repo is a fitness check, not a feature.** Experiments answer "do our
  identifiers drive the standard tools correctly?" and stop at verdict + coverage — see
  [general/experiments/advisory-fitness](general/experiments/advisory-fitness/README.md)
  and phase 3 of the `research-component` skill. Don't build triage/reachability tooling.
- **But identity must be granular enough to be useful.** "Emit identity and stop" holds
  only at the granularity advisories actually key on: CVE-2024-28115 applies to FreeRTOS's
  ARMv7-M/ARMv8-M *MPU port*, not to "FreeRTOS-Kernel" wholesale. When an applicability
  condition shows up, the correct response is **sharpen detection** (identify the port,
  sub-component, or build-inclusion fact), never build an impact analyzer. Full rationale:
  [general/sbom-generator-architecture.md](general/sbom-generator-architecture.md) rec. 13.

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
