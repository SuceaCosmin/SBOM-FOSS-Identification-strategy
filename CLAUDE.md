# Purpose of this repository

This is a **research-only** repository. There is no product code to ship from here.
The goal is to research techniques for identifying known C open-source (FOSS) components
that have been integrated into embedded projects via **copy-paste / vendoring**, i.e.
*without* a package manager (no Conan, no vcpkg, no CMake FetchContent tracking, no git
submodules with clean provenance). The findings from this repo will later inform an SBOM
generator built in a **separate** repository — do not implement a generator here, only
the detection research and prototypes that will inform it.

When you (Claude) start a session in this repo, treat the scope below as settled context
established with the user (Cosmin) — don't re-ask these questions, but do flag if new
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
- **Researched (Phase 1 only)**: [CMSIS](components/cmsis/README.md) — distro-landscape
  pass complete; version-fingerprint experiment not yet built. Confirmed the most
  fragmented component researched so far: sub-components (Core, DSP, NN, RTOS2/RTX,
  Driver, DAP, View, Zone, Stream, Compiler) are independently versioned/repo'd, with a
  further umbrella "pack version" layer bundling snapshots of them and an in-source
  `cmsis_version.h` macro tracking Core specifically — three distinct, simultaneously
  meaningful version numbers. Also found that vendor "CMSIS/Device/<vendor>" trees (e.g.
  STMicroelectronics's `cmsis-device-f4`) are 100% vendor-authored/copyrighted despite
  living in a path and file headers that say "CMSIS" — confirmed by diffing real
  STM32CubeF4 files against upstream Arm CMSIS_5 (Core files byte-identical; device
  headers wholly ST's own). NVD has a CPE only for `cmsis-rtos` (type `o`, matching the
  general RTOS-classification gotcha); no CPE for Core/DSP/NN/Driver/the overall pack.
- **Next up**: CMSIS Phase 2 (version-fingerprint experiment) — track `cmsis_version.h`
  plus 2-3 `core_cm*.h` variants from CMSIS-Core, build the reference DB from the
  `CMSIS_5`/`CMSIS_6` tag history (mind the archived-repo split), and get a second real
  vendor diff (NXP) beyond the one ST data point gathered in Phase 1. Extending the
  mbedTLS experiment to cover the 4.0/TF-PSA-Crypto split remains a separately deferred
  option too.

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

1. **File/hash-based matching** — normalized-content hashing against known OSS file
   versions (ScanCode/ORT-style).
2. **Fingerprint/similarity matching** — token or AST-level fingerprints (winnowing,
   MinHash, fuzzy hashing) to catch modified copies. This is the highest-priority
   technique given the "locally modified" focus above.
3. **Metadata/string heuristics** — license headers, version macros, distinctive
   `#define`s, author comments, embedded identifiers.
4. Binary/firmware artifact analysis is out of scope for now — source-level only.

## Reference corpus question (open)

Whether to build a curated reference database of known C OSS components from scratch,
or lean on existing external sources (ScanCode LicenseDB, ClearlyDefined, OSS Index,
FOSSology, etc.), is an **open question this research should explore**, not a decision
already made. Document tradeoffs as you find them.

## SBOM output format

Both **CycloneDX** and **SPDX** are eventual targets, but format design is out of scope
for this repo — the generator (and its format handling) lives elsewhere. Don't spend
research effort on output serialization here.

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
