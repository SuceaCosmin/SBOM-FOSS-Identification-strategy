# CMSIS

First research pass, following the same shape as the FreeRTOS and Mbed TLS passes:
governance/licensing history and distro landscape before attempting a detection
experiment. CMSIS turned out to be the most fragmented component researched so far in
this repo — an umbrella brand over more than a dozen independently-versioned repos, plus
a *pack version* numbering layer on top of that, plus per-vendor device-specific packs
that structurally live inside "CMSIS" directories but are not CMSIS at all. Section 2
covers this in detail since it's the central finding of this pass.

General principles extracted from this research live in
[general/README.md](../../general/README.md) rather than being restated here — this doc
covers what's specific to CMSIS itself.

## 1. Governance and licensing history

- **CMSIS** (**Common** Microcontroller Software Interface Standard, per the current
  [arm.com](https://www.arm.com/technologies/cmsis) and
  [CMSIS_6 docs](https://arm-software.github.io/CMSIS_6/latest/General/index.html))
  originated as an Arm specification/reference-implementation project, distributed for
  years only via the Keil pack system (`www.keil.com/pack`), not Git. **The acronym
  expansion itself changed over time**: the archived `ARM-software/CMSIS_4` README
  (confirmed by fetching it directly) spells it out as "**Cortex** Microcontroller
  Software Interface Standard" — Arm re-expanded "Cortex" to "Common" sometime between
  the v4 era and today, on a stable acronym/identifier. Not two different components
  sharing an acronym, just one project's own branding drifting under a fixed name — worth
  noting since a detector or doc that hardcodes one expansion could flag a mismatch
  against a source using the other.
- **CMSIS Version 4** and earlier: per the `ARM-software/CMSIS_4` repo's own README, "the
  CMSIS components (CORE, RTOS, DSP, Driver) ... are today licensed under BSD or zlib
  license," governed by a separate End User License Agreement PDF. `CMSIS_4` is a
  read-only mirror (release images from v4.3.0 on) — the repo itself is archived
  (last push 2018-10-18) and its README explicitly redirects issues/contributions to
  CMSIS_5.
- **CMSIS Version 5** (development moved to GitHub, `ARM-software/CMSIS_5`, created
  2016-02-18): Arm re-licensed the whole thing to **Apache-2.0** specifically *to accept
  external contributions* — confirmed directly in the CMSIS_4 README's own words ("To
  accept contributions to the source we did also change the license to Apache 2.0").
  This is a clean, single license-family change (BSD/zlib → Apache-2.0), not a dual-license
  situation like Mbed TLS, so there's no comment-stripped-matching blind spot to flag here
  the way there was for Mbed TLS/ST. CMSIS_5 is itself now archived (last push
  2024-09-03) — superseded by CMSIS_6.
- **CMSIS-DSP and CMSIS-NN split into their own repos in June 2022** (both created
  2022-06-01), each starting independent semver version lines, *before* the "CMSIS v6"
  rebrand — the modular split predates the version-6 marketing name.
- **CMSIS Version 6** (`ARM-software/CMSIS_6`, created 2023-03-08, active/unarchived):
  the current meta-repo. Its own README states plainly: "CMSIS v6 splits the monolithic
  CMSIS 5 repository into a set of modular, independently versioned sub-repositories."
  `CMSIS_6/ARM.CMSIS.pdsc` still uses Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`
  confirmed in the fetched `LICENSE` file).
- **CMSIS-Pack (the pack-format/tooling spec itself) has moved governance** to a
  dedicated **Open-CMSIS-Pack** GitHub org/consortium — the `ARM.CMSIS.pdsc` release
  notes literally say `CMSIS-Pack: deprecated (moved to Open-CMSIS-Pack)` as of pack
  version 5.9.0 (2022-05-02). This mirrors the Mbed TLS → TrustedFirmware.org governance
  shift pattern (see mbedtls README) — a brand's packaging/tooling layer spun out to
  neutral, multi-vendor governance while the core library repos stayed under the
  original org (`ARM-software`).

## 2. Component granularity: CMSIS is fragmented at three nested levels, not one

This is the central finding of this pass, and it's a sharper version of the granularity
trap already flagged for FreeRTOS (kernel vs. libraries) and Mbed TLS (4.0/TF-PSA-Crypto
split — see [general/README.md](../../general/README.md#component-granularity)). CMSIS
has **three separate, simultaneously-meaningful version numbers** for what looks like
"one" piece of vendored software:

1. **Individual component repos**, each with its own independent version line, confirmed
   directly via GitHub tags (fetched this session):
   - `ARM-software/CMSIS_6` — meta-repo (Core, Driver *API headers*, RTOS2 *API headers*,
     CoreValidation). Tags: `v6.3.0`, `v6.2.0`, `v6.1.0`, `v6.0.0` — its own v6.x line.
   - `ARM-software/CMSIS-DSP` — tags `v1.17.0`, `v1.16.2`, ... — a v1.x line, *unrelated*
     numerically to CMSIS_6's v6.x.
   - `ARM-software/CMSIS-NN` — tags `v7.0.0`, `v6.0.0`, `v5.0.0`, `v4.1.0`, `v4.0.0`, then
     older `24.02`, `23.08`, `23.02` — note the **tag-scheme change**: CMSIS-NN used
     date-based tags (`YY.MM`) before switching to semver at `v4.0.0`. A phase-2
     fingerprint tag-filter regex for this component needs to handle both schemes, or
     deliberately scope to one era (see FreeRTOS/mbedTLS "Known pitfalls" precedent about
     tag-naming inconsistency across a repo's history).
   - `ARM-software/CMSIS-RTX` (RTX5 kernel, the CMSIS-RTOS2 native implementation),
     `ARM-software/CMSIS-Driver` (generic driver implementations/templates),
     `ARM-software/CMSIS-DAP` (debug probe protocol), `ARM-software/CMSIS-View`,
     `ARM-software/CMSIS-Zone`, `ARM-software/CMSIS-Stream`, `ARM-software/CMSIS-Compiler`,
     `ARM-software/CMSIS-FreeRTOS` (FreeRTOS's CMSIS-RTOS2 API adapter) — each its own
     repo, each independently versioned and released. `ARM-software/CMSIS-TFM` and
     `ARM-software/CMSIS-Musca-S1` exist as further downstream pack repos for specific
     platforms/TF-M integration.
2. **The overall "ARM::CMSIS" software-pack version** (`ARM.CMSIS.pdsc`'s `<releases>`
   list) — a bundle/manifest version (e.g. `5.9.0`, `5.8.0`) that is itself a distinct
   number from any individual component's version, and whose release notes exist
   specifically to translate one number into the real per-component versions it bundles.
   Directly quoting the fetched pdsc for pack version `5.9.0` (2022-05-02):
   ```
   CMSIS-Core(M): 5.6.0
   CMSIS-DSP: 1.10.0
   CMSIS-NN: 3.1.0
   CMSIS-RTOS2: 2.1.3 (unchanged) - RTX 5.5.4
   CMSIS-Pack: deprecated (moved to Open-CMSIS-Pack)
   CMSIS-SVD: 1.3.9
   CMSIS-DAP: 2.1.1
   ```
   This is effectively a **distro-release model** (à la a Linux distro release bundling
   independently-versioned packages) applied to what looks, from a vendored-copy's
   perspective, like "one" CMSIS. A detector that only recognizes the pack version number
   (if it appears anywhere, e.g. in a `.pdsc` file bundled by a vendor) still cannot infer
   individual component versions from it without this same translation table, and the
   table only exists for versions Arm chose to publish notes for.
3. **`cmsis_version.h`'s internal `__CM_CMSIS_VERSION_MAIN`/`_SUB` macros** track
   **CMSIS-Core(M) specifically** — confirmed directly: STM32CubeF4's shipped
   `cmsis_version.h` reads `V5.0.5` / `__CM_CMSIS_VERSION_SUB (6U)`, which matches
   `ARM-software/CMSIS_5` tag `5.9.0`'s copy exactly (byte-for-byte, see section 3) but is
   numerically unrelated to the `5.9.0` pack version string itself (Core's own sub-version
   was `5.6.0` in that same pack release, per the pdsc quote above — yet another number).

**Practical implication**: "found something that says CMSIS vX.Y" is not sufficient to
identify which of Core, DSP, NN, RTOS2, Driver, etc. is present, nor their individual
versions, nor whether they even came from the same pack release — a detector needs to
identify *which sub-component's own version macro/tag* it's looking at before treating
any single "CMSIS X.Y" string as an answer.

### The device-specific layer is not CMSIS at all, despite living in a folder named "CMSIS"

Confirmed by fetching and diffing real files (this session): every MCU vendor's
"CMSIS/Device" tree (e.g. STMicroelectronics's `cmsis-device-f4` — formerly
`cmsis_device_f4`, renamed on GitHub — vendored into `STM32CubeF4` as a git submodule at
`Drivers/CMSIS/Device/ST/STM32F4xx`) contains **vendor-authored, vendor-copyrighted**
register-definition headers and startup/system files (`stm32f407xx.h`,
`system_stm32f4xx.c`), instantiating the *contract* CMSIS-Core defines (see
`CMSIS_6/CMSIS/Core/Template/Device_M`'s `Config`/`Include`/`Source` template layout) but
containing **zero Arm-owned code**. `stm32f407xx.h`'s header reads `Copyright (c) 2017
STMicroelectronics. All rights reserved` — not Arm. `cmsis-device-f4` is its own
independently-versioned repo (`v2.6.11`, `v2.6.10`, ...), separate from both
`ARM-software/CMSIS_6`'s versioning and from ST's own HAL driver repo
(`stm32f4xx_hal_driver`) versioning — a **fourth** version number in the stack for a
single STM32Cube checkout, on top of the three in the prior subsection, if you count the
overall `STM32CubeF4` firmware-package release tag that pins all of these submodules
together.

**This is a sharper case of the general "vendored integrations are often multiple stacked
components" principle** (see
[general/README.md](../../general/README.md#attribution-vendored-integrations-are-often-multiple-stacked-components)):
here the trap isn't just "there's a vendor layer on top of upstream" — it's that the
vendor layer sits *inside a directory path and file-header comment that literally says
"CMSIS"* (`@brief CMSIS STM32F407xx Device Peripheral Access Layer Header File`), making
it easy for a naive path- or keyword-based detector to misattribute ST's own copyrighted
register headers to the Arm CMSIS component. The genuinely Arm-authored files
(`core_cm4.h`, `cmsis_gcc.h`, etc.) live in a *sibling* `CMSIS/Include` directory in the
same checkout and must be distinguished from the `CMSIS/Device/<Vendor>/...` tree next to
them.

## 3. What layers typically stack on top

Unlike Mbed TLS's `_ALT` hardware-acceleration pattern (an in-place patch to an otherwise
upstream file), CMSIS-Core's vendor layer is architecturally different: the **generic
Arm-authored files are vendored verbatim, unmodified**, and the **vendor-specific layer
is a wholly separate, vendor-authored file set** instantiating an Arm-defined template
contract, not a patched copy of an Arm file. Confirmed directly this session:

- **STMicroelectronics** (`STM32CubeF4`, submodule `Drivers/CMSIS/Include` mirroring
  upstream Arm CMSIS-Core `Include/`): diffed `core_cm4.h` and `cmsis_version.h` against
  `ARM-software/CMSIS_5` tag `5.9.0` — **byte-identical**, both files, including the
  version macros (`V5.0.5`, `__CM_CMSIS_VERSION_SUB (6U)`, `Copyright (c) 2009-2022 ARM
  Limited`). This is the "verbatim vendoring" case named in this repo's scope as a
  background/secondary pattern — worth having a confirmed real example of it, in contrast
  to FreeRTOS/Mbed TLS where every real fork checked had at least some in-place patch.
- **STMicroelectronics device pack** (`cmsis-device-f4`, vendored as a git submodule, not
  a copy-paste): `stm32f407xx.h` and `system_stm32f4xx.c` are 100% ST-authored (see
  section 2) — there is no "upstream Arm version" of these files to diff against, since
  Arm only ships a generic template (`CMSIS_6/CMSIS/Core/Template/Device_M`), not a
  per-device instantiation.
- **NXP** (`nxp-mcuxpresso/legacy-mcux-sdk`, the still-active older-style monolithic SDK
  repo, `SW-Content-Register.txt` present at repo root): device folders (e.g.
  `devices/K32L2A31A/`) contain the same vendor-authored device-header/system-file
  pattern as ST — but this is about the *device-specific* files (`K32L2A31A.h`,
  `system_K32L2A31A.c`), not CMSIS-Core's own generic files. **Correction from the
  Phase 2 pass** (confirmed by reading `west.yml` directly): `legacy-mcux-sdk` does
  **not** vendor CMSIS-Core's `core_cm*.h`/`cmsis_version.h` as static copy-paste
  anywhere in the repo either — a repo-wide recursive search turns up zero matches. It's
  pulled via the identical **west-managed external dependency** shape as the newer line
  (`name: CMSIS_5, path: core/CMSIS, revision: MCUX_2.16.000`, resolving by default to
  `nxp-mcuxpresso/CMSIS_5`, NXP's own fork of `ARM-software/CMSIS_5`). Diffed that fork's
  four Phase-2-tracked files against the matching upstream tag (`5.9.0` — see
  [experiments/version-fingerprint](experiments/version-fingerprint/README.md)): **all
  four byte-identical**, a second confirmed verbatim-vendoring data point alongside ST's.
  NXP's newer SDK line (`nxp-mcuxpresso/mcuxsdk-core`, a from-scratch multi-repo rewrite
  using Zephyr's `west` tool and a manifest/submanifest system) does **not** vendor
  CMSIS-Core directly into that repo at all either — its `arch/arm/` tree is build-system
  glue only (`Kconfig`, `.cmake` files). Also notable: NXP's own
  top-level `arch/` lists `arm`, `riscv`, `dsp56800`, and `xtensa` siblings — a concrete
  confirmation that **CMSIS only applies to the Arm Cortex-M subset of a given vendor's
  silicon lineup** (CMSIS-Core is Cortex-M-profile only — confirmed directly against the
  CMSIS_6 docs, which list M0/M0+/M1/M3/M4/M7/M23/M33/M35P/M52/M55/M85, SecurCore
  SC000/SC300, and Arm China's STAR-MC1/MC3, with no Cortex-A or Cortex-R variants), not
  to that vendor's non-Arm cores (relevant since this repo's in-scope vendor SDKs, e.g.
  ESP-IDF for Xtensa/RISC-V ESP32 variants, may not involve CMSIS at all for those
  specific chips — CMSIS detection logic should gate on "is this an Arm Cortex-M target"
  before expecting to find it).
- **The same architecture-gated split was confirmed independently for two more vendors
  this session, beyond NXP** — the pattern is "gated by which CPU core a given product
  *line* licenses," not by which company makes the chip:
  - **Infineon**: the **XMC family** (`Infineon/mtb-xmclib-cat3`) licenses Cortex-M0
    (XMC1000) / Cortex-M4 (XMC4000) cores and ships an explicit `CMSIS` folder
    ("CMSIS compliant device header files," confirmed directly). The **AURIX family**
    runs **TriCore**, Infineon's own proprietary 32-bit architecture (launched 1999 as
    "AUDO," fusing a RISC core + microcontroller + DSP in one design — nothing to do with
    Arm), used for automotive ECUs. Checked seven public AURIX repos
    (`illd_release_tc3x`/`tc2x`/`tc4x`, `AURIX_code_examples`, etc.) — zero CMSIS
    references in any of them.
  - **Renesas**: the **RA family** (`renesas/fsp`) licenses Cortex-M23/M33/M4 (RA8 parts
    use Cortex-M85) and ships CMSIS-Core device files at
    `ra/fsp/src/bsp/cmsis/Device/RENESAS/Include/renesas.h` — the same Device-pack shape
    as ST's `cmsis-device-f4`, confirmed directly. The **RX family**
    (`renesas/rx-driver-package`) is Renesas' own proprietary 32-bit architecture
    ("Renesas Xtreme," launched 2009 post Renesas/NEC merger, descended from the
    pre-merger Hitachi/Mitsubishi 8/16-bit lines) — checked directly, essentially no real
    CMSIS presence (one incidental unrelated string match in an unrelated FAT filesystem
    driver file, not a real integration). Renesas' RL78 and legacy SuperH lines are the
    same non-Arm story, not individually checked.
  - **Practical rule**: a CMSIS detector should determine "does this specific product
    line's core license Arm Cortex-M" (e.g. from a part-number/datasheet lookup) before
    applying any CMSIS heuristic — not infer it from the vendor name, since the same
    company can straddle both sides of this line depending on which of their chips a
    given source tree targets.
- **ARM-software itself maintains some vendor-specific CMSIS-Driver implementations**:
  `ARM-software/NXP_LPC`, `ARM-software/NXP_iMX`, `ARM-software/NXP_Kinetis` are
  Arm-hosted repos of CMSIS-Driver implementations *for* NXP parts — an unusual
  governance shape (the spec owner publishing vendor-targeted implementations directly,
  rather than the silicon vendor doing so) worth remembering if a NXP_* driver file turns
  up in a corpus sample attributed to the wrong org.
- **Real vendor provenance file found**: NXP's `legacy-mcux-sdk` ships
  `SW-Content-Register.txt` (an SCR, NXP's standard component-attribution file format) at
  repo root — but the top-level SCR only describes the *core drivers/build-scripts*
  package itself (origin: NXP + Zephyr + Kconfiglib), not a full per-component manifest
  of every vendored library (CMSIS included) — unlike Mbed TLS's `st_readme.txt`, this SCR
  is not a reliable one-stop CMSIS-version disclosure for this repo; per-subsystem SCRs
  may exist deeper in the tree but weren't found at the top level.
- **A real vendor "SBOM" file that turned out not to cover embedded source at all**:
  `nxp-mcuxpresso/mcuxsdk-core` ships a top-level `SBOM.spdx.json` — fetched and parsed
  this session. Its 63 `packages` entries are entirely **Ruby gems, RubyGems itself,
  Kconfiglib, and a pinned Zephyr version** — i.e. the SBOM covers the *documentation/
  build-tooling* dependency chain (a Ruby-based doc-site generator, it appears), not the
  vendored C source (CMSIS, drivers, middleware) the repository actually ships. Worth
  noting plainly: a real, currently-published vendor SBOM file existing in a repo is not
  evidence that the embedded C content of that repo is SBOM-tracked — the filename alone
  isn't a substitute for checking what's actually inside it.

## 4. Naming a detected CMSIS component in an SBOM

- **PURL**: derive one **per sub-repo**, not one for "CMSIS" as a whole, following the
  granularity finding in section 2 — e.g. `pkg:github/ARM-software/CMSIS_6@v6.3.0`,
  `pkg:github/ARM-software/CMSIS-DSP@v1.17.0`, `pkg:github/ARM-software/CMSIS-NN@v7.0.0`,
  and for a vendor device pack, `pkg:github/STMicroelectronics/cmsis-device-f4@v2.6.11`
  (noting the repo's own rename from `cmsis_device_f4`, confirmed via a `301 Moved
  Permanently` redirect this session — same "don't emit a now-redirected identifier"
  gotcha already flagged for Mbed TLS's `ARMmbed` → `Mbed-TLS` org rename, just at
  repo-name rather than org-name granularity here).
- **CPE**: queried the live NVD CPE dictionary (`services.nvd.nist.gov/rest/json/cpes/2.0`)
  for `cmsis`, `cmsis-dsp`, `cmsis-nn`, `cmsis-core`, and `cmsis-driver` this session.
  **Only `cmsis-rtos` has dictionary entries** — five records,
  `cpe:2.3:o:arm:cmsis-rtos:2.0.0` through `2.1.3`. Note the **`o` (operating-system) part
  field**, not `a` — the same RTOS-classification gotcha already flagged for
  FreeRTOS-Kernel in general notes, now confirmed a second time for a different RTOS-API
  component. No CPE exists for CMSIS-Core, CMSIS-DSP, CMSIS-NN, CMSIS-Driver, or the
  overall CMSIS pack as of this pass — don't assume one; fall back to PURL-only for those.
- **GHSA/OSV**: checked `security-advisories` via `gh api` for `CMSIS_5`, `CMSIS_6`, and
  `CMSIS-NN` — **zero advisories** on any of the three. One real CVE exists,
  **CVE-2021-27431** (integer wraparound in `osRtxMemoryAlloc`, CMSIS-RTOS2, fixed in
  2.1.3), matching the CPE dictionary's `cmsis-rtos` version range exactly. This
  corroborates that **CMSIS-RTOS2 is the one sub-component with a real tracked CVE
  history**; the header-heavy Core/DSP/NN/Driver components have essentially no public
  vulnerability history to date — plausible given their nature (mostly compile-time
  macros and register definitions, not parsers or network-facing code) but worth
  re-checking as CMSIS-NN's runtime kernels mature (NN inference code is a more plausible
  future CVE target than the older components).
- **Pack-based naming (separate from GitHub PURL/CPE)**: the CMSIS-Pack ecosystem uses
  its own `Cvendor::Cpack` naming (e.g. `ARM::CMSIS`, and vendor Device Family Packs like
  `STM32U5xx_DFP`, hosted under the `Open-CMSIS-Pack` org per this session's org listing).
  If a detector ever parses a `.pdsc` file directly (rather than inferring from source
  content), this pack-name/version is a *third* naming scheme worth surfacing alongside
  PURL/CPE, not a substitute for either.
- **Supplier/publisher**: `Arm Limited` / `ARM-software` for the core CMSIS repos;
  individual silicon vendors (`STMicroelectronics`, `NXP`, etc.) for their own device
  packs and CMSIS-Driver implementations — keep these as distinct `supplier` values per
  the section 2/3 attribution split, not collapsed into "Arm."

## 5. Amalgamation: not a meaningful case for this component

CMSIS-Core is already a small, header-heavy library by nature (most files are `.h`;
`system_<device>.c`/startup files are the only real `.c`/`.s` content, and those are
per-device, not a bulk implementation to amalgamate). No official single-file/amalgamated
CMSIS release was found. This mirrors the Mbed TLS finding
([mbedtls README §6](../mbedtls/README.md#6-amalgamation-not-an-upstream-release-shape-for-this-component))
— CMSIS is a second component in this repo's research for which the
"amalgamated/single-header" integration pattern named in scope doesn't apply. If that
pattern still needs a corpus example, look to a component whose upstream shape is
naturally a large single translation unit (e.g. an SQLite-style amalgamation, or a
`stb_*.h`-style single-header library) — CMSIS won't provide it either.

## 6. Licensing: no divergence found (unlike Mbed TLS)

CMSIS's licensing history is a clean single-license-family migration (BSD/zlib pre-v5 →
Apache-2.0 from v5 onward, confirmed section 1), not an ongoing dual-license model — there
is no GPL-alternative for a vendor to quietly drop the way ST does for Mbed TLS (see
[mbedtls README §5](../mbedtls/README.md#5-licensing-can-diverge-from-upstream-in-a-vendored-copy-without-any-content-change)).
The vendor device-pack layer (section 2/3) does carry **different copyright ownership**
than the Arm core files even where both currently land on Apache-2.0 (e.g. ST's
`cmsis-device-f4` repo-level `LICENSE` is Apache-2.0 text, same family as Arm's) — so this
is an **authorship/attribution** distinction, not a license-family divergence like the
Mbed TLS case. Worth stating precisely rather than overclaiming a second instance of the
same finding: same license text, different copyright holder, and that holder difference
is the part a detector needs to get right for accurate `supplier` metadata.

## 7. Detection implications

- **Structural fingerprint first**: `CMSIS/Include/core_*.h` + `CMSIS/Include/cmsis_*.h`
  file set is a cheap, high-confidence signal for "an Arm Cortex-M CMSIS-Core checkout
  is present," separately from whatever's in the sibling `CMSIS/Device/<vendor>/` tree.
- **Version-macro anchor**: `cmsis_version.h`'s `__CM_CMSIS_VERSION_MAIN`/`_SUB` macros
  are the CMSIS-Core-specific analog of FreeRTOS's `tskKERNEL_VERSION_NUMBER` and Mbed
  TLS's `MBEDTLS_VERSION_NUMBER` — confirmed to survive verbatim (byte-identical) in the
  one real vendor fork diffed this session. Remember it identifies **Core's own
  sub-version**, not the overall CMSIS pack version (section 2) — don't conflate the two
  numbers in a report.
- **Separate CMSIS-Core detection from CMSIS-Device-pack detection entirely** — they need
  different signature sets (Arm's fixed `core_*.h`/`cmsis_*.h` names for the former;
  vendor+family-specific header names like `stm32f407xx.h` for the latter), different
  attribution (`ARM-software` vs. the silicon vendor), and different version schemes
  (`cmsis_version.h` macro vs. whatever versioning the vendor's own DFP repo uses, if any
  is even embedded in-tree). Treating a `CMSIS/Device/...` match as "found CMSIS" would
  misattribute vendor-owned content to Arm.
- **No file-presence/absence extension-point pattern to look for here** (contrast with
  Mbed TLS's `_ALT` in-place-patch shape) — the realistic modification case for
  CMSIS-Core itself is a vendor pinning an older Core release inside an otherwise-current
  SDK (a genuine version-skew finding, exactly the scenario the FreeRTOS/mbedTLS
  cross-file-consistency check was built for), not a functional patch to Core's own files.
- **Gate CMSIS detection on architecture**: don't expect to find CMSIS in a non-Arm target
  tree from a vendor that also ships non-Arm silicon. Confirmed across three independent
  vendors this session (section 3): NXP (`arch/{arm,riscv,dsp56800,xtensa}` split),
  Infineon (XMC/Cortex-M ships CMSIS; AURIX/TriCore does not), and Renesas (RA/Cortex-M
  ships CMSIS; RX's proprietary architecture does not). General form extracted to
  [general/README.md](../../general/README.md#architecture-tied-standards-are-gated-by-cpu-core-choice-not-by-vendor).
- **A `.pdsc` file, if present in a corpus sample, is a strong direct-disclosure signal**
  (like Mbed TLS's `st_readme.txt`) — it names exact per-sub-component versions in
  human/machine-readable XML, better ground truth than any fingerprint. Not always
  present in a vendored (non-pack-tooling) source tree, though — many real-world
  copy-paste integrations (this repo's actual target case) drop the `.pdsc` and just keep
  the source files.

## Open questions / next steps

- **Phase 2 (version-fingerprint experiment) is done** — see
  [experiments/version-fingerprint](experiments/version-fingerprint/README.md). Tracks
  `cmsis_version.h` (the version-macro anchor) plus `core_cm0.h`/`core_cm4.h`/`core_cm33.h`
  (spanning Armv6-M/v7-M/v8-M), reference DB built from both `ARM-software/CMSIS_5`
  (13 releases) and `ARM-software/CMSIS_6` (4 releases) tag history, validated against a
  real ST fork, a real NXP fork, a synthetic mixed-version case, and a negative control —
  all four verdicts came out as expected.
- **A second real vendor fork was diffed (NXP)**, resolving the prior open item. Corrected
  a Phase 1 gap in the process: `legacy-mcux-sdk` doesn't vendor CMSIS-Core's generic files
  as static copy-paste at all — it pulls them via a **west-managed external dependency**
  (`core/CMSIS` → `nxp-mcuxpresso/CMSIS_5` fork, tag `MCUX_2.16.000`), the same
  external-dependency shape Phase 1 only previously confirmed for NXP's *newer*
  `mcuxsdk-core` line. Diffed against the correct upstream tag (`5.9.0` — not the `5.6.0`
  a naive read of the version macro would suggest, see the experiment README), all four
  tracked files are **byte-identical** — a second confirmed verbatim-vendoring data point,
  matching ST's. **Still open**: a genuinely *modified* real CMSIS-Core fork was never
  found (both real forks checked vendor verbatim) — Renesas's `renesas/fsp`
  (`ra/fsp/src/bsp/cmsis/Device/RENESAS/Include/`, confirmed present separately this
  session) is a candidate third data point if a modified case is still needed.
- **CMSIS-NN's date-based-to-semver tag transition** (section 2) — the concrete decision
  (bucket by which tag-regex a release matches, `^\d{2}\.\d{2}$` vs.
  `^v(\d+)\.(\d+)\.(\d+)$`, never compare across buckets numerically) is now documented in
  [experiments/version-fingerprint/README.md](experiments/version-fingerprint/README.md#cmsis-nn-tag-scheme-decision-documented-not-implemented---cmsis-nn-is-out-of-this-experiments-scope) —
  not implemented, since CMSIS-NN itself remains out of this experiment's scope.
- **Re-check CMSIS-NN's CVE exposure periodically** — currently zero advisories, but the
  reasoning in section 4 (inference kernels are a more plausible future target than
  header/macro components) suggests this could change as the component matures and sees
  wider adoption; worth a periodic recheck rather than treating "zero today" as permanent.
- **Not investigated**: CMSIS-Zone, CMSIS-Toolbox, CMSIS-Stream, and CMSIS-View in any
  depth beyond confirming they're separate repos (section 2) — none of these appear to be
  things that get *vendored into firmware source trees* the way Core/DSP/NN/Driver are
  (Toolbox and Zone are host-side tooling; View is an event-recorder/debug component); if
  any turns out to have a real vendoring footprint worth detecting, revisit.
- **Device Family Pack (DFP) repos as their own detection targets**: a DFP (e.g.
  `cmsis-device-f4`, `STM32U5xx_DFP`) is arguably its own separately-attributable
  component per vendor per device family (section 2/3) — whether this repo should track
  DFPs as first-class detection targets in their own right (separate from both "CMSIS"
  and the vendor's HAL, which is itself already out of this repo's CMSIS scope) is an open
  question, not decided in this pass.

Sources:
- [CMSIS - arm.com](https://www.arm.com/technologies/cmsis) — current acronym expansion
  ("Common Microcontroller Software Interface Standard"), cross-checked against
  [keil.arm.com/cmsis](https://www.keil.arm.com/cmsis) (same expansion; `developer.arm.com/.../cmsis`
  redirects here) and [CMSIS_6 docs](https://arm-software.github.io/CMSIS_6/latest/General/index.html)
  (same expansion).
- [GitHub - ARM-software/CMSIS_4 (README, fetched directly this session)](https://github.com/ARM-software/CMSIS_4)
  — older "Cortex Microcontroller Software Interface Standard" expansion, confirmed
  directly in this repo's own README text.
- [GitHub - ARM-software/CMSIS_5](https://github.com/ARM-software/CMSIS_5)
- [GitHub - ARM-software/CMSIS_6](https://github.com/ARM-software/CMSIS_6)
- [CMSIS_6/README.md (fetched directly this session)](https://github.com/ARM-software/CMSIS_6/blob/main/README.md)
- [CMSIS_6/ARM.CMSIS.pdsc (fetched directly this session, release-notes history quoted in section 2)](https://github.com/ARM-software/CMSIS_6/blob/main/ARM.CMSIS.pdsc)
- [CMSIS_6/LICENSE (fetched directly this session)](https://github.com/ARM-software/CMSIS_6/blob/main/LICENSE)
- [CMSIS: Introduction — arm-software.github.io/CMSIS_6](https://arm-software.github.io/CMSIS_6/latest/General/index.html)
- GitHub API repo/tag listings fetched directly this session for: `ARM-software/CMSIS_4`,
  `ARM-software/CMSIS_5`, `ARM-software/CMSIS_6`, `ARM-software/CMSIS-DSP`,
  `ARM-software/CMSIS-NN`, `ARM-software/CMSIS-RTX`, `ARM-software/CMSIS-Driver`,
  `ARM-software/CMSIS-DAP`, `ARM-software/CMSIS-View`, `ARM-software/CMSIS-Zone`,
  `ARM-software/CMSIS-Stream`, `ARM-software/CMSIS-Compiler`,
  `ARM-software/CMSIS-FreeRTOS`, `ARM-software/CMSIS-TFM`, `ARM-software/NXP_LPC`,
  `ARM-software/NXP_iMX`, `ARM-software/NXP_Kinetis`, `ARM-software/Cortex_DFP`
  (org search: `api.github.com/search/repositories?q=CMSIS+org:ARM-software`).
- [Open-CMSIS-Pack GitHub org (repo listing fetched directly this session)](https://github.com/Open-CMSIS-Pack)
- [NVD CPE Dictionary API — cmsis-rtos query (fetched directly this session)](https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=cmsis)
- [CVE-2021-27431 — ARM CMSIS RTOS2 Integer Overflow](https://github.com/advisories/GHSA-fphh-2884-975g)
- GitHub Security Advisories checked directly via `gh api repos/ARM-software/{CMSIS_5,CMSIS_6,CMSIS-NN}/security-advisories` this session (zero results each).
- Direct diff (this session) of `CMSIS/Core/Include/core_cm4.h` and
  `CMSIS/Core/Include/cmsis_version.h` between
  [STMicroelectronics/STM32CubeF4@master](https://github.com/STMicroelectronics/STM32CubeF4)
  and [ARM-software/CMSIS_5@5.9.0](https://github.com/ARM-software/CMSIS_5/tree/5.9.0)
  (byte-identical).
- [STM32CubeF4 .gitmodules (fetched directly this session — submodule map for CMSIS Device, HAL, BSP, Middlewares)](https://github.com/STMicroelectronics/STM32CubeF4/blob/master/.gitmodules)
- [STMicroelectronics/cmsis-device-f4 (formerly cmsis_device_f4, rename confirmed via redirect this session)](https://github.com/STMicroelectronics/cmsis-device-f4)
- [nxp-mcuxpresso/legacy-mcux-sdk (structure inspected directly this session, incl. SW-Content-Register.txt)](https://github.com/nxp-mcuxpresso/legacy-mcux-sdk)
- [nxp-mcuxpresso/mcuxsdk-core (structure and SBOM.spdx.json/SCR.txt fetched and parsed directly this session)](https://github.com/nxp-mcuxpresso/mcuxsdk-core)
- [CMSIS_6 Core documentation — supported processor list (fetched directly this session)](https://arm-software.github.io/CMSIS_6/latest/Core/index.html)
- [Infineon/mtb-xmclib-cat3 (structure inspected directly this session — confirmed CMSIS folder/device headers, Cortex-M0/M4)](https://github.com/Infineon/mtb-xmclib-cat3)
- Infineon AURIX public repos checked directly this session for CMSIS references (zero hits in all): [illd_release_tc3x](https://github.com/Infineon/illd_release_tc3x), [illd_release_tc2x](https://github.com/Infineon/illd_release_tc2x), [illd_release_tc4x](https://github.com/Infineon/illd_release_tc4x), [AURIX_code_examples](https://github.com/Infineon/AURIX_code_examples).
- [Wikipedia — Infineon TriCore architecture](https://en.wikipedia.org/wiki/Infineon_TriCore)
- [renesas/fsp (GitHub code search + direct file fetch this session, confirmed `ra/fsp/src/bsp/cmsis/Device/RENESAS/Include/renesas.h` and `bsp_api.h`'s CMSIS-CORE include)](https://github.com/renesas/fsp)
- [renesas/rx-driver-package (GitHub code search this session — no real CMSIS integration found)](https://github.com/renesas/rx-driver-package)
- [Wikipedia — Renesas RX architecture](https://en.wikipedia.org/wiki/Renesas_RX)
- [nxp-mcuxpresso/legacy-mcux-sdk west.yml (fetched directly this session — confirmed the `CMSIS_5`/`core/CMSIS` west-manifest entry pointing at `nxp-mcuxpresso/CMSIS_5@MCUX_2.16.000`)](https://github.com/nxp-mcuxpresso/legacy-mcux-sdk/blob/master/west.yml)
- [nxp-mcuxpresso/CMSIS_5 (NXP's fork of ARM-software/CMSIS_5, fetched and diffed directly this session at tag `MCUX_2.16.000` — byte-identical to upstream `5.9.0` across all four Phase-2-tracked files)](https://github.com/nxp-mcuxpresso/CMSIS_5)
- Phase 2 (version-fingerprint experiment): [experiments/version-fingerprint](experiments/version-fingerprint/README.md)
  — full source list for the reference-DB build and corpus in that experiment's own README.
