# Mbed TLS

First research pass, following the same shape as the FreeRTOS pass: governance/licensing
history and distro landscape (who forks/vendors it, what silicon-vendor integration
layers exist) before attempting a detection experiment.

General principles extracted from this research (component granularity, PURL/CPE
identifier strategy, detection technique patterns) live in
[general/README.md](../../general/README.md) rather than being restated here — this doc
covers what's specific to Mbed TLS itself.

## 1. Governance and licensing history

- Started life as **XySSL** (Christophe Devine, first released 2006-11-01) under GPLv2
  and BSD dual licensing.
- Renamed **PolarSSL** (~2008/2009). Source headers from this era read
  `This file is part of PolarSSL`.
- **November 2014**: PolarSSL acquired by ARM Holdings, rebranded **mbed TLS**. Source
  headers shift to `This file is part of Mbed TLS` / `Copyright (C) <year>, Arm Limited,
  All Rights Reserved` under Apache-2.0. This exact header-text substitution
  (PolarSSL → Mbed TLS phrasing) is a sharper brand-era signal than the copyright-year
  alone, similar in spirit to FreeRTOS's WHIS-vs-Amazon header shift (see general notes),
  though weaker in isolation since the Apache-2.0 boilerplate itself is generic and reused
  by unrelated projects — the diagnostic part is the specific project-name phrase, not the
  license block.
- **Starting with 2.1.0**, the library moved to dual licensing: **Apache-2.0 OR
  GPL-2.0-or-later** — still the current model as of mid-2026.
- **March 2020**: Mbed TLS joined the **TrustedFirmware.org** project (Linaro-hosted),
  moving to open, multi-stakeholder governance rather than being solely Arm-controlled.
  The GitHub org was renamed from `ARMmbed` to `Mbed-TLS` around this transition; old
  `ARMmbed/mbedtls` links now redirect.
- **October 2025**: joint release of **Mbed TLS 4.0** and **TF-PSA-Crypto 1.0** — see
  section 2, this is a real repo/product split, not just a version bump.
- LTS cadence: roughly 18 months between LTS branches, each supported ~3 years (e.g.
  Mbed TLS 2.28 LTS and 3.6 LTS, the latter supported until at least March 2027). Multiple
  LTS branches are commonly in the wild simultaneously — a vendored copy's version can't
  be assumed to track the newest release line.

## 2. Component granularity: the 4.0 / TF-PSA-Crypto split matters

Unlike FreeRTOS (which was *always* an umbrella brand over several independently
versioned repos), Mbed TLS was historically a **single repo, single component**: TLS,
X.509, and all crypto primitives (plus the PSA Crypto API surface) lived in one
`Mbed-TLS/mbedtls` tree with one version number. Pre-4.0 vendored trees should be treated
as **one SBOM component**.

That changed with the October 2025 split:

- **[Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls)**, from **4.0** onward, contains
  only TLS and X.509, and depends on TF-PSA-Crypto for all cryptographic primitives.
- **[Mbed-TLS/TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto)**, **1.0** onward,
  is the reference implementation of the PSA Cryptography API and now owns the low-level
  crypto code that used to live inside `mbedtls`. Its own repo, own version line (1.0,
  planned 1.1 LTS in 2026 Q1), released in lockstep with Mbed TLS but independently
  versioned.
- A vendored **4.x-era** tree should therefore potentially be attributed as **two**
  components (Mbed TLS + TF-PSA-Crypto), not one — the same granularity trap identified
  for FreeRTOS-Kernel vs. FreeRTOS-Plus (see general notes on component granularity).
- **[Mbed-TLS/mbedtls-framework](https://github.com/Mbed-TLS/mbedtls-framework)** also
  exists (shared build/test tooling extracted out) but is not shipped/vendored into
  firmware — likely irrelevant for SBOM detection, noted for completeness only.

**Practical implication for the eventual detector**: version-era detection (e.g. via the
`MBEDTLS_VERSION_STRING` macro, section 6) should branch on major version — pre-4.0 findings
map to one component, 4.0+ findings should attempt to separately identify a bundled
TF-PSA-Crypto tree.

## 3. What layers typically stack on top

The core library is usually vendored close to verbatim except for hardware-acceleration
hooks. The `_ALT` mechanism is Mbed TLS's official, sanctioned extension point: defining
`MBEDTLS_<MODULE>_ALT` (whole-module) or `MBEDTLS_<MODULE>_<FUNC>_ALT` (single-function)
in `mbedtls_config.h`/`config.h` is meant to let a vendor drop the upstream
implementation of that module and link a hardware-backed replacement instead.

**Real vendor repos were fetched and diffed against the matching upstream tag to see what
this actually looks like on disk (not just what the mechanism's documentation implies)**,
and the result was a genuine correction to an initial assumption: it is *not* mainly a
"whole file absent, vendor-authored file added" pattern. All three vendors checked patch
the upstream file **in place**, wrapping the accelerated path in an inline
`#if !defined(MODULE_ALT) ... #endif` guard around the *existing* implementation, with the
vendor's own code nearby (often with an explicit attribution comment):

- **Espressif ESP-IDF** — [espressif/mbedtls](https://github.com/espressif/mbedtls) fork.
  Diffed `mbedtls-3.6.2-idf` against upstream `v3.6.2`: `library/bignum.c` and
  `library/ecp.c` each carry real, localized changes (~48-49 diff lines), e.g.
  `#if !defined(MBEDTLS_MPI_MUL_MPI_ALT)` wrapping `mbedtls_mpi_mul_mpi()`'s software
  path. `include/mbedtls/version.h` is byte-identical to upstream.
- **NXP** — [nxp-mcuxpresso/mbedtls](https://github.com/nxp-mcuxpresso/mbedtls) fork.
  Diffed `release/25.12.00` (tracks upstream 2.28.10) against upstream `mbedtls-2.28.10`:
  `library/aes.c` (67 diff lines) and `library/ecdsa.c` (6 lines) both show the same
  shape — `#if defined(MBEDTLS_CIPHER_MODE_CBC) && !defined(MBEDTLS_AES_CBC_ALT)` guards
  added around existing code, each annotated `/* NXP added MBEDTLS_AES_CBC_ALT */` inline.
  `library/bignum.c` and `library/ecp.c` are also modified (67, 92 lines) for
  ELS/PKC-backed asymmetric crypto. `version.h` is untouched.
- **STMicroelectronics** — [stm32-mw-mbedtls](https://github.com/STMicroelectronics/stm32-mw-mbedtls).
  Diffed `v3.6.6_20260511` against upstream `v3.6.6`: `library/ecdsa.c` has a real,
  functional patch (33 diff lines — ST's own "double signature check" feature, unrelated
  to hardware acceleration). `library/aes.c` and `version.h` differ by only **4 lines
  each**, and every one of those lines is the `SPDX-License-Identifier` line inside the
  file's header comment (see section 5) — i.e. no code difference at all once comments
  are stripped.
  - `stm32-mw-mbedtls/st_readme.txt` is itself a strong signal on its own: a
    vendor-maintained changelog stating exactly which upstream version each release
    tracks ("Move to Mbed-TLS V3.6.6") and bullet-listing every ST-specific patch by name
    and file. Worth checking for this class of file before falling back to
    fingerprinting (see general notes on detection technique patterns).
- **Silicon Labs** (Gecko SDK CRYPTO/AES plugins) and **Infineon**
  ([cy-mbedtls-acceleration](https://github.com/Infineon/cy-mbedtls-acceleration) for
  PSoC 6) were identified as `_ALT` users during the distro-landscape pass but not
  diffed directly — assume the same in-place-patch shape until checked, don't assume
  file-absence.
- **RTOS/middleware consumers** (not forks, just dependents worth noting since they may
  co-occur in a corpus sample): Zephyr (module, alongside TinyCrypt/PSA alternatives,
  TinyCrypt being phased out in favor of PSA Crypto), lwIP (`altcp_tls`), Amazon FreeRTOS
  libraries.

This generalizes into a corrected version of the general notes on sanctioned extension
points (see general/README.md) — the discriminator is patch *shape* (small, localized,
macro-gated diffs, often with a vendor-name comment), not file presence/absence.

## 4. Naming a detected Mbed TLS component in an SBOM

- **CPE**: NVD carries `cpe:2.3:a:mbed:mbedtls:<version>:*:*:*:*:*:*:*` across many
  versions (confirmed 1.3.10 through 2.24.0+) — **type `a`** ("application"), unlike
  FreeRTOS-Kernel's `o` gotcha. Separately, the **PolarSSL-branded era has its own CPE**:
  `cpe:2.3:a:polarssl:polarssl:<version>` (57 records in NVD) — a vendored copy that still
  carries PolarSSL-era headers/version strings needs the PolarSSL CPE, not the `mbed`
  one; don't assume a project's own renames collapse into a single vendor:product pair.
  No CPE has been found yet for TF-PSA-Crypto (too new — split was ~9 months before this
  research pass); re-check as NVD coverage matures.
- **PURL**: `pkg:github/Mbed-TLS/mbedtls@<tag>` (e.g. `@v3.6.0`). Note the GitHub org is
  now `Mbed-TLS` (capitalized, hyphenated) — a PURL derived from an old local clone's
  remote URL may still read `ARMmbed/mbedtls`; normalize to the current org rather than
  emitting a now-redirected identifier. From 4.0 onward, a TF-PSA-Crypto finding should
  get its own PURL: `pkg:github/Mbed-TLS/TF-PSA-Crypto@<tag>`.
- **GHSA/OSV**: keyed to `Mbed-TLS/mbedtls` (e.g. CVE-2026-25834, CVE-2025-49601) —
  matches the PURL granularity, same pattern as FreeRTOS.
- **supplier/publisher**: `Arm Limited` for pre-2020 releases; treat post-2020 releases as
  published under **TrustedFirmware.org / Linaro** stewardship (open governance, code
  copyright spread across contributors) rather than solely Arm — keep as separate
  metadata from `name`.

## 5. Licensing can diverge from upstream in a vendored copy without any content change

Confirmed directly in the ST diff from section 3: `stm32-mw-mbedtls`'s `st_readme.txt`
states *"Remove dual license, STMicroelectronics provides the Mbed TLS middleware under
only the Apache-2.0 license"* starting with their mbedtls-3.6.1-based release
(Sept. 2024), and the repo's top-level `LICENSE` file confirms it — Apache-2.0 text only,
no GPL option. Critically, this re-licensing is enforced by editing **only** the
`SPDX-License-Identifier` line inside each source file's header comment (e.g.
`Apache-2.0` instead of `Apache-2.0 OR GPL-2.0-or-later`) — nothing else in the file
changes. `library/aes.c` and `include/mbedtls/version.h` each differ from upstream by
exactly that one line.

**Implication for detection**: this is legal for a downstream redistributor of a
dual-licensed project (Apache-2.0 doesn't require preserving the GPL alternative), but it
means a vendored copy's actual license can't be inferred from "which upstream release
this content-matches" — a detector needs a **separate, unnormalized** check of the
license header/file text, because the same comment-stripping normalization that correctly
treats reformatting as a non-change (see general notes: "in-source version strings
survive modification") will just as correctly, and unhelpfully, treat this real licensing
difference as no difference at all. Generalizes beyond Mbed TLS to any dual-licensed
component (see general/README.md).

## 6. Amalgamation: not an upstream release shape for this component

Unlike `stb_*.h`-style single-header libraries or SQLite's amalgamated build, **Mbed TLS
does not ship an official amalgamated/single-file release**. A 2015 feature request for
this was never merged upstream. If an amalgamated Mbed TLS blob is found vendored into a
project, it's necessarily a **third-party repackaging** (e.g. tooling like
`embedthis/patch-mbedtls`), not evidence of a particular upstream version shape — the
"amalgamated/single-header" integration pattern named in this repo's scope simply doesn't
apply to Mbed TLS itself the way it might to another component. Worth remembering when
picking the next component to research if amalgamation detection specifically needs
validating — Mbed TLS won't be the corpus example for that case.

## 7. Detection implications

- **Version macro**: `MBEDTLS_VERSION_STRING` / `MBEDTLS_VERSION_NUMBER`
  (`0xMMNNPP00` packed form) in `include/mbedtls/version.h` — same "in-source version
  string survives modification" pattern as FreeRTOS's `tskKERNEL_VERSION_NUMBER`. Confirmed
  directly: byte-identical to upstream in both the Espressif and NXP diffs (section 3),
  since neither vendor had reason to touch it — a reliable pinning anchor even when
  crypto-module files are genuinely modified.
- **Structural fingerprint**: characteristic file/directory layout (`library/`,
  `include/mbedtls/`, `include/psa/` for pre-4.0; split `tf-psa-crypto/` tree for 4.0+) is
  a cheap first-pass filter, as with FreeRTOS.
- **Recognize the `_ALT` pattern by patch shape, not file absence** (see section 3):
  small, localized diffs clustered around `#if !defined(MODULE_ALT)`/`#endif` guards,
  frequently with an inline vendor-attribution comment, wrapping an otherwise-intact
  upstream function. This is a named, structured modification category — "vendor
  hardware-acceleration integration" — distinct from generic "modified/forked," and,
  per the real diffs gathered here, is also distinct from ST's `ecdsa.c` patch (a
  functional feature addition unrelated to hardware acceleration) and from ST's
  `aes.c`/`version.h` (no code change at all, license-line-only — section 5). A detector
  should be able to tell these three apart rather than reporting all non-exact-matches
  as one undifferentiated "modified" bucket.
- **Check for a vendor provenance changelog before fingerprinting** (e.g.
  `st_readme.txt`) — when present it directly states the upstream version and patch list,
  which is strictly better ground truth than any content-matching approach.
- **License check needs to be separate from content matching** (section 5) — don't infer
  license from version-match; check the SPDX line/LICENSE file directly, unnormalized.
- **Real fork case**: Espressif's `espressif/mbedtls` (in-place patches to bignum/ECC) is
  the right corpus candidate for validating fuzzy/winnowing similarity matching against a
  genuinely modified copy, mirroring the role ESP-IDF FreeRTOS played in the FreeRTOS
  experiment.
- **Copyright header era**: `PolarSSL` vs. `Mbed TLS` project-name phrase in the header is
  a usable brand-era signal, but weaker than FreeRTOS's WHIS text since the surrounding
  Apache-2.0 license block is boilerplate shared with unrelated projects — match on the
  project-name phrase specifically, not the license text.
- **Two-component attribution for 4.0+**: a detector that finds Mbed TLS 4.0+ signatures
  should also look for a co-located TF-PSA-Crypto tree and report both, rather than
  assuming one component per FreeRTOS/general-notes granularity guidance (section 2).

## Open questions / next steps

- Detection experiment built and validated: see
  [experiments/version-fingerprint](experiments/version-fingerprint/README.md) — the same
  exact-hash + winnowing-similarity approach used for FreeRTOS-Kernel, run against real
  Espressif, ST, and NXP corpus entries plus a mixed-version and a negative-control case.
  All five verdicts came out correct (three PARTIALLY MODIFIED, one MIXED VERSION
  WARNING, one NOT THIS COMPONENT) — the version-macro anchor file correctly pinned the
  base release even in the NXP case where 4 of 5 tracked files were genuinely modified.
  The negative control surfaced and fixed a real verdict-logic bug (a zero-similarity tie
  was being misreported as "LIKELY CONSISTENT").
- Re-check NVD for a dedicated TF-PSA-Crypto CPE as it matures (none found as of this
  pass, mid-2026, ~9 months post-split).
- No amalgamation experiment should be planned against Mbed TLS specifically (section 6)
  — if the amalgamated/single-header detection case needs a corpus example, look
  elsewhere.
- Not yet investigated: PSA Crypto driver interface (a *third* extension mechanism,
  distinct from classic `_ALT`, used for newer PSA-API-based hardware drivers) — worth a
  follow-up look since Mbed TLS 4.x pushes everything through PSA Crypto by default,
  which may make the driver-interface pattern more common than classic `_ALT` in newly
  vendored trees.
- Not yet built: a detector rule that specifically recognizes the `#if !defined(..._ALT)`
  patch shape (section 3/7) as its own category, distinct from "modified." The version-
  fingerprint experiment reports these as PARTIALLY MODIFIED (correct, but undifferentiated
  from any other kind of partial modification) — teaching it the specific shape is future
  work, not done in this pass.
- Not yet built: a standalone, unnormalized license-header check (section 5) — the
  fingerprint experiment only does version/modification detection, not license
  verification.

Sources:
- [Mbed TLS - Wikipedia](https://en.wikipedia.org/wiki/Mbed_TLS)
- [Mbed TLS, TF-PSA-Crypto - trustedfirmware.org](https://www.trustedfirmware.org/projects/mbed-tls/)
- [Newsroom | Linaro - Hafnium, mbedTLS, PSA Crypto join Trusted Firmware](https://www.linaro.org/news/hafnium-mbedtls-psa-crypto-join-the-trusted-firmware-project/)
- [Will you continue to provide GPL licence? · Issue #343 · Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls/issues/343)
- [mbedtls/LICENSE at development · Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE)
- [How is Mbed TLS (formerly PolarSSL) protected legally? — Mbed TLS documentation](https://mbed-tls.readthedocs.io/en/latest/kb/licensing/how-is-mbedtls-protected/)
- [Roadmap — Mbed TLS documentation](https://mbed-tls.readthedocs.io/en/latest/project/roadmap/)
- [Major changes in Mbed TLS 4.0 - mbed-tls-announce](https://lists.trustedfirmware.org/archives/list/mbed-tls-announce@lists.trustedfirmware.org/thread/CXXFH3JQNRHEW4CHT2OHDEK5HXBOW3L4/)
- [GitHub - Mbed-TLS/TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto)
- [Add new Zephyr module for Mbed TLS 4.0 + TF-PSA-Crypto 1.0 releases · Issue #97660 · zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr/issues/97660)
- [NVD - Detail - cpe:2.3:a:mbed:mbedtls:2.16.5](https://nvd.nist.gov/products/cpe/detail/811292?namingFormat=2.3&orderBy=CPEURI&keyword=cpe%3A2.3%3Aa%3Ambed%3Ambedtls&status=FINAL%2CDEPRECATED)
- [NVD - Results - polarssl](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe%3A2.3%3Aa%3Apolarssl%3Apolarssl%3A*%3A*%3A*%3A*%3A*%3A*%3A*%3A*&status=FINAL%2CDEPRECATED&orderBy=CPEURI&namingFormat=2.3)
- [GitHub - nxp-mcuxpresso/mbedtls](https://github.com/nxp-mcuxpresso/mbedtls)
- [Mbed TLS - ESP32 — ESP-IDF Programming Guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/protocols/mbedtls.html)
- [GitHub - STMicroelectronics/stm32-mw-mbedtls](https://github.com/STMicroelectronics/stm32-mw-mbedtls)
- [Porting Mbed TLS to the STM32H5 platform with hardware crypto acceleration - ST Community](https://community.st.com/t5/stm32-mcus/porting-mbed-tls-to-the-stm32h5-platform-with-hardware-crypto/ta-p/741441)
- [GitHub - Infineon/cy-mbedtls-acceleration](https://github.com/Infineon/cy-mbedtls-acceleration)
- [Alternative cryptography engines implementation — Mbed TLS documentation](https://mbed-tls.readthedocs.io/en/latest/kb/development/hw_acc_guidelines/)
- [STMicroelectronics/stm32-mw-mbedtls st_readme.txt](https://raw.githubusercontent.com/STMicroelectronics/stm32-mw-mbedtls/main/st_readme.txt) —
  vendor changelog directly cited for the licensing and in-place-patch findings (sections 3, 5).
- Direct diffs (this session) of `library/bignum.c`, `library/ecp.c`,
  `include/mbedtls/version.h` between
  [espressif/mbedtls@mbedtls-3.6.2-idf](https://github.com/espressif/mbedtls/tree/mbedtls-3.6.2-idf)
  and [Mbed-TLS/mbedtls@v3.6.2](https://github.com/Mbed-TLS/mbedtls/tree/v3.6.2).
- Direct diffs (this session) of `library/aes.c`, `library/ecdsa.c`,
  `include/mbedtls/version.h`, `LICENSE` between
  [STMicroelectronics/stm32-mw-mbedtls@v3.6.6_20260511](https://github.com/STMicroelectronics/stm32-mw-mbedtls/tree/v3.6.6_20260511)
  and [Mbed-TLS/mbedtls@v3.6.6](https://github.com/Mbed-TLS/mbedtls/tree/v3.6.6).
- Direct diffs (this session) of `library/aes.c`, `library/ecdsa.c`,
  `include/mbedtls/version.h` between
  [nxp-mcuxpresso/mbedtls@release/25.12.00](https://github.com/nxp-mcuxpresso/mbedtls/tree/release/25.12.00)
  and [Mbed-TLS/mbedtls@mbedtls-2.28.10](https://github.com/Mbed-TLS/mbedtls/tree/mbedtls-2.28.10).
- [Amalgamated Releases · Issue #202 · Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls/issues/202)
- [mbedtls/BRANCHES.md at development · Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls/blob/development/BRANCHES.md)
- [MBed TLS v3.6.0 Long Term Support(LTS) Release - trustedfirmware.org blog](https://www.trustedfirmware.org/blog/mbed-tls-3-6-0-lts/)
- [File include/mbedtls/version.h — Mbed TLS Versioned documentation](https://mbed-tls.readthedocs.io/projects/api/en/development/api/file/include_2mbedtls_2version_8h/)
- [Mbed-TLS/mbedtls-framework](https://github.com/Mbed-TLS/mbedtls-framework)
- [Security Advisories · Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls/security/advisories)
