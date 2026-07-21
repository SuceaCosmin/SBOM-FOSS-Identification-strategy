# Identifying OSS inside prebuilt static libraries (`*.a` + headers)

**Question**: when a vendor SDK ships OSS components pre-compiled into static
libraries (with only headers as source), which signals identify the component —
and its version — without assuming vendored source? This is the open topic
queued 2026-07-16 and promoted to next-up 2026-07-21, motivated by a real
encounter with Texas Instruments SDKs associated with Bluetooth Low Energy.

**Status (2026-07-21, first triage session)**: all four cheap signals surveyed
against a real SDK installed locally — **TI SimpleLink CC13xx/CC26xx SDK
8.33.00.16** (`C:\ti\simplelink_cc13xx_cc26xx_sdk_8_33_00_16`, freely
downloadable from ti.com; binaries not redistributable, so this experiment
records findings and commands, not corpus files). Headline results below;
no scripts yet — everything was done with stock Cygwin binutils
(`ar`, `nm`, `strings`) and PowerShell one-liners recorded inline.

## The artifact surveyed

- **684 static archives**, 1.4 GB total, in one SDK.
  Breakdown by subtree: 588 under `source\ti` (TI-authored),
  46 under `source\third_party`, 30 `kernel\nortos`, 15 `kernel\tirtos7`,
  5 `kernel\freertos`.
- Most libs come in **3 toolchain flavors (gcc / IAR / ticlang) × several
  cores (m0p/m4/m4f/m33f)** — the compiler-variance dimension of the binary
  problem is directly measurable from a single SDK.
- `source\third_party` contains prebuilt libs for known OSS: **FatFs**
  (roadmap Tier-1 adversarial case), **mbedTLS** (3.5.0), **SPIFFS**,
  **nanopb** (as `libext_nanopb.a` under sidewalk), plus **psa_crypto** and
  an `ecc` library (see licensing finding below). `kernel\freertos` has
  prebuilt FreeRTOS libs for IAR only.

## Findings by signal

### 1. `ar` member names — excellent when present (the common case)

Member names preserve upstream source filenames essentially always in this SDK:

- `fatfs.a` → `diskio.c.obj, ff.c.obj, ffsystem.c.obj, ffunicode.c.obj,
  ramdisk.c.obj` — unmistakably FatFs (`ff.c`/`ffunicode.c` exist nowhere
  else), plus TI's port files visible by name.
- `libmbedcrypto.a` → 60+ members exactly mirroring upstream mbedTLS
  `library/` (`aes.o`, `bignum_core.o`, `ecp_curves_new.o`, …). The member
  *set* itself is version-indicative (`bignum_mod_raw.o` only exists ≥ 3.x,
  `ecp_curves_new.o` narrows further).
- The naming convention differs per build system (`.c.obj` CMake-style vs
  plain `.o`) but the stem survives.

### 2. `nm` symbol tables — works out of the box, highest-value signal

Stock Cygwin binutils `nm` reads the ARM ELF objects from **both** GCC and
IAR archives (and defined-symbol sets are toolchain-independent, unlike code
bytes). Defined `T`-symbol sets are exactly the component's API surface —
`pb_encode/pb_decode/...` (nanopb), `mbedtls_aes_*`, `disk_*`/`f_*` (FatFs) —
and should support version fingerprinting the same way our source experiments
fingerprint file sets: API surface evolves across releases, so a
symbol-set → version-set reference DB is the natural port of the existing
tag-set approach. **Not yet built — the designated next step.**

### 3. Embedded strings — real but fragile; a negative finding worth keeping

- `libmbedcrypto.a` contains `"Mbed TLS"` (from `MBEDTLS_VERSION_STRING_FULL`
  in `version.o`) — but **the numeric version `"3.5.0"` does not survive as a
  clean string**. GCC compiled the short literal into `movw`/`movt`
  *instruction immediates*: `strings` shows only smeared fragments
  (`3.5.f`, ` 3.5H`) interleaved with opcode bytes. Longer literals stay in
  `.rodata` and survive; short ones can vanish into code.
  **Consequence**: absence of a version string in `strings` output proves
  nothing — the strings signal is confirm-only, never rule-out.
- Toolchain provenance leaks: every GCC object carries a
  `GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0` comment — TI built these on
  an Ubuntu 20.04 box. Useful context metadata, not component identification.

### 4. Bundled headers/source — often makes the binary problem moot (here)

For this SDK, mbedTLS / FatFs / SPIFFS ship **full source trees alongside
their prebuilt libs** (e.g. `build_info.h` states `MBEDTLS_VERSION_STRING
"3.5.0"` outright) — existing source fingerprinting already covers them; the
`.a` adds nothing except confirmation that the component is actually *built
into* firmware rather than merely present on disk. The genuinely binary-only
cases in this SDK are:

- `third_party\ecc` — headers + libs only, **no `.c`** (see licensing note),
- the sidewalk prebuilts (`libace_ama.a`, `libext_nanopb.a`),
- the 588 TI-authored libs (BLE stack et al.).

## Case studies

### nanopb hidden inside a proprietary archive (the SBOM-critical case)

`source\ti\ti_sidewalk\library\sid_demo\freertos\gcc\bin\sidewalk_fsk_ble.a`
(10.5 MB, 209 members, TI/Amazon Sidewalk proprietary code) **embeds nanopb
wholesale**: members `pb_encode.c.obj`, `pb_decode.c.obj`, `pb_common.c.obj`
and the full `pb_*` defined-symbol surface — with **no copyright/license
string announcing it**. Member names + symbols catch it trivially; a
source-only scanner misses it entirely. This is the exact
"proprietary blob as opaque carrier of hidden OSS" scenario, demonstrated on
a shipping commercial SDK. (FreeRTOS, by contrast, is *not* embedded there —
only `osal_*_freertos.c.obj` wrapper objects; the kernel links in from the
SDK's own tree.)

### `OneLib.a` (BLE5 stack core) — clean on cheap signals

`ble5stack\libraries\cc26x2r1\OneLib.a` (4.9 MB, 54 members: `att_*`, `gap_*`,
`gatt_*`, `hci*`, `ll_*`) shows no OSS member names, symbols, or license
strings — consistent with all-TI-authored code. Serves as the de-facto
negative control for the cheap signals. (Deeper binary-similarity checking of
such libs is constrained by licensing — next point.)

### The `ecc` "third_party" lib is TI-proprietary, with a no-disassembly clause

`third_party\ecc` (X25519/Ed25519, `ECCSW*`/`X25519_*` symbols) is **not**
micro-ecc or any OSS: `license.txt` is TI copyright 2015, redistribution in
binary form only, **"No reverse engineering, decompilation, or disassembly"**.
Two lessons:

1. `third_party/` placement and OSS-sounding names prove nothing about
   licensing — attribution needs evidence, not directory names (rhymes with
   the CMSIS `Device/<vendor>` finding).
2. **Legal constraint on technique depth**: archive listing, symbol tables,
   and strings are metadata reads of a distributed file; but
   decompilation-based function-similarity (the Ghidra BSim end of the
   candidate-tool list) would breach such license terms. A real-world scanner
   must be able to stop at the metadata tier — which is another argument for
   making the symbol-set fingerprint tier strong.

   On whether the metadata tier itself could be read as decompilation
   (question raised 2026-07-21): technically it is neither decompilation
   (no source reconstruction) nor disassembly (no instruction translation) —
   it reads structures the format *declares for third-party consumption*:
   the archive member table, the ranlib symbol index, and ELF symbol tables
   are consumed by the linker during normal licensed use (which is why they
   can't be stripped from a functional `.a`), and `strings` reads literal
   bytes without interpreting code. Nothing copyrightable is reconstructed;
   the output is a name list compared against public OSS releases. The gray
   zone is the broader term "reverse engineering" in restrictive clauses —
   a maximalist reading could reach any compositional analysis; counter-
   weights include the EU Software Directive's non-waivable observe/study/
   test right for lawful users, SBOM regulation (CRA, EO 14028) pushing
   composition transparency, embedded-OSS license obligations that *require*
   knowing what's inside, and industry practice (commercial binary-SCA tools
   do exactly this) — but this needs a real legal review in the product
   context, not an engineering opinion. The clean line: the tier boundary
   coincides with the legal one (metadata inspection vs BSim-style
   disassembly/decompilation), so the generator should default to
   metadata-only, gate binary-similarity behind explicit per-artifact
   opt-in, and record per finding which tier produced it so compliance can
   audit that no restricted technique touched a restricted file.

### IAR `freertos.a` contains only `portasm.s.o`

TI's prebuilt FreeRTOS libs (IAR only) hold a single assembly-port object —
the kernel proper is built from source per-project. A `.a`'s *name* promises
more than its contents deliver; detection must weigh contents, not filenames
(in both directions: `OneLib.a` says nothing, `freertos.a` says too much).

## Existing SBOM/manifest references in the SDK (checked 2026-07-21)

Before building anything, we checked whether TI already ships SBOM data that
could be reused (asked explicitly before proceeding with the symbol-set
prototype). Findings:

- **TI software manifest (root of every SDK)**:
  `manifest_simplelink_cc13xx_cc26xx_sdk_8_33_00_16.html` — a genuine
  per-component inventory table (name, version, license, delivered-as,
  modified-flag, location, obtained-from incl. upstream repo + tag). TI also
  hosts these online (`ti.com/pim/documents/swmetadata/...`). This is the
  closest thing to a vendor-supplied SBOM and a valuable *cross-check input*.
  **But it is demonstrably unreliable as ground truth on this very SDK**:
  - **nanopb appears nowhere in the manifest** (0 case-insensitive matches)
    despite being physically shipped both as `libext_nanopb.a` and embedded
    unannounced inside `sidewalk_fsk_ble.a` — the Sidewalk tree is declared
    only as "Amazon Sidewalk Commercial Proprietary License".
  - The manifest declares **Mbed-TLS 3.4.0** (tag v3.4.0) for
    `source/third_party/mbedtls`, but the shipped `build_info.h` in that
    exact directory says **3.5.0** (`MBEDTLS_VERSION_NUMBER 0x03050000`) —
    the manifest is stale against the SDK's own payload.
- **Upstream SBOMs ride along inside vendored trees**:
  `source/third_party/freertos/sbom.spdx` is AWS's own SPDX 2.2 document for
  FreeRTOS-Kernel **v10.5.1** with **per-file SHA1 checksums** (plus a
  matching upstream `manifest.yml`). Where present, this is high-quality
  reference data for free — both for identifying the vendored copy and as a
  mineable source of per-file hashes. Detection heuristic: glob for
  `sbom.spdx`/`manifest.yml`/`*.spdx` inside candidate trees.
- **Code Composer Studio (ccs2100)**: no user-facing SBOM-generation
  capability found (locally or in public docs). CCS does *ship* SPDX
  documents for TI's own compiler runtime libraries (e.g.
  `TI_ARM_CLANG_RTS_5_1_0_LTS-*.spdx`), generated by **ScanCode Toolkit**
  over TI's build sources — TI's own creator comment warns checksums "may
  not be the final checksums". So TI's internal SBOM tooling is
  ScanCode-based and applied to compiler tools, not SDK payloads, and
  nothing in CCS generates SBOMs for user projects.

**Conclusion**: vendor manifests/SBOMs exist and should be *harvested as
inputs* (component hints, upstream repo+tag pointers, embedded upstream SPDX
files), but the two errors above — an undeclared embedded OSS component and a
wrong version for a declared one, in a single SDK — confirm they cannot
replace independent detection. They are a corroboration tier, and
manifest-vs-detected discrepancies are themselves a valuable scanner output.

## Implications for the detection strategy

1. **Tiered pipeline mirrors the source-side design**: member names (exact,
   cheap) → defined-symbol sets (version fingerprinting via reference DB) →
   strings (confirm-only corroboration) → binary similarity (last resort,
   license-permitting). The first three tiers needed nothing but binutils and
   caught everything present in this SDK.
2. **The reference-DB approach ports directly**: for each curated component,
   compile (or mine from release archives/symbols) the per-version
   API-symbol sets; match a `.a`'s defined symbols against them exactly like
   the source experiments match file tag-sets. minr/KB infrastructure is
   unaffected — this is a new *extractor* front-end, not a new backbone.
3. **"Present as source" ≠ "built into firmware"**: the `.a` tier answers a
   question source scanning can't — which components are actually compiled
   into the delivered binary. Worth noting for eventual SBOM semantics
   (`.a` evidence is closer to the deployed artifact).

## Symbol-set version-fingerprint prototype (2026-07-21) — VALIDATED

The designated next step was built and validated the same day. Three scripts,
all clean-room (no binutils/compiler dependency anywhere):

- **`extract_symbols.py`** — parses the ar format and each member's ELF
  symbol table directly (ELF32 *and* ELF64 little-endian; GNU + BSD member
  naming); emits defined GLOBAL/WEAK symbols per member and flat.
- **`mine_ref_symbols.py`** — builds the per-release reference sets **from
  source, no compilation**: checks out each git tag and extracts candidate
  external function names from the component's headers by prototype-pattern
  matching (comment/preprocessor-stripped). Confirms the no-compiler thesis:
  reference mining is a source-only operation, exactly like minr's.
- **`match_symbols.py`** — ports the tag-set/window logic: observed symbols
  must be a *subset* of a release's set (config-gated builds), releases
  ranked by fewest soft absences; discriminating symbols listed as evidence.
- Reference DBs checked in: `nanopb_ref_symbols.json` (26 releases,
  0.3.6–0.4.9.1), `mbedtls_ref_symbols.json` (18 releases,
  v2.28.0–v3.6.7).

### Results (all ground truths hit, negative controls clean)

| Target | Truth | Result |
|---|---|---|
| `libext_nanopb.a` (labeled prebuilt) | 0.3.9.3 (its own `pb.h`) | window {0.3.9 … 0.3.9.3} — truth inside, 4 releases wide |
| nanopb hidden inside `sidewalk_fsk_ble.a` | undeclared | identical window {0.3.9 … 0.3.9.3} — pinned from symbols alone inside a 209-member proprietary blob |
| `libmbedcrypto.a` | 3.5.0 (bundled `build_info.h`) | window {v3.5.0, v3.5.1, v3.5.2} — truth inside, 3 releases wide; 752/763 observed symbols known to DB |
| `fatfs.a` vs nanopb DB | negative | NO MATCH |
| `OneLib.a` (BLE stack) vs mbedTLS DB | negative | NO MATCH |

**The mbedTLS result also positively refutes the vendor manifest**: observed
symbols like `mbedtls_ct_memcpy_if` exist only in ≥ v3.5.0, so the manifest's
claimed 3.4.0 is *excluded by binary evidence*, not just contradicted by the
bundled headers. Detection out-performed the vendor's own declaration.

### Prototype findings / limitations

- **`libmbedcrypto.a` is an x86-64 host build** (ELF64, `e_machine=62`,
  GCC/Ubuntu 20.04) shipped inside an ARM SDK — build detritus in
  `library/` from TI's CMake run. Scanner lesson: parse arch-agnostically
  (symbol names don't care), and treat "which architecture" as metadata,
  not a filter.
- Header-prototype mining misses **data symbols** (`extern const ...
  mbedtls_ecdsa_info` etc. — no `(` after the name): 11/763 observed
  symbols unknown to the DB. Harmless here; a data-declaration pattern can
  close it later.
- Version windows from symbols are **3–4 point releases wide** on these two
  components — coarser than source hashing (as predicted) but exactly the
  window-shaped output the existing consistency logic already handles.
- One mined-set artifact (`psa_get_and_lock_key_slot_with_policy` appearing
  version-bound when it shouldn't be) shows prototype-regex mining has
  noise; a tree-sitter-grade extractor would clean it up if needed.

## Next steps (decided 2026-07-21, in priority order)

Principle: the prototype proved the concept — next moves either test its
failure modes cheaply or connect it to the system it belongs to; no
gold-plating.

1. **De-risking sweeps** (one short session, tooling already exists):
   - **gcc/IAR/ticlang variance check** — diff extracted symbol sets across
     the three toolchain flavors of the *same* lib version (SPIFFS/FatFs
     ship all three). Empirically verifies the compiler-independence claim
     the whole tier rests on, instead of taking it on faith.
   - **Batch-scan all 588 TI-authored libs** against both reference DBs:
     false-positive stress test at scale (they should overwhelmingly say
     NO MATCH) + hunt for more undeclared OSS (the nanopb precedent), and
     the output doubles as a whole-SDK composition-report demo.
2. **Integrate, don't expand**: fold symbol reference sets into the
   minr-experiment lightweight-export artifact design (the mined JSONs are
   a few hundred KB — trivial next to the 48 MB artifact). Makes the symbol
   tier a first-class evidence type of the curated-KB backbone rather than
   a side experiment. Mostly a design/writeup task.
3. **Return to the deferred OSV.dev fitness test** — with the static-lib
   scenario covered, the biggest program-level unknown is again the output
   end (does purl+version output drive vuln scanning correctly?). The
   mbedTLS result supplies a fresh test case: a shipping SDK whose binary
   contains 3.5.x (known CVEs) while its manifest claims 3.4.0 — exactly
   the story an SBOM-to-vuln-scan pipeline exists to tell.

Deliberately deferred (polish, not risk): data-symbol mining (the 11/763
unknown gap), member-name normalization policy (`.c.obj` vs `.o`,
truncation in ancient ar formats), and the stripped/LTO hard tier (parked
until a real artifact exhibits it; this SDK does not).

## Commands used (Cygwin binutils on Windows, PowerShell)

```powershell
$sdk = 'C:\ti\simplelink_cc13xx_cc26xx_sdk_8_33_00_16'
# inventory
Get-ChildItem $sdk -Recurse -Include *.a,*.lib -File
# member names
ar t "$sdk\source\third_party\fatfs\lib\gcc\m4f\fatfs.a"
# defined symbols (works for gcc and IAR ARM ELF alike)
nm --defined-only "$sdk\...\sidewalk_fsk_ble.a" | Select-String ' T '
# strings probe (confirm-only!)
strings "$sdk\source\third_party\mbedtls\library\libmbedcrypto.a" |
  Select-String 'Mbed TLS'
# extract a single member
ar x "$sdk\source\third_party\mbedtls\library\libmbedcrypto.a" version.o
```
