# Experiment: identifying the FreeRTOS-Kernel port layer (and deciding MPU applicability)

**Question**: the [core-file experiment](../version-fingerprint/README.md) answers *which
FreeRTOS-Kernel release* a tree vendored. It cannot answer *which port*, and the port is
what decides whether a kernel CVE applies at all. Can the port be identified from
vendored source, and does that turn the over-broad vulnerability verdict produced by
version matching alone into a precise one?

**Answer: yes, on all four corpus trees** — including flipping a real vendor fork
(ESP-IDF) from AFFECTED to NOT_AFFECTED on correct grounds, and flipping a synthetic
ARMv8-M tree either way purely on its build configuration.

Motivation, in one line: CVE-2024-28115 — the only published FreeRTOS-Kernel GHSA
advisory — applies to *"ARMv7-M MPU ports and ARMv8-M ports with MPU support enabled"*.
The [end-to-end vuln check](../../../../general/experiments/advisory-fitness/README.md#closing-the-loop--detected-version--applicable-cve-end-to-end-2026-07-28)
could pin the version but had to report every affected-version tree as AFFECTED, because
the port was invisible to it.

## Approach

Two questions, deliberately kept separate:

1. **Which port is this?** — content fingerprinting, same technique as the core-file
   experiment (normalized exact hash, winnowing-Jaccard fallback), but the reference DB is
   indexed by **(port, tag)** instead of tag alone.
2. **Does the MPU apply?** — a classification derived from the port identity, plus
   *build-configuration evidence* read from the tree.

### Identification is by content, never by path

A vendored tree routinely renames or flattens `portable/<compiler>/<arch>/`. ESP-IDF's
kernel copy is the proof: its ports live at `portable/xtensa/` and
`portable/riscv/`, names that exist nowhere upstream, with the headers moved to
`portable/xtensa/include/freertos/`. So the directory name is reported as a *hint* and
never used as evidence — every candidate directory is scored against all 176 known ports.

Upstream also ships some ARMv8-M ports **twice** (e.g. `portable/GCC/ARM_CM33/non_secure`
and `portable/ARMv8M/non_secure/portable/GCC/ARM_CM33`) with identical content, so
equally-scoring matches sharing (compiler, arch, security) are collapsed into one port
with several upstream paths.

### MPU is a three-valued classification, not a boolean

| classification | meaning | ports |
|---|---|---|
| `always` | a dedicated MPU port — presence alone settles it | 5: `GCC/ARM_CM3_MPU`, `GCC/ARM_CM4_MPU`, `GCC/ARM_CRx_MPU`, `IAR/ARM_CM4F_MPU`, `RVDS/ARM_CM4_MPU` |
| `optional` | ARMv8-M (CM23/33/35P/55/85): the MPU is a **build-time** choice (`configENABLE_MPU`) | 39 |
| `none` | no MPU support (Xtensa, RISC-V, PIC, non-MPU ARM, …) | 132 |

For `optional` ports the port files genuinely cannot answer the question, so the matcher
reads `configENABLE_MPU` from any `FreeRTOSConfig.h` in the tree and reports it **as
evidence, with the file it came from**. With no config found the answer is `UNKNOWN` —
never "no".

### Negative evidence for unidentified ports

An unidentified port is not automatically "unknown MPU". If no MPU-capable port scores
above the fuzzy floor (0.30) *and* the directory ships none of the MPU wrapper files,
that is **negative evidence**: whatever this port is, it isn't one of the ports the
advisory covers. The justification is calibrated against this repo's own data — the
heavily modified ESP-IDF `tasks.c` still scored **0.56** against its upstream base, so a
score near zero means *different code*, not *modified code*. ESP-IDF's Xtensa port scores
**0.035** against the closest upstream Xtensa port and **0.000** against every MPU port.

## Reference DB size

62 release tags × 176 port directories → **6.6 MB** (9 745 lines pretty-printed), from
7 050 (tag, port, file) observations deduplicated to 1 734 unique file contents.

Split by tier: **4.9 MB** for the 44 MPU-relevant ports (every port file fingerprinted)
and **1.6 MB** for the 132 identification-only ports (`port.c` + `portmacro.h` only).
Without that split — fingerprinting every file of every port — the DB would roughly
double for data that answers no question this experiment asks. Compare the core-file DB's
1.7 MB for 7 files × 62 tags: **the port layer costs ~4× the core kernel** to cover, which
is the concrete price of the granularity the advisory ecosystem keys on.

Built from a **full local clone** (~150 MB, ~25 s) rather than per-file HTTP: 7 050 file
reads over `raw.githubusercontent.com` would be slow and rude. A *blobless* clone
(`--filter=blob:none`) looks like the frugal option and is the wrong one — it defers blob
download, so `git cat-file --batch` degenerates into thousands of lazy per-blob network
fetches and hangs. That pitfall cost this session two dead background runs.

## Results

Run `python match_port.py <tree>` for port identity alone, or the
[end-to-end check](../../../../general/experiments/advisory-fitness/end_to_end_freertos.py)
for the vulnerability verdict. Against the corpus:

| corpus tree | port identified | version window | MPU | verdict (version only → refined) |
|---|---|---|---|---|
| `nxp-mcux-vendored` | **GCC / ARM_CM4_MPU** (ARMv7-M), exact | `V11.2.0` | ENABLED (dedicated MPU port) | NOT_AFFECTED → unchanged (post-fix release) |
| `esp-idf-fork` | **UNKNOWN_PORT** (correct — Espressif's Xtensa port is their own code) | — | NOT_SUPPORTED (negative evidence) | **AFFECTED → NOT_AFFECTED** |
| `armv8m-config-synthetic` | **GCC / ARM_CM33 non_secure** (ARMv8-M), exact | `V10.5.1` | DISABLED (`configENABLE_MPU 0`) | **AFFECTED → NOT_AFFECTED** |
| ↑ same tree, macro flipped to `1` | as above | `V10.5.1` | ENABLED (`configENABLE_MPU 1`) | AFFECTED → **AFFECTED, condition confirmed** |
| `mixed-version-synthetic` | no port files in the tree | — | UNKNOWN | AFFECTED → **POSSIBLY_AFFECTED** (undecidable) |

The port version window also **cross-checks the core-file result** without being told it:
NXP's `ARM_CM4_MPU` port resolves to `V11.2.0`, matching the core files' independent
`V11.2.0`. Two independent evidence producers agreeing is a stronger statement than
either alone.

### Finding 1 — the refinement changes real answers, in both directions

The headline is the ESP-IDF row: a **real vendor fork**, correctly detected as an affected
kernel version, is correctly ruled **not affected** because its port is not an ARM MPU
port. That is a false positive removed on evidence, not by assumption. The
`armv8m-config-synthetic` pair is the other direction: the *same source tree* is affected
or not depending only on a build macro, and the tool follows the macro.

### Finding 2 — the refinement must only ever narrow

`refine()` in the end-to-end script never turns NOT_AFFECTED into AFFECTED. Port evidence
can *withdraw* an advisory (condition provably unmet) or *suspend* it (condition
undecidable), but a version outside the affected range is already a complete answer.
Letting composition evidence upgrade a verdict would invent findings.

### Finding 3 — "no port files" is a different answer from "no MPU"

The mixed-version tree contains three kernel `.c` files and nothing else, so the port
cannot be determined and the verdict is suspended to POSSIBLY_AFFECTED. Silently treating
absent evidence as absent MPU would be the same class of error as reading an empty
advisory result as "no known vulnerabilities" — the tool distinguishes them.

### Finding 4 — a tree's evidence can be split across directories

ESP-IDF puts `port.c` in `portable/xtensa/` and `portmacro.h` in
`portable/xtensa/include/freertos/`, so directory-grouping sees two half-populated
candidates instead of one port. It happens not to change the outcome here (both resolve
to the same negative evidence), but grouping by literal directory is a weak assumption for
real vendor layouts. A future refinement should group by nearest common ancestor.

## How to reproduce

```
python build_port_db.py [--clone <dir>]   # ~6 min; clones FreeRTOS-Kernel if needed
python match_port.py <file-or-directory>  # port identity + MPU classification
```

No third-party dependencies; the fingerprinting primitives are imported from
[../version-fingerprint/freertos_fingerprint.py](../version-fingerprint/freertos_fingerprint.py)
so both experiments share one normalization/winnowing definition.

## Known limitations / next steps

- **Assembly normalization is C-flavored.** The shared normalizer strips `/* */` and `//`
  comments; `.s`/`.S` ports use `;` and `@`, which therefore survive into the fingerprint.
  Exact matching is unaffected (identical bytes still hash identically); only fuzzy scores
  on modified assembly are noisier than they need to be.
- **`configENABLE_MPU` is read from any `FreeRTOSConfig.h` in the tree.** A real project
  may carry several (per-board, per-build-variant), and the one the build actually uses is
  a build-system fact this experiment doesn't attempt to resolve — conflicting values are
  reported as UNKNOWN rather than guessed. Anything beyond that starts becoming build
  analysis, which is out of scope (see
  [general/sbom-generator-architecture.md](../../../../general/sbom-generator-architecture.md)
  rec. 13).
- **The applicability condition is curated by hand.** "CVE-2024-28115 requires MPU" was
  transcribed from the advisory's prose, because no source publishes it machine-readably.
  That curation is per-advisory work; it does not generalize automatically.
- **`ident`-tier ports are only fingerprinted on `port.c`/`portmacro.h`**, so a *modified*
  non-MPU port is identified more coarsely than a modified MPU port. Deliberate — that
  precision buys nothing for the MPU question.
- **Directory grouping** — see Finding 4.
- Only the FreeRTOS instance of this pattern exists so far. The general question ("which
  sub-layer of a component is present, and does the advisory apply to it?") is now
  recommendation 12 in the architecture handoff.
