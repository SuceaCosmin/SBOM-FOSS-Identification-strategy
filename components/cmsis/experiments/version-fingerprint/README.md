# Experiment: version-fingerprinting CMSIS-Core from source only

**Question**: given a subset of CMSIS-Core's source files in a project (no build
metadata, no `.pdsc` pack manifest, no package manager), can we (a) confirm CMSIS-Core is
present, (b) identify which release it came from, and (c) tell whether it's been locally
modified - using the same exact-hash + winnowing-similarity approach already validated for
FreeRTOS-Kernel
([components/freertos/experiments/version-fingerprint](../../../freertos/experiments/version-fingerprint/README.md))
and Mbed TLS
([components/mbedtls/experiments/version-fingerprint](../../../mbedtls/experiments/version-fingerprint/README.md)),
applied to a component whose real-world vendoring turned out to be **verbatim** rather
than patched (see [../../README.md](../../README.md) section 3)?

## Tracked files

CMSIS-Core ships roughly 30 `core_c{a,m,r}*.h` variants (one per supported Arm core) plus
a handful of shared compiler/version headers. Tracking all of them isn't the point of a
research prototype, so this experiment deliberately tracks four files:

- `CMSIS/Core/Include/cmsis_version.h` - carries the `__CM_CMSIS_VERSION_MAIN`/`_SUB`
  macros, CMSIS-Core's version anchor (see [../../README.md](../../README.md) section 7).
  Confirmed byte-identical to upstream in **both** real vendor forks diffed this session
  (see "Result" below) - the strongest possible anchor candidate given the evidence.
- `CMSIS/Core/Include/core_cm0.h` - the Armv6-M baseline core (used by e.g. Infineon's
  XMC1000 line, see [../../README.md](../../README.md) section 3).
- `CMSIS/Core/Include/core_cm4.h` - the mainstream Armv7-M core; the one file already
  diffed against a real ST fork during Phase 1.
- `CMSIS/Core/Include/core_cm33.h` - the newer Armv8-M mainline/TrustZone core (used by
  e.g. Renesas RA, see [../../README.md](../../README.md) section 3).

These three `core_cm*.h` variants were picked to span the Cortex-M profile's age range,
not because they're "the" three most important cores - a real vendored copy typically
ships the *entire* `CMSIS/Core/Include/` directory regardless of which single core the
target chip uses (confirmed this session: STM32CubeF4, an M4-only part family, still
ships `core_cm0.h` and `core_cm33.h` alongside `core_cm4.h`), so any subset would have
worked as a research sample.

## Approach

Same three-script shape as the FreeRTOS and Mbed TLS experiments (kept as its own copy
per this repo's per-component convention, not shared code):

1. `build_reference_db.py` - enumerates release tags across **two** repos via
   `git ls-remote` (no clone) and merges them into one reference DB, reflecting the real
   governance split found in Phase 1 ([../../README.md](../../README.md) section 1):
   - `ARM-software/CMSIS_5` (archived, tags `5.0.0`-`5.9.0`) - matched with an anchored
     `^(\d+)\.(\d+)\.(\d+)$` regex, which also excludes a stray non-release tag on this
     repo, `NN/2.0.0` (an artifact of CMSIS-NN's pre-split history living in this repo's
     tag namespace before CMSIS-NN moved to its own repo in 2022 - see
     [../../README.md](../../README.md) section 2).
   - `ARM-software/CMSIS_6` (active, tags `v6.0.0`-`v6.3.0`) - matched with
     `^v(\d+)\.(\d+)\.(\d+)$`.
   - Both anchored regexes naturally exclude every `-dev`/`-rc`/`-Beta`/`-devN` pre-release
     tag found on either repo (e.g. `5.8.0-rc`, `5.2.1-dev3`, `v6.3.0-dev`, `v6.3.1-dev`).
   - **Tag-count reality check**: both repos combined carry only **17 in-scope release
     tags** (13 + 4) - far smaller than FreeRTOS-Kernel's 58 tags or Mbed TLS's 116 unique
     commits, since CMSIS_6 is young and CMSIS_5 was never double-tagged under two naming
     schemes the way mbedTLS was. Confirmed the file path (`CMSIS/Core/Include/<file>`)
     is stable across every one of the 17 tags before writing the fetch script, not
     assumed from the single Phase 1 data point.
   - **A real scope boundary, not a bug**: `cmsis_version.h` doesn't exist before
     `CMSIS_5` tag `5.1.0` (confirmed directly this session) - `5.0.0` and `5.0.1` have
     no entry for it in the reference DB, same "some releases predate the anchor file"
     shape as Mbed TLS's 1.3.x/PolarSSL-era gap, just three commits instead of a whole
     licensing era.
2. `cmsis_fingerprint.py` - identical normalize/hash/winnow algorithm to the FreeRTOS and
   Mbed TLS experiments (comment-stripping + whitespace-collapse normalization, SHA-256
   exact hash, 30-gram/50-window winnowing fingerprint with 32-bit hashes).
3. `match_target.py` - same verdict categories as the other two matchers (CONFIRMED /
   MIXED VERSION WARNING / PARTIALLY MODIFIED / INCONSISTENT / INCOMPLETE / LIKELY
   CONSISTENT / NOT THIS COMPONENT), including the `NO_SIMILARITY_FLOOR` fix the Mbed TLS
   negative control surfaced - ported forward from the start this time rather than
   rediscovered. Files are grouped by literal parent directory (like the FreeRTOS
   matcher), since all four tracked files normally sit together in one
   `CMSIS/Core/Include/` directory in a real checkout - unlike Mbed TLS's two-subdirectory
   layout.

Reference DB: `reference/cmsis_fingerprints.json` (~480 KB - 17 tags, 44 unique
file-contents across the four tracked files).

## A second real vendor diff, and a version-macro subtlety it surfaced

Phase 1 only diffed ST's fork directly. This pass added a second: NXP's `legacy-mcux-sdk`
pulls CMSIS-Core via a **west-managed external dependency**
(`core/CMSIS` -> `nxp-mcuxpresso/CMSIS_5` fork, tag `MCUX_2.16.000`), confirmed by reading
its `west.yml` manifest and fetching the fork's actual tree - a real refinement of the
Phase 1 characterization, which described the *device-specific* files (`K32L2A31A.h`,
etc.) as vendor-authored but didn't check whether CMSIS-Core's own generic files were
vendored as static copy-paste in this repo. They aren't; they're pulled from a pinned
external fork, the same architectural shape Phase 1 already found for NXP's *newer*
`mcuxsdk-core` line, now confirmed for the "legacy" line too.

Diffing that fork's four tracked files against `ARM-software/CMSIS_5` initially used the
**wrong** upstream tag: the fork's `cmsis_version.h` macros read
`__CM_CMSIS_VERSION_MAIN (5U)` / `__CM_CMSIS_VERSION_SUB (6U)`, which is *not* release
`5.6.0` - the sub-version macro is an internal Arm counter, not the tag's own third digit
(the same fact Phase 1 already noted for STM32CubeF4's identical `5U`/`6U` reading, which
maps to tag `5.9.0` - see [../../README.md](../../README.md) section 3). Diffing against
the correct tag, `5.9.0`, all four tracked files are **byte-identical**. This is a second
confirmed "verbatim vendoring" data point (matching ST's), and a concrete reminder - now
baked into `cmsis_fingerprint.py`'s docstring - that the version-macro *value*, not a
file's own `@version`/`@date` docstring comment or a superficially-similar tag string,
is what actually pins a release.

## Result

Tested against [../../corpus/](../../corpus/) - two real vendor forks (both turned out
verbatim, consistent with Phase 1's finding that CMSIS-Core's realistic modification case
is version-skew, not in-place patching - see [../../README.md](../../README.md) section
7), one synthetic mixed-version case, and one negative control:

| Target | Result |
|---|---|
| `stm32cubef4/` (`STMicroelectronics/STM32CubeF4@master`) | **CONFIRMED -> 5.9.0.** All four tracked files exact-match a single common release. |
| `nxp-legacy-mcux-sdk/` (`nxp-mcuxpresso/CMSIS_5@MCUX_2.16.000`) | **CONFIRMED -> 5.9.0.** Same result as ST, byte-identical release - both real forks checked so far vendor CMSIS-Core verbatim. |
| `mixed-version-synthetic/` (synthetic: `core_cm4.h` from `5.6.0`, the other three tracked files from `5.9.0`) | All four files exact-match, but **not to a common release** -> **MIXED VERSION WARNING**, correctly isolating the deliberately-mismatched `core_cm4.h`. |
| `unrelated-negative-control/` (`DaveGamble/cJSON`'s `cJSON.h` saved under all four tracked filenames) | **NOT THIS COMPONENT** - every file scores 0.000 similarity against every known release; the `NO_SIMILARITY_FLOOR` guard (ported from the Mbed TLS fix) correctly intercepts the tie-break trap before it could be misreported as `LIKELY CONSISTENT`. |

**Conclusion**: the same exact-hash + winnowing pipeline validated for FreeRTOS-Kernel and
Mbed TLS transfers to CMSIS-Core without algorithm changes. Unlike the other two
components, **both** real forks checked here vendor verbatim rather than patch in place -
this is itself a confirming data point for Phase 1's finding that CMSIS-Core's
in-the-wild modification risk is a vendor pinning an older release wholesale (a
cross-file-consistency / version-skew question), not a functional patch to Core's own
files (general notes:
[detection technique patterns](../../../../general/README.md#detection-technique-patterns)).
The synthetic mixed-version and negative-control cases confirm the matcher still catches
the two failure modes a "verbatim-only" real corpus can't exercise on its own.

## How to reproduce

```
python build_reference_db.py      # rebuilds reference/cmsis_fingerprints.json (~1-2 min, ~64 paced HTTP fetches)
python match_target.py <path>     # scans a directory for the four tracked filenames, grouped by parent dir
```

No third-party dependencies - pure standard library (`urllib`, `hashlib`, `subprocess`
for `git ls-remote` only). On Windows, run via a shell with native Python path resolution
(e.g. PowerShell) rather than Git Bash - see the `research-component` skill's "known
pitfalls" for why.

## CMSIS-NN tag-scheme decision (documented, not implemented - CMSIS-NN is out of this
experiment's scope)

[../../README.md](../../README.md) section 2 flagged that `ARM-software/CMSIS-NN`'s tags
switch schemes mid-history: date-based `YY.MM` tags (`24.02`, `23.08`, `23.02`, ...) before
`v4.0.0`, then semver (`v4.0.0` through `v7.0.0`) after. If CMSIS-NN is ever brought into
this experiment's scope, the decision (consistent with how this experiment already
separates `CMSIS_5` from `CMSIS_6` by per-repo regex) is: **bucket by which regex a tag
matches, never compare across buckets numerically.** A date-based tag like `24.02` and a
semver tag like `v4.0.0` are not orderable against each other as version numbers (`24.02`
is not "newer" than `4.0.0` despite the larger leading number) - they're two different,
non-comparable tagging eras. A reference-DB builder for CMSIS-NN would need two tag-regex
filters (`^\d{2}\.\d{2}$` and `^v(\d+)\.(\d+)\.(\d+)$`) feeding the same content-dedup
logic already used here, and a matcher would report whichever bucket produces the
exact/fuzzy match - exactly the same shape this experiment already uses to keep
`CMSIS_5`'s and `CMSIS_6`'s tags from being compared as if they were one numbering space.

## Known limitations / next steps

- Four files is this experiment's deliberately narrow scope (see "Tracked files" above),
  not a claim that these are "the" minimal CMSIS-Core signature. A real vendored copy
  ships roughly 30 `core_c{a,m,r}*.h` variants; a target with only some of the four
  tracked here would currently report INCOMPLETE.
- **Both real corpus forks turned out verbatim** - this experiment did not get a
  genuinely-modified real CMSIS-Core fork to test the PARTIALLY MODIFIED path against
  (only the synthetic mixed-version case exercises the "files disagree" branches). This
  is itself consistent with Phase 1's finding (no known `_ALT`-style extension point for
  CMSIS-Core), but a third vendor fork - e.g. Renesas's `renesas/fsp`
  (`ra/fsp/src/bsp/cmsis/Device/RENESAS/Include/`, confirmed present in the architecture-
  gating research this session) - would be worth diffing before treating "verbatim is
  universal" as fully confirmed rather than "verbatim in the two forks checked so far."
- CMSIS-NN's tag-scheme split (section above) is a documented decision, not implemented -
  no CMSIS-NN reference DB or corpus entries exist yet.
- Reference DB coverage stops at the newest tag on each repo as of this session
  (`CMSIS_5@5.9.0`, `CMSIS_6@v6.3.0`) - will need a re-run if either repo cuts a new
  release.
- Tie-breaking among equal fuzzy-similarity scores (by tag name, lexicographic) is
  arbitrary and inherited from the FreeRTOS/Mbed TLS matcher design - not exercised
  differently here, since every non-INCOMPLETE result in this pass resolved via exact
  hash rather than fuzzy fallback.
