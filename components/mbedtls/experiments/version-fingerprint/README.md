# Experiment: version-fingerprinting Mbed TLS from source only

**Question**: given a subset of Mbed TLS's source files in a project (no build metadata,
no package manager), can we (a) confirm it's Mbed TLS, (b) identify which release it came
from, and (c) tell whether it's been locally modified - using the same exact-hash +
winnowing-similarity approach validated for FreeRTOS-Kernel
([components/freertos/experiments/version-fingerprint](../../../freertos/experiments/version-fingerprint/README.md)),
applied to a component whose vendor modifications turned out to look structurally
different (see [../../README.md](../../README.md) sections 3 and 7)?

## Tracked files

Unlike FreeRTOS-Kernel (3 files that are close to "the whole component" and always sit
flat in one directory), Mbed TLS is a large, multi-hundred-file library. Tracking all of
it isn't the point of a research prototype, so this experiment deliberately tracks five
files, chosen from real vendor diffs gathered while writing [../../README.md](../../README.md)
section 3 (not an arbitrary or "complete" file list):

- `include/mbedtls/version.h` - carries `MBEDTLS_VERSION_STRING`; confirmed
  byte-identical to upstream in every vendor fork diffed. The anchor file: it should pin
  the base release even when everything else tracked is modified.
- `library/bignum.c`, `library/ecp.c` - the files Espressif's ESP-IDF fork is documented,
  and confirmed by diffing, to patch for hardware bignum/ECC acceleration.
- `library/aes.c`, `library/ecdsa.c` - files confirmed modified by NXP (hardware AES/ECDSA
  acceleration) and, differently, by STMicroelectronics (`ecdsa.c` gets a real feature
  patch; `aes.c` differs from upstream by only its license header line - see
  [../../README.md](../../README.md) section 5).

These files span two subdirectories of a real checkout (`include/mbedtls/` vs.
`library/`), so - unlike the FreeRTOS matcher, which groups files by their literal parent
directory - `match_target.py` here treats the whole scanned target path as a single
group representing one vendored copy.

## Approach

Same three-script shape as the FreeRTOS experiment (kept as its own copy per this repo's
per-component convention, not shared code):

1. `build_reference_db.py` - enumerates tags on `Mbed-TLS/mbedtls` via `git ls-remote`
   (no clone), scoped to release tags with major version 2 or 3 (`mbedtls-X.Y.Z` or
   `vX.Y.Z` forms). Out of scope: 1.3.x (PolarSSL era, pre-dual-license, pre-rebrand -
   see [../../README.md](../../README.md) section 1) and 4.0+ (moves `bignum.c`/`ecp.c`/
   `aes.c`/`ecdsa.c` out of this repo into the separate TF-PSA-Crypto repo - section 2;
   tracking that split is future work, not done here).
   - **Tag-count reality check that shaped this script**: this repo carries **537 total
     tags**, but many releases are tagged *twice* - an old `mbedtls-X.Y.Z` name and a
     newer `vX.Y.Z` name pointing at the identical commit (a coexistence FreeRTOS-Kernel
     doesn't have). Fetching both would waste roughly half the HTTP requests for zero
     new information, so tags are deduplicated **by commit SHA** (from `git ls-remote`'s
     peeled `^{}` entries) before any file is fetched, not just by content hash
     afterward. Result: 280 tags in the 2.x/3.x range collapsed to **116 unique commits**.
   - **Rate limiting**: the first run of this script hit `HTTP 429` from
     `raw.githubusercontent.com` after ~150 unauthenticated requests. Fixed with a fixed
     0.3s delay between requests plus exponential backoff on 429 - both now baked into
     the script (and into this skill's reusable template, see below) rather than
     something to rediscover per component.
2. `mbedtls_fingerprint.py` - identical normalize/hash/winnow algorithm to the FreeRTOS
   experiment (comment-stripping + whitespace-collapse normalization, SHA-256 exact hash,
   30-gram/50-window winnowing fingerprint with 32-bit hashes).
3. `match_target.py` - same verdict categories as the FreeRTOS matcher (CONFIRMED / MIXED
   VERSION WARNING / PARTIALLY MODIFIED / INCONSISTENT / INCOMPLETE / LIKELY CONSISTENT),
   plus one addition made *because* of what this experiment's negative control exposed -
   see below.

Reference DB: `reference/mbedtls_fingerprints.json` (~2.6 MB - 159 tags, 266 unique
file-contents across the five tracked files, 116 unique commits fetched). Pretty-printed
(structure indented, winnow integer arrays kept inline per line) for human browsing —
see `pretty_json()` in `build_reference_db.py`.

## A real bug this experiment's negative control caught

The FreeRTOS matcher's final fallback branch picks each file's single best fuzzy-match
tag and checks whether all tracked files agree. Mbed TLS's negative control (an unrelated
C file - `cJSON.c` - saved under all five tracked filenames) scored **0.000 similarity
against every known release**, as expected... but the matcher still reported
**"LIKELY CONSISTENT: best-match version agrees across all files -> v3.6.6"**. The reason:
with every candidate tied at score 0.0, the tie-break (highest tag name, lexicographically)
picked the same tag - `v3.6.6` - for every file, which the "do all files agree" check
then read as genuine agreement.

Fixed by adding a similarity floor (`NO_SIMILARITY_FLOOR = 0.05`): if any tracked file's
best score is below it, the tool now reports **`NOT THIS COMPONENT`** instead of reaching
the agreement check at all. Re-verified against all five corpus entries below after the
fix (real modifications still correctly reach PARTIALLY MODIFIED/MIXED VERSION - the
floor only intercepts the true-zero case). Backported the same fix into this skill's
reusable `match_target.py.template` so the next component's first negative-control run
doesn't have to rediscover it.

## Result

Tested against [../../corpus/](../../corpus/) - three real vendor forks, one synthetic
mixed-version case, and one negative control:

| Target | Result |
|---|---|
| `esp-idf-fork/` (`espressif/mbedtls@mbedtls-3.6.2-idf`) | **PARTIALLY MODIFIED.** `version.h`, `aes.c`, `ecdsa.c` exact-match (the latter two turned out untouched by Espressif - a new finding, since the original diffing in `../../README.md` only checked `bignum.c`/`ecp.c`). `bignum.c` and `ecp.c` have no exact match; closest fuzzy matches (0.967, 0.981) land at v3.6.4 and v3.6.2 respectively, both within the exact-matched files' common range, so the tool reports a plausible base of **{v3.6.2, v3.6.4}** - consistent with the fork's known v3.6.2 origin. |
| `stm32-mw-mbedtls/` (`STMicroelectronics/stm32-mw-mbedtls@v3.6.6_20260511`) | **PARTIALLY MODIFIED.** `version.h` and `aes.c` exact-match (as predicted - their only diff from upstream is the license-header line, which normalization strips). `ecp.c` **also** exact-matches (v3.6.5/v3.6.6) - not previously checked in the distro-landscape pass, a genuine new data point: ST's ECC hardware acceleration doesn't touch this file. `bignum.c` and `ecdsa.c` have no exact match (bignum.c similarly not previously diffed directly - the experiment surfaced that ST modifies it too, presumably for PKA-backed bignum operations, alongside the already-documented `ecdsa.c` "double signature check" patch). Base correctly pinned to **v3.6.6**. |
| `nxp-mcuxpresso-fork/` (`nxp-mcuxpresso/mbedtls@release/25.12.00`) | **PARTIALLY MODIFIED**, the most heavily-modified case: only `version.h` exact-matches (**v2.28.10**). All four other tracked files (`bignum.c`, `ecp.c`, `aes.c`, `ecdsa.c`) are genuinely modified (confirmed by direct diff beforehand: 67, 92, 67, and 6 lines respectively - NXP's ELS/PKC hardware acceleration hooks). Despite 4-of-5 tracked files being modified, the single untouched anchor file (`version.h`) still correctly pins the base to **v2.28.10** via the fuzzy-match overlap check - the strongest stress-test of the "unmodified anchor survives even heavy modification" property in either experiment so far. |
| `mixed-version-synthetic/` (synthetic: `bignum.c`+`ecp.c` from v3.5.0/v3.6.0 respectively, `aes.c`+`ecdsa.c`+`version.h` from v3.6.0) | All five files exact-match, but **not to a common release** → **MIXED VERSION WARNING**, correctly flagging the deliberately-mismatched `bignum.c`. |
| `unrelated-negative-control/` (`cJSON.c` saved under all five tracked filenames) | **NOT THIS COMPONENT** (post-fix) - every file scores 0.000 similarity against every known release. Before the fix (see above), this was misreported as `LIKELY CONSISTENT`. |

**Conclusion**: the same exact-hash + winnowing pipeline validated for FreeRTOS-Kernel
transfers to Mbed TLS without algorithm changes, confirms the version-macro-carrier file
is a reliable pinning anchor even when most other tracked files are genuinely modified
(NXP case: 4-of-5 modified, still correctly pinned), and - just as importantly - the
process of running it against a *real* negative control (not just real forks) surfaced an
actual verdict-logic bug that a "does it work on real forks" test alone would never have
exposed. This validates fingerprint/similarity matching (general notes:
[detection technique patterns](../../../../general/README.md#detection-technique-patterns))
as viable for a second, structurally different component, and reinforces
[../../README.md](../../README.md) section 7's point that a modified file's *closest fuzzy
match* and an unrelated file's *coincidental tie* need to be told apart by score
magnitude, not just by which branch of the verdict logic is reached.

## How to reproduce

```
python build_reference_db.py      # rebuilds reference/mbedtls_fingerprints.json (~10-15 min, ~580 paced HTTP fetches)
python match_target.py <path>     # scans a directory for the five tracked filenames
```

No third-party dependencies - pure standard library (`urllib`, `hashlib`, `subprocess`
for `git ls-remote` only). On Windows, run via a shell with native Python path resolution
(e.g. PowerShell) rather than Git Bash - see the `research-component` skill's "known
pitfalls" for why.

## Known limitations / next steps

- Five files is this experiment's deliberately narrow scope (see "Tracked files" above),
  not a claim that these are "the" minimal Mbed TLS signature the way
  `tasks.c`/`queue.c`/`list.c` are for FreeRTOS-Kernel. A real vendored copy could
  plausibly include only some of these five, which would currently report INCOMPLETE.
- Reference DB is scoped to 2.x/3.x only (section above) - a 4.0+ target will always
  report INCOMPLETE against this DB today, since `bignum.c`/`ecp.c`/`aes.c`/`ecdsa.c`
  no longer live in the `Mbed-TLS/mbedtls` repo from 4.0 onward. Extending to 4.0+
  requires a second reference DB against `Mbed-TLS/TF-PSA-Crypto` - deferred, matching
  the "two-component attribution" open item in `../../README.md`.
- The `NO_SIMILARITY_FLOOR = 0.05` threshold was picked to clear the observed 0.000
  negative-control score with margin, not calibrated against a larger set of
  genuinely-similar-but-different C code (e.g. another crypto library). A real modified
  file that happens to score under 0.05 (very heavy rewrite) would also be misreported as
  "not this component" - untested edge case.
- Tie-breaking among equal fuzzy-similarity scores (by tag name, lexicographic) is
  arbitrary and inherited from the FreeRTOS matcher design - visible in the
  `esp-idf-fork` result, where `bignum.c`'s closest match is reported as a single tag
  (`v3.6.4`) despite four releases (`v3.6.1`-`v3.6.4`) tying at 0.967. Doesn't change any
  verdict here, but would be worth surfacing ties explicitly rather than picking one if
  this matures beyond a prototype.
- Not attempted: recognizing the specific `#if !defined(MODULE_ALT)` patch shape
  (`../../README.md` sections 3/7) as its own reported category, distinct from generic
  PARTIALLY MODIFIED. All three real forks tested here would currently report identically
  regardless of *why* their files diverge from upstream.
