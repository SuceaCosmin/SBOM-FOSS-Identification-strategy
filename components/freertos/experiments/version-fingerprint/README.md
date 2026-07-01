# Experiment: version-fingerprinting FreeRTOS-Kernel from source only

**Question**: given only `tasks.c`/`queue.c`/`list.c` in a source tree (no build
metadata, no package manager), can we (a) confirm it's FreeRTOS-Kernel, (b) identify
which release it came from, and (c) tell whether it's been locally modified — using
only content-level analysis, per the pipeline sketched in
[components/freertos/README.md §6](../../README.md#6-detection-implications)?

## Approach

1. `build_reference_db.py` — lists every tag on `FreeRTOS/FreeRTOS-Kernel` via
   `git ls-remote` (no clone needed), then fetches `tasks.c`/`queue.c`/`list.c` per tag
   over HTTPS from `raw.githubusercontent.com`. Handles the repo's layout change over
   time: tags from roughly V10.3.0-kernel-only onward have the files at the repo root;
   older tags predate the kernel-only extraction and still carry the old
   `FreeRTOS/Source/...` distribution layout — the fetcher tries both paths. Very old
   pre-2014 tags (V4.x–V7.1.x, plus non-release refs like `BackupPoints`) weren't chased
   further; they're outside the realistic range for anything vendored into a project
   today.
2. `freertos_fingerprint.py` — for each file: strip comments and collapse whitespace
   (`normalize`), then compute both a SHA-256 of the normalized content (exact-match
   fast path) and a **winnowing fingerprint** (Schleimer/Wilkerson/Aiken): hash every
   30-character gram of the normalized text, then keep only the minimum hash in each
   sliding window of 50 grams (rightmost on ties). The surviving hash set is the
   fingerprint — small, and provably still shares at least one hash with any other file
   containing a common substring of ~79+ normalized characters.
3. `match_target.py` — for a candidate file: check for an exact SHA-256 match against
   every known tag first; if none, fall back to Jaccard similarity between winnowing
   fingerprints and report the closest tags.

Reference DB: `reference/kernel_fingerprints.json` (~4.7 MB, committed — 58 tags,
V8.0.0 through V11.3.0 plus a handful of older ones, three files each).

## Result

Tested against three real-world files (saved as ground truth in
[../../corpus/](../../corpus/)):

| Target | Result |
|---|---|
| `corpus/nxp-mcux-vendored/tasks.c` (NXP's `FreeRTOS-Kernel` mirror, `release/26.03.00` branch) | **Exact match → V11.2.0.** Confirms NXP vendors the kernel byte-for-byte (modulo comments/whitespace) unmodified. |
| `corpus/esp-idf-fork/tasks.c` (Espressif's SMP fork, `master` branch) | No exact match (expected — it's a real fork). Closest by fingerprint similarity: **V10.5.1 (0.556)**, then V10.5.0 (0.553), V10.6.x (~0.539). This **independently confirms** what [components/freertos/README.md §3](../../README.md#3-what-layers-typically-stack-on-top-of-the-kernel) already noted from Espressif's own docs: the fork is based on v10.5.1. |
| Unrelated file (`cJSON.c`, saved as `tasks.c` to pass the filename filter) | **0.000 similarity** against every known tag — clean negative control, no false positive. |

**Conclusion**: the pipeline works as designed on real data. Exact hashing correctly
identifies untouched vendored copies and their precise version; winnowing similarity
correctly recovers the base version of a genuinely modified fork, with a wide margin
over unrelated code (0.556 vs. 0.000). This validates fingerprint/similarity matching
(general notes: [detection technique patterns](../../../../general/README.md#detection-technique-patterns))
as a viable approach for the "locally modified vendored copy" case, which is the
highest-priority integration pattern per [CLAUDE.md](../../../../CLAUDE.md).

## How to reproduce

```
python build_reference_db.py      # rebuilds reference/kernel_fingerprints.json (~5-10 min, ~300 HTTP fetches)
python match_target.py <path>     # matches a single file or scans a directory for tasks.c/queue.c/list.c
```

No third-party dependencies — pure standard library (`urllib`, `hashlib`, `subprocess`
for `git ls-remote` only).

## Known limitations / next steps

- Only covers the three "core kernel" files, not `portable/<compiler>/<arch>/port.c`,
  which is where a lot of MPU/architecture-specific vulnerabilities (e.g.
  CVE-2024-28115) actually live. Extending the reference DB to port files is a natural
  next step, but port files are compiler/arch-specific, so the reference set would need
  to be indexed by (tag, arch, compiler) rather than just tag.
- Similarity threshold for "is this FreeRTOS at all vs. something else entirely" hasn't
  been calibrated beyond the single negative control tested here — would benefit from
  testing against more unrelated C code (other RTOSes, generic embedded code) to find a
  reasonable confidence cutoff.
- GRAM_SIZE/WINDOW_SIZE (30/50) were chosen from general winnowing literature
  conventions, not tuned specifically for C source or for this file set — worth
  revisiting if false-positive/negative rates show up in a larger test set.
