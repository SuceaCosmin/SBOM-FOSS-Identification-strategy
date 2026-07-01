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
3. `match_target.py` — for each candidate file: check for an exact SHA-256 match against
   every known tag first; if none, fall back to Jaccard similarity between winnowing
   fingerprints and report the closest tags. Candidate files are **grouped by the
   directory they were found in**, since presence of the kernel can't be confirmed from
   a single file alone — a real vendored copy keeps `tasks.c`/`queue.c`/`list.c`
   together. Per group:
   - If not all three are present, the group is reported **INCOMPLETE** — an
     unconfirmed signal, not a positive detection.
   - If all three exact-match releases that share a common tag → **CONFIRMED**.
   - If all three exact-match releases but don't share a common tag → **MIXED VERSION
     WARNING** (e.g. a partial upgrade that replaced only some kernel files).
   - If some files exact-match and others don't → **PARTIALLY MODIFIED**, and it checks
     whether the modified files' closest fuzzy-match release overlaps with the
     unmodified files' exact-match release(s), to report a plausible common base.
   - If none exact-match, compares each file's closest fuzzy-match release for
     agreement (**LIKELY CONSISTENT** vs. **INCONSISTENT**).

Reference DB: `reference/kernel_fingerprints.json` (~4.7 MB, committed — 58 tags,
V8.0.0 through V11.3.0 plus a handful of older ones, three files each).

## Result

Tested against the full three-file sets in [../../corpus/](../../corpus/):

| Target | Result |
|---|---|
| `nxp-mcux-vendored/` (NXP's `FreeRTOS-Kernel` mirror, `release/26.03.00` branch) | All three files exact-match → **CONFIRMED, V11.2.0.** (`list.c` alone ties across V11.1.0–V11.3.0 since it's unchanged over that range; intersecting with `tasks.c`/`queue.c` narrows it to the true version.) Confirms NXP vendors the kernel byte-for-byte (modulo comments/whitespace) unmodified. |
| `esp-idf-fork/` (Espressif's SMP fork, `master` branch) | **PARTIALLY MODIFIED.** `list.c` exact-matches (untouched — ties across V10.5.0–V10.6.2); `tasks.c` and `queue.c` have no exact match. Closest fuzzy matches: `tasks.c` → V10.5.1 (0.556), `queue.c` → V10.6.0 (0.763). Both fall inside `list.c`'s exact-match range, so the tool reports a consistent plausible base of **{V10.5.1, V10.6.0}** — independently confirming what [components/freertos/README.md §3](../../README.md#3-what-layers-typically-stack-on-top-of-the-kernel) already noted from Espressif's own docs (forked from v10.5.1), while also surfacing the real detail that `list.c` wasn't modified at all. |
| `mixed-version-synthetic/` (synthetic: `tasks.c`+`list.c` from V10.4.3, `queue.c` from V11.0.0) | All three files exact-match, but to **disjoint** release sets → **MIXED VERSION WARNING**, correctly identifying the deliberately-mismatched files without a common tag. |
| Unrelated file (`cJSON.c`, saved as `tasks.c`, no matching `queue.c`/`list.c`) | Reported **INCOMPLETE** (correctly refuses to confirm kernel presence from one file) and, even so, scores **0.000 similarity** against every known tag — clean negative control. |

**Conclusion**: the pipeline works as designed on real data, including a real case of
partial modification (ESP-IDF leaving `list.c` untouched) and a case matching a pattern
observed directly in a real project — a FreeRTOS-Kernel integration mixing files from
different releases, which now gets flagged explicitly rather than silently reported as
three unrelated single-file matches. This validates fingerprint/similarity matching
(general notes: [detection technique patterns](../../../../general/README.md#detection-technique-patterns))
as a viable approach for the "locally modified vendored copy" case, which is the
highest-priority integration pattern per [CLAUDE.md](../../../../CLAUDE.md), and confirms
that single-file matching alone is insufficient — component presence and version
identity both require cross-checking all of a component's core files together.

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
- **Open task**: run the matcher against the actual real-world project where a mixed-
  version FreeRTOS integration was originally observed (the synthetic corpus entry
  above reproduces the pattern but isn't the real data). Deferred until those files are
  available to test against directly.
