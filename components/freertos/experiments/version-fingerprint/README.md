# Experiment: version-fingerprinting FreeRTOS-Kernel from source only

> **Scope note (POC, not consolidated):** this experiment establishes that the
> *technique* works; its reference set is intentionally not exhaustive. See the
> repo-wide [maturity caveat](../../../../general/README.md#maturity-caveat-the-fingerprints-here-are-poc-scoped-not-consolidated).
> The DB was widened from 3 to all **7 core kernel `.c` files** (2026-07-23), but still
> covers only source-level core files — **not** the `portable/<compiler>/<arch>/port.c`
> + `mpu_wrappers` layer where architecture/MPU CVEs (e.g. CVE-2024-28115) actually
> live. Consolidating to production coverage (port layer, tuned thresholds) is future
> work.

**Question**: given the core kernel `.c` files in a source tree (no build metadata, no
package manager), can we (a) confirm it's FreeRTOS-Kernel, (b) identify which release it
came from, and (c) tell whether it's been locally modified — using only content-level
analysis, per the pipeline sketched in
[components/freertos/README.md §6](../../README.md#6-detection-implications)?

## Approach

1. `build_reference_db.py` — lists every tag on `FreeRTOS/FreeRTOS-Kernel` via
   `git ls-remote` (no clone needed), then fetches the **7 core kernel `.c` files**
   (`tasks`/`queue`/`list`/`timers`/`event_groups`/`stream_buffer`/`croutine`) per tag
   over HTTPS from `raw.githubusercontent.com`. Of these, `tasks`/`queue`/`list` are the
   **anchors** (they essentially always ship); the rest are optional/feature-gated
   (`croutine` is legacy and frequently omitted), so a target missing them is not
   penalized. Fetches tolerate transient network errors with retry+backoff, and any
   file absent for a given tag is simply skipped. Handles the repo's layout change over
   time: tags from roughly V10.3.0-kernel-only onward have the files at the repo root;
   older tags predate the kernel-only extraction and still carry the old
   `FreeRTOS/Source/...` distribution layout — the fetcher tries both paths. Very old
   pre-2014 tags (V4.x–V7.1.x, plus non-release refs like `BackupPoints`) weren't chased
   further; they're outside the realistic range for anything vendored into a project
   today.
2. `freertos_fingerprint.py` — for each file: strip comments and collapse whitespace
   (`normalize`), then compute both a SHA-256 of the normalized content (exact-match
   fast path) and a **winnowing fingerprint** (Schleimer/Wilkerson/Aiken): hash every
   30-character gram of the normalized text (32-bit blake2b — see "Reference DB size"
   below for why 32-bit), then keep only the minimum hash in each sliding window of 50
   grams (rightmost on ties). The surviving hash set is the fingerprint — small, and
   provably still shares at least one hash with any other file containing a common
   substring of ~79+ normalized characters.
3. `match_target.py` — for each candidate file: check for an exact SHA-256 match against
   every known tag first; if none, fall back to Jaccard similarity between winnowing
   fingerprints and report the closest tags. Candidate files are **grouped by the
   directory they were found in**, since presence of the kernel can't be confirmed from
   a single file alone — a real vendored copy keeps the core files together. Presence is
   gated on the **anchor** files (`tasks`/`queue`/`list`); every *other* core file that
   happens to be present is folded into the cross-file consistency check, tightening the
   version resolution. Per group:
   - If any anchor file is missing, the group is reported **INCOMPLETE** — an
     unconfirmed signal, not a positive detection.
   - If all present core files exact-match releases that share a common tag →
     **CONFIRMED** (more present files ⇒ a narrower, more confident version).
   - If all present core files exact-match releases but don't share a common tag →
     **MIXED VERSION WARNING** (e.g. a partial upgrade that replaced only some kernel
     files).
   - If some files exact-match and others don't → **PARTIALLY MODIFIED**, and it checks
     whether the modified files' closest fuzzy-match release overlaps with the
     unmodified files' exact-match release(s), to report a plausible common base.
   - If none exact-match, compares each file's closest fuzzy-match release for
     agreement (**LIKELY CONSISTENT** vs. **INCONSISTENT**).

Reference DB: `reference/kernel_fingerprints.json` (~1.7 MB, committed — 58 tags,
V8.0.0 through V11.3.0 plus a handful of older ones, **7 core files each** (anchors
present in all 58 tags; `event_groups.c`/`stream_buffer.c` only in the tags that
predate/postdate their introduction — 48/30 tag-slots), **168 unique file-contents**).
It's **pretty-printed** (structure indented one-field-per-line, with the opaque winnow
integer arrays kept inline on a single line each) so it can be browsed by a human — see
`pretty_json()` in `build_reference_db.py`.

## Reference DB size

Widening from 3 to 7 core files roughly doubled the unique-content count (89 → 168);
pretty-printing added ~0.5 MB of structure whitespace (winnow arrays stay inline, so the
cost is newlines/indentation around the object structure, not per-integer). The
compaction techniques below still apply and still leave the file at ~1.7 MB.

An initial 3-file version of this DB was 4.7 MB — a real concern once you're bundling one
of these per supported component for offline use. Two changes, applied together, cut it
substantially with **no change in match results** (re-verified against all corpus
scenarios below):

1. **Deduplicate by content, not by tag.** 49% of (tag, file) entries turned out to be
   byte-identical to another tag's version of that file (patch/rc releases that didn't
   touch that particular file) — see `nxp-mcux-vendored`'s `list.c` below, which ties
   across three releases. The DB now stores one fingerprint per unique
   `(filename, sha256)`, plus a small tag → content-hash index, instead of one full
   fingerprint per tag.
2. **32-bit hashes instead of 64-bit.** `_hash_gram` truncates blake2b to 4 bytes. At
   ~1-2k hashes per file this is nowhere near collision-risk territory (well under 0.1%
   birthday-collision probability), and this isn't a security context — a stray
   collision would nudge a similarity score by a fraction of a percent, never flip a
   verdict.

A further large reduction is possible by switching from JSON decimal integers to packed
binary — not done here, deliberately: the reference DB is kept **plain, pretty-printed
JSON** so it stays inspectable/browsable for a research prototype (per the repo-wide
preference that committed JSON be human-readable). Packed binary is worth doing only if
this format is ever adapted for an actual bundled tool, where transport size beats
inspectability. See
[general/README.md — reference DB scalability](../../../../general/README.md#reference-db-size-scales-with-component-shape-not-a-fixed-constant)
for how this generalizes (or doesn't) beyond FreeRTOS-Kernel.

## Result

Re-validated against the corpus with the widened 7-file DB (2026-07-23) — **all verdicts
unchanged**, confirming no regression from the 3→7 file widening or the anchor-quorum
refactor. The corpus dirs contain only the 3 anchor files, so these exercise the
anchor-presence path; a real full-tree case is shown below the table.

| Target | Result |
|---|---|
| `nxp-mcux-vendored/` (NXP's `FreeRTOS-Kernel` mirror, `release/26.03.00` branch) | All anchor files exact-match → **CONFIRMED, V11.2.0.** (`list.c` alone ties across V11.1.0–V11.3.0 since it's unchanged over that range; intersecting with `tasks.c`/`queue.c` narrows it to the true version.) Confirms NXP vendors the kernel byte-for-byte (modulo comments/whitespace) unmodified. |
| `esp-idf-fork/` (Espressif's SMP fork, `master` branch) | **PARTIALLY MODIFIED.** `list.c` exact-matches (untouched — ties across V10.5.0–V10.6.2); `tasks.c` and `queue.c` have no exact match. Closest fuzzy matches: `tasks.c` → V10.5.1 (0.565), `queue.c` → V10.6.0 (0.762). Both fall inside `list.c`'s exact-match range, so the tool reports a consistent plausible base of **{V10.5.1, V10.6.0}** — independently confirming what [components/freertos/README.md §3](../../README.md#3-what-layers-typically-stack-on-top-of-the-kernel) already noted from Espressif's own docs (forked from v10.5.1), while also surfacing the real detail that `list.c` wasn't modified at all. |
| `mixed-version-synthetic/` (synthetic: `tasks.c`+`list.c` from V10.4.3, `queue.c` from V11.0.0) | All three files exact-match, but to **disjoint** release sets → **MIXED VERSION WARNING**, correctly identifying the deliberately-mismatched files without a common tag. |
| Unrelated file (`cJSON.c`, saved as `tasks.c`, no matching `queue.c`/`list.c`) | Reported **INCOMPLETE** (correctly refuses to confirm kernel presence from one file) and, even so, scores **0.000 similarity** against every known tag — clean negative control. |

**Full 7-file tree (real V11.2.0, all 7 core files present):** every file exact-matches
and the version intersection collapses to exactly **V11.2.0** — where `list.c`/`timers.c`
alone each tie across several releases, the additional files narrow it. This is the
concrete payoff of widening the file set: more present core files ⇒ a tighter, more
confident version, and more independent files to catch a partial/mixed integration.

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

- Covers the 7 core kernel `.c` files but **not** `portable/<compiler>/<arch>/port.c`
  or `mpu_wrappers`, which is where a lot of MPU/architecture-specific vulnerabilities
  (e.g. CVE-2024-28115 — the *one* published FreeRTOS-Kernel GHSA advisory, an ARMv7-M
  MPU privilege-escalation bug) actually live. So today the DB can confirm the kernel
  and its version but **cannot locate the file the kernel's own CVE resides in**.
  Extending to port files is the natural next step, but they're compiler/arch-specific,
  so that reference set must be indexed by (tag, arch, compiler) rather than just tag.
  Explicitly deferred (2026-07-23) per scope decision.
- Nor does it cover the `include/` headers (21 of them) — header-level fingerprints
  would add corroboration and catch header-only integrations, another consolidation item.
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
