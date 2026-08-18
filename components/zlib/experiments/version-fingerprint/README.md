# zlib version fingerprinting — exact hash + winnowing similarity

Phase 2 of the [`research-component`](../../../../.claude/skills/research-component/SKILL.md)
workflow for zlib, run 2026-08-18. Phase 1 findings: [../../README.md](../../README.md).

## The question

Phase 1 concluded zlib is **the first component researched here with no reliable version
anchor** — U-Boot deletes `ZLIB_VERSION` outright and the Linux kernel replaces it with
prose comments. So:

1. Can a version be pinned from **content alone**, with the declared version absent,
   stale, or actively false?
2. Does a **decompression-only subset** (zlib's normal integration shape, ~4 of 8 tracked
   files) still resolve, or does partial presence look like a weak match?
3. Can a heavily **restructured** subset be pinned at all? Phase 1 showed raw line-diff
   distance ranks the Linux kernel's tags but cannot discriminate them (1.2.1/1.2.2/1.2.3
   within 8% of each other). Winnowing has to do better or the technique has a real gap.
4. Does content matching survive the **adversarial** case — zlib-ng, which ships files
   with identical names and an API-compatible header declaring
   `ZLIB_VERSION "1.3.1.zlib-ng"` over a complete rewrite?

## Result

**All four answered, and one of them overturned a phase-1 conclusion.**

| corpus tree | ground truth | verdict | resolved |
|---|---|---|---|
| `verbatim-1.2.11` | upstream 1.2.11 | **CONFIRMED** | 1.2.11 |
| `subset-inflate-only-synthetic` | inflate side of 1.2.13 | **CONFIRMED** | 1.2.13 |
| `chromium-third-party-zlib` | post-1.3.2 untagged commit | **LIKELY_CONSISTENT** | 1.3.2 |
| `uboot-lib-zlib` | pppd-patched, two-era | **INCONSISTENT** | deflate ≈1.2.5, inflate ≈1.2.2–1.2.3 |
| `linux-kernel-zlib` | inflate 1.2.3 + deflate 1.1.3 | **INCONSISTENT** | deflate ≈1.1.4, inflate ≈1.2.3.x |
| `mixed-version-synthetic` | inflate 1.2.13 + deflate 1.2.8 | **MIXED_VERSION** | both sides named exactly |
| `zlib-ng-adversarial` | not zlib | **NOT_THIS_COMPONENT** | — (best file 0.250) |
| `negative-control-cjson` | not zlib | **NOT_THIS_COMPONENT** | — (all files 0.000) |

Ground truth is correct in all eight cases. Details and the three findings that generalise
follow.

> The corpus later gained two more trees (`dist-1.2.13-core-only` and
> `dist-1.2.13-with-contrib`) for **phase 3**, where sub-component presence had to be
> tested. They are irrelevant here — identical in version and in every tracked file, both
> CONFIRMED 1.2.13 — and are described in [corpus/README.md](../../corpus/README.md).

## Phase 1's "no version anchor" conclusion was half wrong — zlib hides it in string literals

The discrimination measurement (below) put `inftrees.c` and `deflate.c` at **55 distinct
contents across 55 releases** — every single release separable. Code churn does not explain
that. The cause:

```c
const char inflate_copyright[] =
   " inflate 1.3.2 Copyright 1995-2026 Mark Adler ";      /* inftrees.c */
const char deflate_copyright[] =
   " deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly and Mark Adler ";  /* deflate.c */
```

These are **string literals, not comments**, so they survive `normalize()`'s comment
stripping and land in the fingerprint. zlib carries its version *inside two `.c` files*,
not only in the header the carriers delete. Phase 1 looked for `ZLIB_VERSION` in headers,
found it gone, and concluded the anchor was absent; it was in the sources all along.

Which carriers keep it, checked directly:

| carrier | `inflate_copyright` | `deflate_copyright` | `ZLIB_VERSION` |
|---|---|---|---|
| upstream | ✔ | ✔ | ✔ |
| Chromium | ✔ `1.3.2.1` | ✔ `1.3.2.1` | ✔ `1.3.2.1-motley` |
| U-Boot | ✘ (deleted) | ✔ `1.2.5` | ✘ (deleted) |
| Linux kernel | ✘ (deleted) | ✘ (deleted) | ✘ (prose comment only) |
| zlib-ng | ✘ (never had one) | ✘ | ✔ `1.3.1.zlib-ng` (false) |

The corrected statement is narrower and more useful than either the phase-1 version or its
opposite: **zlib has three independent version declarations and no carrier keeps all
three; two carriers keep none.** The matcher therefore extracts all of them via
`declared_versions()` and prints them *beside* the content verdict, flagging disagreement —
never using them to resolve it. That is the confirm-only metadata tier of CLAUDE.md's
technique list, kept visibly separate rather than merged in.

It pays off immediately: on the mixed-version tree the declared strings independently
corroborate the content answer (`deflate_copyright=1.2.8`, `inflate_copyright=1.2.13`),
while on zlib-ng the sole declaration is a lie the content verdict overrides.

## Picking the tracked files

Measured first, chosen second — distinct normalized contents across the 55 in-scope
release tags (`v1.1.3` … `v1.3.2`):

| file | distinct | present | file | distinct | present |
|---|---|---|---|---|---|
| **`zlib.h`** | **55** | 55 | `deflate.h` | 17 | 55 |
| **`inftrees.c`** | **55** | 55 | **`inffast.c`** | **15** | 55 |
| **`deflate.c`** | **55** | 55 | `adler32.c` | 12 | 55 |
| `zconf.h` | 37 | 54 | `compress.c` | 9 | 55 |
| `zutil.h` | 33 | 55 | `inflate.h` | 9 | 53 |
| **`inflate.c`** | **27** | 55 | `uncompr.c` | 8 | 55 |
| `gzlib.c` | 23 | 31 | `inftrees.h` | 8 | 55 |
| **`trees.c`** | **21** | 55 | `inffast.h` | 4 | 55 |
| **`zutil.c`** | **20** | 55 | `crc32.h` | 4 | 53 |
| **`crc32.c`** | **20** | 55 | `gzclose.c` | 4 | 31 |

The 8 in bold are tracked. Selection reasoning:

- **`inftrees.c` is the star.** Top discrimination (55/55, via `inflate_copyright`),
  present in *every* copy including decompression-only subsets, and the file real forks
  barely touch — Chromium changes 4 lines in it against v1.3.2. It is simultaneously the
  best discriminator and the best modification-survivor, which is a stronger position than
  lwIP's `pbuf.c` (untouched but only 8/11 discriminating).
- **`deflate.c`** matches it on the compression side (55/55, `deflate_copyright`).
- **The set is deliberately split across zlib's two halves**, because subset vendoring is
  the normal case: `inftrees.c`/`inflate.c`/`inffast.c`/`zutil.c` are present in
  decompression-only copies; `deflate.c`/`trees.c`/`crc32.c` are not.
- **`zlib.h` is tracked to observe it, not to trust it** — see the table above.
- Deliberately excluded: `zconf.h` (37) and `zutil.h` (33) score well but are the two
  files most often hand-edited for a target platform, so their discrimination is real
  upstream and misleading in the field. `gz*.c` (23/20/18) only exist from 1.2.4 and are
  absent from every embedded carrier examined.

Deliberately narrow research scope — 8 of ~30 root sources — not a claim that these are
*the* minimal signature files for zlib.

## Reference DB size

55 release tags, 8 tracked files → **1.4 MiB**, 268 unique file-contents. Measured, per
[general/README.md](../../../../general/README.md#reference-db-size-scales-with-component-shape-not-a-fixed-constant).

The shape driver here is **release count × file size**, not file count: zlib has few files
but 55 in-scope releases (four-component development releases included — each has a dated
`ChangeLog` entry, so they are real releases, not junk refs) and `deflate.c`/`zlib.h` are
large. Compare lwIP: 7 files × 17 releases → 792 KiB. Per tracked-file-version zlib is
roughly comparable; the total is larger because the release axis is 3× longer.

## Restructured subsets: winnowing succeeds where line-diff distance failed

Phase 1's line-diff sweep on the Linux kernel's `inflate.c` ranked v1.2.2 (812 changed
lines) marginally ahead of the claimed v1.2.3 (878) — an 8% spread across three candidate
tags, i.e. no real discrimination. Winnowing, per half:

```
linux-kernel-zlib
  deflate  deflate.c~v1.1.4@0.35
  inflate  inftrees.c~v1.2.3.1@0.81, inffast.c~v1.2.3.2@0.35, inflate.c~v1.2.2@0.28
```

`inftrees.c` — the file the kernel restructured least — lands on **v1.2.3.x at 0.81**,
and the deflate side lands in the **1.1.x** era. That reproduces, from content alone, the
split the kernel states in prose in `include/linux/zlib.h`:

```c
/* zlib deflate based on ZLIB_VERSION "1.1.3" */
/* zlib inflate based on ZLIB_VERSION "1.2.3" */
```

The declaration was never fed to the matcher (the kernel deleted every machine-readable
version macro). So: **on a heavily restructured subset, one well-chosen low-churn file
carries the version signal that the heavily-rewritten files have lost.** That is the
argument for choosing tracked files by measured modification-survival, not by prominence —
`inflate.c` is the obvious "main" file and it is the one that scored worst (0.28).

## U-Boot: the experiment found a discrepancy the vendor's own comment doesn't mention

```
uboot-lib-zlib
  deflate  deflate.c~v1.2.5@0.92, trees.c~v1.2.5.2@0.90
  inflate  inftrees.c~v1.2.3.1@0.72, inffast.c~v1.2.9@0.68, inflate.c~v1.2.2.2@0.57, zutil.c~v1.2.0.1@0.09
  declared: deflate_copyright[] in deflate.c = 1.2.5
```

U-Boot's header comment says the tree is *"derived from ... the zlib-1.2.3 distribution"*.
The deflate side fingerprints to **1.2.5 at 0.90–0.92** — high confidence — and its own
surviving `deflate_copyright` string independently says **1.2.5**. The inflate side sits
around 1.2.2–1.2.3, consistent with the comment.

So U-Boot is a **two-era tree whose prose provenance names only one era**, and the later
one is undocumented. This was not visible in phase 1 (the diff sweep only examined
`inflate.c`, the half the comment describes correctly) and it is not visible from any
declared metadata alone. Two independent signals — winnowing similarity and a surviving
string literal — agree against the prose.

This is now the third component where a shipped tree contradicts its own version
declarations, after mbedTLS's Wi-SUN case (four sources, four answers) and lwIP's phantom
tag. The pattern is consistent enough to treat as an expectation rather than a surprise.

**`INCONSISTENT` was hiding this.** The flat verdict listed seven disagreeing tags with no
structure. `group_consensus()` was added to report **per half**, because two of the three
real forks in this corpus turned out to be two-era trees. The verdict vocabulary keeps the
honest top-level answer (INCONSISTENT — there is no single version) while the per-half
breakdown carries the part a reader can act on.

## Calibrating the reject rule — the template's per-file veto is the wrong shape

The skill template, and every component here before zlib, rejected a tree with a per-file
**veto**: if *any* tracked file scored below `NO_SIMILARITY_FLOOR = 0.05`, the whole tree
became `NOT_THIS_COMPONENT`. This corpus shows that rule is unsound. Measured per-file
bests:

| tree | per-file best scores |
|---|---|
| `uboot-lib-zlib` (**genuine**) | 0.09, 0.21, 0.57, 0.68, 0.72, 0.90, 0.92 |
| `linux-kernel-zlib` (**genuine**) | 0.12, 0.28, 0.35, 0.35, 0.81 |
| `zlib-ng-adversarial` (**not zlib**) | 0.00, 0.10, 0.12, 0.14, 0.19, 0.23, 0.25 |
| `negative-control-cjson` (**not zlib**) | 0.00 × 8 |

The genuine forks' per-file scores and the reimplementation's **overlap across 0.00–0.25**.
No per-file threshold separates them. U-Boot survived the old veto only because its worst
file (`zutil.c`, 0.094) landed 0.04 above the floor — a real vendor fork within a rounding
error of being reported as "not zlib".

What *does* separate them cleanly is the tree **maximum**: 0.92 and 0.81 for the genuine
forks against 0.25 for the reimplementation. So the rule was replaced with positive
evidence — `POSITIVE_EVIDENCE_CEILING = 0.40`, sitting mid-gap — requiring at least one
tracked file to actually look like zlib. A rewritten or missing file is then weak evidence,
never a veto. All eight ground truths still resolve correctly after the change.

Two consequences worth carrying forward:

- **Absence of similarity in one file is not evidence of absence of the component.** The
  reverse framing (a low-scoring file counts *against* the tree) is what the old rule
  encoded, and a heavily-patched vendor fork violates it routinely.
- **This is a calibrated data point for the resolver evidence rule** queued in
  `CLAUDE.md`. That work was motivated by the opposite failure — one file matching in a
  309-file lwIP tree produced a confident whole-tree claim. zlib supplies the other end:
  a genuine tree where most files match *badly*. Both point the same way — the verdict
  must be driven by how much positive evidence exists and how it is distributed, not by a
  per-file pass/fail on either side.

## Chromium: a declared version that names a release the content isn't

Content resolves cleanly to **1.3.2** (every file's top candidate, 0.81–0.99).
`README.chromium` also declares `Version: 1.3.2` and `CPEPrefix: cpe:/a:zlib:zlib:1.3.2`.
But the in-source strings say **1.3.2.1**, and `README.chromium`'s declared
`Revision: 09a1572aa624e5ddb6c075dc013880de70b1b9b9` is a real upstream commit from
**2026-02-21 — four days after v1.3.2, and contained in no tag** (`git tag --contains`
returns nothing). It carries a post-release `inflateBack()` fix.

So the tree is an **untagged post-release development snapshot**, and a tag-mined reference
DB is structurally unable to name it: 1.3.2 is the closest true statement available, and
it is not exactly right. The matcher reports `LIKELY_CONSISTENT -> 1.3.2` rather than
`CONFIRMED`, which is the correct epistemic status — but nothing in the output says *why*
it can't be confirmed.

This is the "origin outside coverage" verdict from the
[nested-component work](../../../../general/experiments/nested-component-attribution/README.md)
arriving for an ordinary, fully-covered component, simply because the carrier tracks a
branch instead of tags. It strengthens the case for architecture rec. 14 (mine artifacts
and commits, not only tags) and is directly consequential for phase 3: querying NVD for
1.3.2 would *under-report* the tree's fixes, and any CVE fixed in that untagged window
would be reported as present when it isn't.

## Known limitations / next steps

- **`crc32.c` is absent from both key embedded carriers** (U-Boot's and the kernel's
  inflate-only trees), so it contributes only to fuller copies. Kept for its 1.2.12 rewrite
  boundary, but it is the weakest member of the set.
- **`Z_PREFIX` is untested here and needs no test at this tier** — it is a `zconf.h` macro
  table that leaves `.c` files untouched (component README §5). It matters for the
  symbol-set tier, not this one.
- **`contrib/minizip` is not tracked.** Phase 1 found `CVE-2023-45853` binds a MiniZip
  flaw to the zlib CPE, so "was minizip vendored?" is a *detection* question with direct
  advisory consequences. It needs its own tracked-file set, not a zlib version window.
- **Untagged-snapshot carriers** (Chromium) can only ever resolve to the nearest release.
  Mining commits rather than tags would fix it; out of scope here, recorded for the
  architecture handoff.
- **The 0.40 ceiling is calibrated on one component's corpus.** The 0.25 → 0.81 gap is
  wide, but a second API-compatible reimplementation (e.g. `miniz`) would test it properly.
- Winnowing parameters are the shared template defaults (30-char grams, 50-gram windows);
  no zlib-specific tuning was attempted, and the repo-wide
  [POC-scope caveat](../../../../general/README.md#maturity-caveat-the-fingerprints-here-are-poc-scoped-not-consolidated)
  applies.

## Files

- `zlib_fingerprint.py` — normalization, exact hashing, winnowing (shared template,
  unmodified).
- `build_reference_db.py` — mines `v1.1.3`…`v1.3.2` from a local clone into
  `reference/zlib_fingerprints.json`.
- `match_target.py` — matcher. zlib-specific: score-based resolution of duplicate
  basenames (flat upstream layout), integration-shape reporting, per-half consensus,
  declared-version extraction, positive-evidence reject rule.
- `../../corpus/` — 8 trees with ground truth; see [corpus/README.md](../../corpus/README.md).

## Reproducing

```
python build_reference_db.py            # clones madler/zlib, ~2 min
python match_target.py ../../corpus/uboot-lib-zlib
```
