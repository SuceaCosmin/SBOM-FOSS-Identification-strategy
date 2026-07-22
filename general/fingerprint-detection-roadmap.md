# Fingerprint / detection-technique roadmap

A catalogue of **every fingerprint-based detection technique** relevant to this
repo's problem (identifying vendored/copy-pasted C FOSS in embedded source and
static-library bundles), marking which are already built/validated here and which
are not yet covered. The uncovered ones are **low-priority TODOs** — logged so we
don't forget the design space, not scheduled ahead of the current in-progress work
(the static-lib symbol tier and its integration; see [CLAUDE.md](../CLAUDE.md)
"Current status").

This is the *technique* roadmap. The list of *components* to research lives
separately in [component-roadmap.md](component-roadmap.md); the reusable-dataset
survey is [existing-fingerprint-datasets.md](existing-fingerprint-datasets.md).

## Why enumerate techniques at all

Each technique is a distinct **evidence producer** keyed on a different property of
the artifact (raw bytes, token stream, program structure, API surface, embedded
data, binary code). They fail on different transformations, so they're additive,
not redundant — a robust detector runs several tiers and fuses them. The
architectural consequences of treating them as swappable, individually-selectable
producers are written up in
[sbom-generator-architecture.md](sbom-generator-architecture.md); this doc is the
menu that document's "selectable criteria" idea draws from.

## Status matrix

Legend — **Covered**: built and validated in this repo. **Partial**: used but not
developed as a first-class tier. **TODO**: not covered, logged below with a
priority. **Parked**: real but deliberately deferred (legal or out-of-corpus).

| # | Technique | Unit fingerprinted | Survives… | Defeated by… | Cost | Status |
|---|---|---|---|---|---|---|
| 1 | Exact / normalized file-content hash | whole file (MD5, comment-stripped) | verbatim vendoring, reformatting (normalized variant) | any in-file edit (exact); heavy edits (normalized) | very low | **Covered** |
| 2 | Token-level winnowing (SCANOSS `wfp`) | rolling k-gram of normalized tokens | partial edits, snippet reuse, file splits | identifier renames, structural rewrites | low | **Covered** |
| 3 | File-set / tag-set presence + cross-file version consistency | *which* files/versions co-occur | per-file edits (set membership is robust) | single-file drops, amalgamation | low | **Covered** |
| 4 | Symbol-set (defined globals of a `.a`; mineable from headers) | exported API surface | compiler/toolchain choice, reformatting, renamed *statics* | stripping, `static`-inlining, LTO | low | **Covered** |
| 5 | Archive/member-name metadata (`ar` member table) | source filenames in `.o` members | recompilation (names persist) | renamed/merged objects, stripped names | very low | **Covered** |
| 6 | Metadata/string heuristics (version macros, license headers, embedded `"Vx.y.z"`) | literal strings / macros | light edits (constants often untouched) | short literals compiled into immediates (confirm-only) | very low | **Partial** |
| 7 | Vendor manifest / embedded-SBOM harvest (`sbom.spdx`, `manifest.yml`, TI manifest) | declared metadata + per-file hashes | n/a (declared data) | absent/stale/wrong manifests | very low | **Partial** (corroboration tier) |
| 8 | AST / structure-normalized fingerprint (tree-sitter, hashed normalized subtrees) | program structure | **renamed identifiers + reformatting** | large structural rewrites | medium | **TODO — highest** |
| 9 | Constant / data-table fingerprint (S-boxes, round constants, CRC/zlib tables) | embedded data | renaming, reformatting, **stripping** | table-free components; table edits | medium | **TODO — high** |
| 10 | Function-level normalized hashing (CENTRIS model) | per-function body | partial component copies, per-function edits | whole-function rewrites | medium | **TODO — medium** |
| 11 | Fuzzy whole-file hash (TLSH / ssdeep / sdhash) | whole-blob similarity | moderate edits | no line-level localization; coarser than #2 | low | **TODO — low** |
| 12 | MinHash sketches over normalized tokens | token-set similarity | partial edits | ~equivalent to #2, not additive | low | **TODO — low** |
| 13 | Binary control-flow / semantic similarity (Ghidra BSim, FunctionSimSearch, CFG hashing) | disassembled function structure | **stripping, LTO** | obfuscation; **legal (no-disassembly clauses)** | high | **Parked** |

## Covered tiers — where they live

- **#1 / #2 / #3** — the source-side backbone. Validated across FreeRTOS, mbedTLS,
  CMSIS via the bespoke per-component matchers and the self-mined SCANOSS KB;
  exported into the lightweight artifact's `files` (exact) and `wfp` (winnowing)
  sections. See [experiments/minr-self-mining](experiments/minr-self-mining/README.md)
  and the per-component `experiments/version-fingerprint/` folders.
- **#4 / #5** — the static-library tier. Built and validated 2026-07-21/22 in
  [experiments/static-lib-identification](experiments/static-lib-identification/README.md)
  (symbol-set extractor + source-mined reference DBs + subset-tolerant window
  matcher; member-name reading as the cheap first pass). Note #4's reference sets
  are **mined from source headers**, so the same tier detects a headers-only drop
  (no `.c`, no `.a`) for free. As of 2026-07-22 #4 is **folded into the
  lightweight-export artifact** as a tier-labeled `tiers.symbol` producer
  alongside the exact (#1) and winnowing (#2) tiers, resolving through the same
  canonical `releases` table — see
  [experiments/minr-self-mining](experiments/minr-self-mining/README.md#tier-labeled-artifact--symbol-tier-fold-in-schema-2-2026-07-22).
- **#6 / #7** — used as fast corroboration layers. #6 is documented under
  "Detection technique patterns" in [README.md](README.md) (in-source version
  strings survive modification; copyright-header era as a coarse signal) and as the
  "confirm-only" strings finding in the static-lib doc. #7 is the vendor-manifest
  harvest finding in the static-lib doc (harvest as input; treat
  manifest-vs-detected discrepancies as an output, never as ground truth).

Both #6 and #7 are marked **Partial** because they're consumed opportunistically,
not developed into a systematic tier — a deliberate choice, not a gap to close.

## Not-yet-covered tiers — low-priority TODOs

Ordered by expected value against this repo's #1 priority (locally-modified copies
with renamed identifiers and reformatting). None is scheduled ahead of the current
static-lib integration + OSV.dev work; pick one up only when a component or artifact
makes it suddenly relevant, or when there's slack.

### TODO-8 (highest): AST / structure-normalized fingerprinting

The direct answer to the priority-#1 transformation that token-winnowing (#2) only
half-handles: identifier renaming. Parse C with a real grammar (tree-sitter has a
mature C grammar), normalize identifiers and literals to placeholders, hash
subtrees or normalized statement sequences. Robust to renaming, reformatting, and
comment churn simultaneously. CLAUDE.md already names "AST-level fingerprints" as an
aspiration in "Detection approaches under research" — this is that line, unbuilt.
**Effort**: medium (parser integration + a normalization/hashing scheme + a small
reference-mining pass). **Trigger to pick up**: a real modified-fork case where
winnowing recall proves insufficient (none has forced it yet — vendor forks seen so
far kept enough verbatim content for #1–#3).

### TODO-9 (high): constant / data-table fingerprinting

A fundamentally different axis from every covered tier: fingerprint the *data*, not
the API/text/bytes — crypto S-boxes, SHA/AES round constants, elliptic-curve
parameters, CRC and zlib/Huffman tables, protocol magic numbers. Two properties make
it valuable: (a) invariant under identifier renaming and reformatting on the source
side, and (b) it survives *into `.rodata` even when a binary is stripped of
symbols* — i.e. it's the binary tier that works exactly where the symbol tier (#4)
goes blind. Strongest for crypto/compression components, which dominate the SDKs
we're targeting (mbedTLS et al.). Complements #4 rather than overlapping it.
**Effort**: medium (curate per-component constant sets; a `.rodata`/source scanner).
**Trigger**: the first stripped static library, or a crypto component where symbol
windows are too coarse.

### TODO-10 (medium): function-level normalized hashing (CENTRIS model)

Middle granularity between whole-file (#1) and token-winnowing (#2): hash each
normalized function body. Detects a component when only some functions were copied
and/or modified, and its unit aligns with the symbol tier (#4). Already surveyed as
a *technique* (not an operational dataset) in
[existing-fingerprint-datasets.md](existing-fingerprint-datasets.md) (CENTRIS,
ICSE 2021; Tiver, ICSE 2025). Overlaps more with existing tiers than TODO-8/9 do, so
lower value now. **Effort**: medium. **Trigger**: partial/amalgamated-copy cases
that #1–#3 miss.

### TODO-11 / TODO-12 (low): fuzzy whole-file hashing / MinHash

Logged for completeness. TLSH/ssdeep/sdhash give whole-blob similarity without
winnowing infrastructure, but coarser than #2 and with no line-level localization —
a potential cheap pre-filter at best. MinHash sketches over normalized tokens are
roughly equivalent to winnowing (#2), not additive. Both are **low priority**:
likely a downgrade or a lateral move relative to what's already built. Revisit only
if a performance profile shows #2 is too expensive as a first-pass filter.

## Parked (real, deliberately deferred)

### Binary control-flow / semantic similarity (#13)

Ghidra BSim, FunctionSimSearch, basic-block/CFG hashing — the hard tier for
**stripped/LTO** binaries where the symbol tier (#4) yields nothing. Parked for two
independent reasons, both documented in
[experiments/static-lib-identification](experiments/static-lib-identification/README.md):
(1) **legal** — it requires disassembly/decompilation, which some vendor licenses
forbid outright (the TI `ecc` no-disassembly clause); the clean tier boundary is
"metadata inspection vs. disassembly," and a real scanner should default to
metadata-only and gate this behind explicit per-artifact opt-in; (2) **out of
corpus** — no static library encountered so far is stripped (symbols and member
names are present), so nothing exercises it. Pick up only when a real stripped
artifact appears *and* the legal context permits.

## Relationship to the architecture doc

The "each technique is an independent, individually-selectable evidence producer"
framing — and the per-finding provenance / scan-profile / legal-tier-boundary
consequences — are in
[sbom-generator-architecture.md](sbom-generator-architecture.md). Keep the two in
sync: a new tier added here should appear there as a selectable producer, and the
legal boundary (metadata tiers 1–7 vs. disassembly tier 13) is the same line both
docs draw.
