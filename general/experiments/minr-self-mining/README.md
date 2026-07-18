# Self-mining with SCANOSS `minr` — baseline experiment

Open item 4 of [existing-fingerprint-datasets.md](../../existing-fingerprint-datasets.md):
after the 2026-07-16 decision made curated attribution-by-construction the backbone,
`minr` is the candidate tool for *industrializing* it — mining the supported component
list into a self-hosted LDB knowledge base instead of hand-building per-component
reference DBs.

## Questions this experiment answers

1. **Attribution by construction — does it actually hold?** `minr -d` takes the
   metadata we declare (`vendor,component,version,date,license,purl`) at mine time.
   Does the `scanoss` engine, querying the resulting KB, report exactly that identity
   (correct purl, correct version, correct license) for our ground-truth corpus —
   eliminating the arbitrary-containing-repo problem observed against the public OSSKB?
2. **Match quality vs the bespoke DBs**: on the same corpus, does the self-mined KB
   reproduce what
   [components/freertos/experiments/version-fingerprint](../../../components/freertos/experiments/version-fingerprint/README.md)
   established — exact version pinning for verbatim copies (NXP → V11.2.0), snippet-level
   detection with a sensible version window for the modified fork (esp-idf → ~V10.5.1),
   per-file version splits for the synthetic mixed-version tree?
3. **Operational cost**: wall-clock mining time, KB size on disk, and effort per
   release — the inputs to the company-scale feasibility math.
4. **License boundary**: confirm the whole stack (ldb, minr, engine — all GPL-2.0)
   runs as separate processes in a container, touched only via CLI + JSON, i.e. the
   process-boundary pattern the (differently-licensed) generator repo needs.

## Setup

- `Dockerfile` — Debian bookworm building [ldb](https://github.com/scanoss/ldb),
  [minr](https://github.com/scanoss/minr), [engine](https://github.com/scanoss/engine)
  from source. Built 2026-07-18 from default branches: ldb `bb1b7b6`, minr `18dccd1`,
  engine `58596e1` (`scanoss-5.4.27`).
- `mine_freertos.sh` / `mine_mbedtls.sh` / `mine_cmsis.sh` — run inside the
  container; mine release tags (13 FreeRTOS-Kernel: V10.4.3–V11.2.0; 12 mbedTLS:
  v2.28.8–v3.6.6; 7 CMSIS across the CMSIS_5/CMSIS_6 repo split) from GitHub archive
  zips with per-release declared metadata, then import into `/var/lib/ldb/oss`.
- Scan targets: the existing ground-truth corpus at
  [components/freertos/corpus](../../../components/freertos/corpus/README.md)
  (esp-idf modified fork ≈ V10.5.1, NXP verbatim V11.2.0, synthetic V10.4.3+V11.0.0 mix),
  volume-mounted read-only into the container.
- `results/<component>/` — the raw `scanoss` JSON output per corpus tree, as scanned
  2026-07-18 against the self-mined KB (pretty-printed per repo convention).

## Operational gotchas found so far

- `ldb`/`minr` `make install` runs `chown $SUDO_USER ...`, assuming an interactive
  sudo build — fails in Docker where `SUDO_USER` is unset. Worked around with
  `ENV SUDO_USER=root` in the Dockerfile.
- `minr -i` requires a `version.json` (`{"monthly":"YY.MM", "daily":"YY.MM.DD"}`)
  inside the mined dir, and **wipes the mined dir after import** — mining output is
  not an artifact you keep, the LDB is.
- minr ships its own walkthrough of exactly this local-KB scenario
  (`examples/local-kb/` in the minr repo), added ~Jan 2025 — the flow here mirrors it.
- minr hard-checks for `/usr/bin/unrar` at startup and exits if absent; Debian only
  packages non-free unrar. `unrar-free` + a symlink satisfies it (we never mine `.rar`).
- `scanoss/engine`'s default branch is `main` while ldb/minr use `master` — trivial,
  but it broke the first scripted build.

## Reproducing the artifact (`results/export.json.gz` — gitignored, regenerable)

The 48 MB export artifact is deliberately **not** committed; this exact chain
rebuilds it from nothing but this folder + upstream GitHub (all steps ran
2026-07-18 on Docker Desktop/WSL2; `<repo>` = this repository's root):

```sh
# 1. Build the GPL stack container (ldb/minr/engine from source)
docker build -t scanoss-stack general/experiments/minr-self-mining/

# 2. Mine all three components into a persistent KB volume (~11 min total)
for c in freertos mbedtls cmsis; do
  docker run --rm -v scanoss-ldb:/var/lib/ldb -v "<repo>:/repo:ro" scanoss-stack \
    bash /repo/general/experiments/minr-self-mining/mine_$c.sh
done

# 3. Collapse LDB's zero-filled map preallocation (103 GB-class -> ~2 GB)
docker run --rm -v scanoss-ldb:/var/lib/ldb scanoss-stack \
  find /var/lib/ldb/oss -name "*.ldb" -exec fallocate -d {} \;

# 4. Export the lightweight artifact (~9 min, clean-room reader, no GPL)
docker run --rm -v scanoss-ldb:/var/lib/ldb:ro -v "<repo>:/repo" python:3.12-slim \
  python /repo/general/experiments/minr-self-mining/export_lightweight.py \
  /var/lib/ldb/oss /repo/general/experiments/minr-self-mining/results/export.json.gz

# 5. Validate against the ground-truth corpus (host: python + scanoss-py)
python general/experiments/minr-self-mining/validate_export.py \
  general/experiments/minr-self-mining/results/export.json.gz \
  components/freertos/corpus/* components/mbedtls/corpus/* components/cmsis/corpus/*
```

Caveat on bit-exactness: re-mining pulls whatever the GitHub tag archives serve
*today*, so a rebuilt artifact is content-equivalent but not guaranteed
byte-identical to the 2026-07-18 one (and release tags could in principle move).
The scan *results* in `results/*/` are committed, so any regeneration can be
diffed against the recorded ground-truth outcomes.

## Results (FreeRTOS baseline, 2026-07-18)

### 1. Attribution by construction: confirmed

Every match, on every corpus tree, reported exactly the declared identity —
`pkg:github/freertos/freertos-kernel`, component `FreeRTOS-Kernel`, license `MIT`.
The `url` table stores the `-d` metadata verbatim (checked with the ldb shell):

```
04ab3b01...: FreeRTOS,FreeRTOS-Kernel,11.0.0,2023-12-18,MIT,pkg:github/freertos/freertos-kernel,https://github.com/FreeRTOS/FreeRTOS-Kernel/archive/refs/tags/V11.0.0.zip
```

The arbitrary-containing-repo failure mode observed against the public OSSKB is
structurally impossible in a curated self-mined KB — there is nothing else in it for
a file to be attributed to. (Corollary: files *outside* the curated list simply
return no match; the recall net for those remains the CC0 tables, per the
2026-07-16 decision.)

### 2. Match quality vs the bespoke reference DBs

| Corpus tree | Ground truth | `scanoss` result |
|---|---|---|
| `nxp-mcux-vendored` | verbatim V11.2.0 | all 3 files `id=file` 100%, version **11.2.0** — exact |
| `mixed-version-synthetic` | tasks/list V10.4.3 + queue V11.0.0 | `id=file` 100% each; split reported **exactly** (10.4.3 / 11.0.0 / 10.4.3) |
| `esp-idf-fork` | SMP-modified fork of V10.5.1; `list.c` functionally untouched | all 3 detected as `id=snippet` (93–99% matched, correct line maps); versions pinned to **10.5.0 / 10.4.3 / 10.4.4** |

Two deviations from the bespoke experiment, both instructive:

- **Raw-MD5 file matching is fragile to header-comment edits.** Espressif's `list.c`
  is code-identical to stock V10.5.0–V10.6.2 but its first comment line reads
  `FreeRTOS Kernel V10.5.1 (ESP-IDF SMP modified)` — so the exact-file path (raw MD5)
  misses, and the engine falls back to snippet matching (98%, correct component).
  The bespoke experiment's *normalized* (comment-stripped) hashing exact-matched this
  file. Same failure class as the ST/mbedTLS license-header edit finding: any
  raw-hash tier needs a normalized-hash tier behind it.
- **Version pinning on modified files reports a single nearest release, not a
  window.** For the heavily modified `tasks.c`/`queue.c` the engine names one
  version (10.4.4 / 10.4.3) where the true fork base is 10.5.1 — kernel files barely
  change between those releases, so snippet voting lands on a near-neighbor and
  reports it as a point answer. The bespoke matcher's explicit version-*window*
  output (with a cross-file consistency check) is more honest for SBOM purposes.
  Post-processing engine output would need to re-widen the answer (e.g. from
  `file_hash`-equivalent releases), or keep the bespoke matcher for version
  assignment. (Ironically the file's own header says `V10.5.1` — the
  metadata/string-heuristics tier would pin this one exactly.)

### 3. Operational cost (13 releases, one component)

- **Mining + snippet mining + LDB import: 5m24s wall** (single container, includes
  downloading 13 GitHub zips; CPU time ~1m12s user + 3m28s sys — import is I/O-bound).
- **Scanning: 3.2 s** for all 9 corpus files, offline, against the local KB.
- **Disk: 103 GB as created — 408 MB after hole-punching (resolved 2026-07-18).**
  The 103 GB is LDB's **fixed floor**, not data: every populated table preallocates
  256 sector files, and each sector file *starts* with a zero-filled lookup map of
  256³ slots × 5-byte pointers ≈ 84 MB (the same layout reverse-engineered in
  [osskb-open-dataset](../osskb-open-dataset/README.md)) — ~21 GB/table × 5
  populated tables (`file`, `wfp`, `license`, `copyright`, `quality`), while the
  actual mined content (`sources` .mz archives) is **28 MB**. At our fill rate the
  maps are ~99.97% zeros, so `fallocate --dig-holes` on the `.ldb` files collapsed
  allocated disk **103 GB → 408 MB**, verified non-destructive: the ldb shell
  returns the same records and a full `scanoss` corpus re-scan gives identical
  results. Caveats: the floor is per *populated table* (skipping the
  `quality`/`copyright` CSVs before `minr -i` would halve it at creation time);
  apparent size stays 103 GB, so any copy/backup must be sparse-aware
  (`cp --sparse=always`, `tar -S`, `rsync -S`); and a fresh `minr -i` rewrites full
  maps for new tables, so re-punch after each import batch.
- minr also auto-populated `license`, `copyright`, `quality`, `attribution` tables
  from local detection — declared license and detected license are both available.

### KB anatomy — what one release looks like inside the LDB

Walked by hand with the `ldb` shell for FreeRTOS-Kernel V11.2.0 / its `list.c`
(all tables live under `/var/lib/ldb/oss/`; layouts match what
[osskb-open-dataset](../osskb-open-dataset/README.md) reverse-engineered from the
CC0 export, plus the metadata tables that export drops):

```
url        key 4444449c13b422154140ad4a1c1ac669   (internal release/archive id)
           = FreeRTOS,FreeRTOS-Kernel,11.2.0,2025-03-04,MIT,
             pkg:github/freertos/freertos-kernel,
             https://github.com/FreeRTOS/FreeRTOS-Kernel/archive/refs/tags/V11.2.0.zip
                       ▲ the -d metadata verbatim — the identity anchor

file       key 5cd6e29ee7e76170879e6bb3add95280   (md5 of list.c's bytes)
           = [4444449c…(16 raw bytes: url-id)][list.c]
             scanned-file md5 → url-id → declared purl/version/license:
             this two-hop chain IS attribution-by-construction

license    same md5 key = "1,MIT"                 (minr's own header detection —
copyright  same md5 key = "1,Copyright (C) 2021 Amazon.com; Inc. …"    so declared
quality    same md5 key = "0,5"                   vs detected license cross-checks,
                                                  e.g. ST-style header relicensing)

wfp        key = 32-bit winnowing hash → [file-md5][line] records
           (67,775 distinct snippet hashes in this KB — the tier that caught the
           modified esp-idf files)

sources    .mz shards, 28 MB — the full compressed content of every unique file,
           powering the line-range evidence in scan output (an archive, not an index)
```

Dedup is automatic and content-addressed: 13 releases produced only **5,736 unique
file contents** — a file unchanged between releases is stored once, and each
release's `file` records just point at it.

### Where the 408 MB actually sits (block-scatter analysis)

Post-punch per-table sizes are almost exactly *key-count × 4 KB*:
`wfp` 285 MB ≈ 67,775 keys × 4 KB; `file`/`license`/`copyright`/`quality` ~25 MB
each ≈ 5,736 keys × 4 KB; `sources` 28 MB (real payload); `url` 108 KB. So ~90% of
the 408 MB is **filesystem block-granularity scatter** — each occupied slot in a
key space sized for hundreds of millions of files pins a whole 4 KB block — not
data. True information content: **~35–40 MB per FreeRTOS-sized component**
(compressed sources + records) for the *complete* 13-release file inventory.

Consequence for scale extrapolation: scatter overhead is **sub-linear in component
count** — the maps are shared, so later components' keys increasingly land in
blocks earlier components already paid for. 408 MB is the singleton worst case,
not a per-component rate. The mbedTLS baseline should record the allocated-size
*delta* after import to measure the marginal cost directly.

### 4. License boundary: pattern confirmed

The whole stack ran as GPL-2.0 CLIs inside one container, driven purely by
`docker run` + volume mounts, emitting JSON — no linking against anything. This is
the process-boundary pattern the generator repo can adopt as-is.

## Results (mbedTLS baseline, 2026-07-18)

Second component mined into the **same KB** (12 releases: v2.28.8–v2.28.10,
v3.5.0/v3.5.2, v3.6.0–v3.6.6 — covering all corpus ground-truth bases), via
`mine_mbedtls.sh`; corpus scanned with the generalized `scan_corpus.sh mbedtls`.
Raw output in `results/mbedtls/`.

**Attribution again perfect, negative control clean.** All 20 matched files across
the four real/synthetic trees reported `pkg:github/mbed-tls/mbedtls`, component
`mbedtls`, Apache-2.0. The cJSON negative control returned `id=none` for all five
files — no false positives (nothing unrelated exists in a curated KB to falsely
match, which is the structural advantage inverted: the KB's precision is bounded
only by what we chose to mine).

Per-tree detail vs ground truth:

| Tree | Ground truth | Result |
|---|---|---|
| `nxp-mcuxpresso-fork` | 2.28.10 base, 4 of 5 files modified | **best case**: `version.h` file-match 100% → **2.28.10 exact**; all 4 modified files snippet 98–99% → all pinned **2.28.10** — even heavily modified, cross-release voting landed on the true base |
| `esp-idf-fork` | v3.6.2 base, `bignum.c`/`ecp.c` patched | untouched files 100% file-match but reported **3.6.1** (content shared across 3.6.x — in 3.x the version macros live in `build_info.h`, so `version.h` is release-stable); patched files snippet 99%, also 3.6.1 |
| `mixed-version-synthetic` | bignum v3.5.0, rest v3.6.0 | bignum → **3.5.0 exact**; the v3.6.0 files 100%-matched but reported **3.6.1** (byte-identical across 3.6.0/3.6.1; engine tie-breaks to one release instead of reporting the identical-content set) |
| `stm32-mw-mbedtls` | v3.6.6 base; 2 files patched, 2 files SPDX-line-only edits, `ecp.c` unmodified | **every file took the snippet path** — ST's Apache-only `SPDX-License-Identifier` header edit defeats the raw-MD5 exact tier *tree-wide*, at 89–99% snippet match; versions scattered (3.5.0–3.6.5, true base 3.6.6) |

Three findings this adds over the FreeRTOS baseline:

- **The ST tree is the raw-MD5 fragility finding at full scale**: a one-line
  license-header edit (already documented in the mbedTLS component research) pushes
  an *entire vendor tree* off the exact tier onto snippet matching. A normalized
  (comment-stripped) hash tier in front of the engine would restore exact matches
  for 3 of those 5 files and correct version pinning with them.
- **Version tie-breaking on release-shared content**: when a file's bytes are
  identical across several releases the engine names one (not the set) — the
  bespoke DBs' per-content tag *lists* (and the version-window logic) remain the
  better version-assignment layer. Small files make it worse (`version.h` at 89%
  snippet → 3.5.0, four minors off).
- **Snippet version voting is strongest when the release era is distinctive**
  (NXP's 2.28.x pinned exactly; ST's 3.6.x neighbors smeared).

**Marginal cost of the second component**: mining+import **3m25s**; KB allocated
size 408 MB → **1.4 GB** after re-punching (mbedTLS's `wfp` table dominates:
285 MB → 1.2 GB — crypto code carries far more distinct snippet hashes than the
small kernel; `sources` 28 → 48 MB). Import also populated the `cryptography`
table (3.6 MB) — minr's algorithm detection, a bonus signal for exactly this kind
of component. Import temporarily re-inflates rewritten sectors (21 GB pre-punch
this round), so the punch step belongs after every import batch.

## Results (CMSIS baseline, 2026-07-18)

Third component into the same KB via `mine_cmsis.sh`: 5 `CMSIS_5` releases
(5.5.0–5.9.0) + 2 `CMSIS_6` (v6.0.0/v6.1.0), spanning the repo split; whole-repo
mining declares the umbrella `CMSIS` component at the pack version (the
granularity tradeoff is documented in the script header). Raw output in
`results/cmsis/`.

- **Fastest mining round yet: 1m44s** for all 7 releases; KB 1.4 → **2.0 GB**
  allocated (wfp 1.2 → 1.7 GB, sources 48 → 58 MB). The feared "large component"
  cost didn't materialize — CMSIS's bulk is docs/prebuilt binaries that contribute
  little to the source-oriented tables.
- **Attribution again perfect, negative control again clean.** All matched files:
  `pkg:github/arm-software/cmsis_5`, Apache-2.0; the cJSON control: `id=none` ×4.
  CMSIS_6 caused no cross-lineage interference.
- **The version tie-break finding sharpened into its clearest form.** Ground truth
  for both real vendor trees (ST, NXP) is *verbatim 5.9.0 across all four tracked
  files* — but the engine reports `core_cm0.h`/`core_cm4.h` as 5.8.0 (byte-identical
  across 5.8.0/5.9.0, arbitrary tie-break). Meanwhile the synthetic mixed tree's
  rogue `core_cm4.h` **is** correctly isolated at 5.6.0. Net effect: **a verbatim
  single-release tree and a genuinely mixed tree are indistinguishable in engine
  output shape** — per-file point versions cannot express "consistent with one
  common release". The bespoke cross-file tag-set intersection is not a nicety;
  it's the thing that separates those two cases.

### The containing-release set IS in the KB — open subtask resolved by construction

The tie-break is an engine *reporting* limitation, not a data limitation. Queried
directly, the `file` table returns **one record per containing release** for a
shared-content hash — e.g. `core_cm0.h`'s md5 resolves to both:

```
50cc2b8f… → ARM-software,CMSIS,5.9.0,2022-05-02,Apache-2.0,pkg:github/arm-software/cmsis_5,…/5.9.0.zip
640821a2… → ARM-software,CMSIS,5.8.0,2021-06-29,Apache-2.0,pkg:github/arm-software/cmsis_5,…/5.8.0.zip
```

Consequences:

- **The open-item-4 subtask "does self-mining recover the full containing-URL list
  the CC0 export drops?" is answered: yes, trivially** — it's the KB's native
  storage shape (the CC0 export's one-exemplar-plus-count reduction is a
  distribution choice, not an LDB property).
- **The bespoke version layer ports cleanly on top of the minr KB**: for each
  scanned file, look up its matched hash's full release set (ldb CLI, or this
  repo's clean-room Python LDB reader from
  [osskb-open-dataset](../osskb-open-dataset/README.md) — same format), then run
  the existing tag-set intersection / version-window / mixed-version-warning
  logic. Engine for identification, thin post-processor for version assignment —
  no GPL entanglement (CLI process boundary, or the clean-room reader).

### Extrapolation: a full automotive-C curated KB (estimated 2026-07-18)

Measured marginal costs — FreeRTOS 408 MB (singleton, pays maximum block
scatter), mbedTLS +~1 GB (wfp-heavy crypto code), CMSIS +~600 MB (bulk is
docs/binaries that don't hit the source tables) — extrapolated to the
[component roadmap](../../component-roadmap.md)'s realistic universe (~30–50
repos, full release histories):

- **True data** (sources + records): ~3–5 GB.
- **Block scatter** grows linearly only until the shared maps start filling
  (~5.2M 4-KB blocks per table); at 10M+ wfp keys, new keys increasingly land in
  already-paid-for blocks.
- **Hard ceiling**: 21.5 GB per populated table (fully-written map) — `wfp`
  approaches it first; the per-file tables stay far below.

**Estimate: ~20–40 GB allocated total**, one cheap disk, fully offline —
vs 1.2 TiB for the CC0 world-KB that carries *less* information per entry
(no sources, no attribution metadata). Skipping the `quality`/`copyright`
imports would trim several GB more. Mining effort at this scale, extrapolating
~2–5 min per dozen releases: **on the order of an hour or two of wall time for
the entire component list**, trivially parallelizable and incremental per release.

### Queued follow-up (2026-07-18, not started): lightweight-export prototype + rollout model

The KB's runtime format need not be its storage format. Since the LDB layout is
readable clean-room (~200 lines of Python, already written for
[osskb-open-dataset](../osskb-open-dataset/README.md)), a **compact export** —
per-file hashes + winnowing prints + full containing-release sets, *no* sources,
no quality/copyright — should collapse the shippable identification artifact from
GBs to tens of MB, embeddable directly in a scanner, GPL-free at runtime. The
prototype should measure: export size for the 3-component KB, whether the ported
bespoke matcher (tag-set/window/consistency logic) over the export reproduces the
baseline results, and what's lost vs the full engine (snippet line-map evidence
needs sources).

This prototype also decides the **rollout model** for the company-scale scenario
(discussed 2026-07-18). Candidate models:

1. **Bundle the full KB per machine** — simplest, fully offline; real cost is
   re-shipping on every KB refresh, not disk (~40 GB × N machines is a rounding
   error and should not drive the decision).
2. **Self-hosted REST service** — SCANOSS's own API protocol over our engine;
   existing clients (`scanoss-py`, SBOM Workbench) work unchanged, fingerprints
   stay in-house, no rate limits. Costs: an always-on SPOF, a network dependency
   in CI/air-gapped environments, and *unversioned answers* (a live API replies
   from whatever the KB contains that day).
3. **KB as a versioned pulled artifact** (preferred direction, noted 2026-07-18):
   publish each KB build to an internal artifact registry as a pinned, versioned
   blob (like a container image); scanners pull-and-cache on first use and scan
   locally. The KB being ~95% zeros means the compressed artifact shrinks to
   roughly real-data size (single-digit GB even at full-roadmap scale; zstd of a
   sparse tar). This keeps the central single-source-of-truth and one update
   point *without* operating a service, and gives **SBOM reproducibility for
   free**: a scan pinned to "KB snapshot 26.07" provably yields the same answer
   when regenerated later — compliance-grade behavior a live API can't offer.
4. **Two-tier (likely end state)**: the thin export (this prototype) bundled
   offline in every scanner for identification + attribution; the full KB —
   distributed per model 3, or served per model 2 — only for evidence/deep-dive
   queries (snippet line maps need the `sources` table).

## Results (lightweight-export prototype, 2026-07-18)

`export_lightweight.py` (clean-room LDB walk, no GPL code in the export path or
artifact) emitted the whole 3-component / 32-release identification KB as
**one 48.1 MB gzipped JSON**: 32 release records, 10,341 file→release-set
entries, 445,774 snippet-hash→(file,line) entries. Sources and the detection
tables stay in the full KB by design (evidence tier). Export walk: ~9 min
single-threaded (dominated by reading sparse maps; `SEEK_DATA`/parallelism
would cut it to seconds — not worth it for a prototype).

`validate_export.py` then rescanned **all twelve corpus trees using only the
artifact** (exact-MD5 tier + snippet-vote tier over locally generated
`scanoss-py` fingerprints + the bespoke cross-file release-set intersection):

- **All 12 tree-level identifications correct** — right purl, component, and
  declared license everywhere; both negative controls cleanly NOT IDENTIFIED.
- **The engine's fake-mix problem is fixed**: the verbatim CMSIS vendor trees
  (which the engine reported as 5.8/5.9 mixes) now yield
  `CONSISTENT — all files coexist in release(s): 5.9.0` via set intersection;
  both genuine synthetic mixes still trigger the MIXED warning with the rogue
  file correctly isolated (`core_cm4.h`→5.6.0, `bignum.c`→3.5.0,
  `queue.c`→11.0.0).
- **Version assignment improved over the engine on modified forks too**: NXP's
  4-of-5-modified mbedTLS fork intersects to exactly 2.28.10; Espressif's
  mbedTLS fork to {3.6.1, 3.6.2} — honestly containing the true 3.6.2 base the
  engine's point answer missed; FreeRTOS `tasks.c` snippet-voted to 10.5.1, the
  documented fork base.
- **Known refinements surfaced** (both already-known lessons, now with a
  concrete fix location): (a) snippet-tier release sets are near-point answers,
  so heavily modified *coherent* forks (esp-idf FreeRTOS, ST mbedTLS) can
  over-trigger the MIXED verdict — the snippet tier should widen to a
  version window / union of top candidates before intersecting; (b) tiny files
  are snippet-noisy (ST's `version.h` at 38 snippets dragged to 3.5.0) — the
  normalized-hash tier would exact-match those SPDX-only edits and pull ST's
  intersection to exactly {3.6.6}.

**Size extrapolation**: 48 MB/gz for 3 components → order **0.5 GB for the full
30–50-repo roadmap** as naive JSON; a binary encoding of the wfp index (the
bulk) shrinks that ~3–4×, i.e. **~100–300 MB — comfortably bundleable inside a
scanner deployment**, vindicating the two-tier rollout model (thin artifact
everywhere, full KB central for evidence).

**Queued follow-up (2026-07-18): plain-JSON artifact feasibility.** Evaluate
making the *canonical* export format plain, pretty-printed JSON instead of a
gzipped blob — rationale: the artifact is the scanner's reference data, and a
directly inspectable/diffable file lets a technical user verify what the
scanner trusts instead of trusting it blindly (the same auditability bar an
SBOM tool asks of everyone else's supply chain). To measure/decide: plain and
pretty-printed sizes at 3-component and extrapolated scale (gz 48 MB likely
≈200–250 MB compact / ≈350–450 MB pretty); whether splitting per component
(one browsable file each, e.g. `freertos.json`, plus a tiny manifest) keeps
files human-navigable; and whether compression should be demoted to a
transport-only encoding (registry/download) with plain JSON on disk. Interacts
with the binary-wfp-encoding idea above — the likely landing zone is a hybrid:
human-auditable JSON for `releases` + `files` (the attribution-bearing parts),
with the bulky machine-only `wfp` index either separate or binary.

### Verdict so far

`minr` does industrialize the curated approach: one command per release with
declared metadata, correct attribution by construction, verbatim + modified-copy
detection out of the box, offline scanning in seconds, clean negative controls
on two components. All three baselines are done (FreeRTOS, mbedTLS, CMSIS —
32 releases total, ~11 minutes of mining, 2.0 GB allocated KB), and they converge
on the same architecture: **engine for identification and attribution, a thin
post-processor over the KB's native containing-release sets for version
assignment** (reusing the bespoke tag-set/window/consistency logic), plus a
normalized-hash tier in front of the raw-MD5 exact match (the ST header-edit
lesson). Remaining subtasks from open item 4: the hybrid curated-first/
CC0-fallback lookup path, and operational-cost extrapolation to the full
roadmap component list.
