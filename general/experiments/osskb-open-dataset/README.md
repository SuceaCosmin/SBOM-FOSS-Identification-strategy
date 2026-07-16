# OSSKB open dataset (`osskb-core`) inspection — what does the offline CC0 data actually contain?

**Question** (open investigation item 3 in
[../../existing-fingerprint-datasets.md](../../existing-fingerprint-datasets.md)):
the downloadable CC0 dataset was the candidate for an offline, license-clean,
rate-limit-free foundation for fingerprint detection. The crux question: does it
expose *all* containing repos per file fingerprint (which would enable attribution
post-processing), or just one (inheriting the hosted API's arbitrary-attribution
defect)?

**Answer (2026-07-13): just one — plus a count.** Each `file-url` record is
`path,exemplar-URL,count`: a single arbitrary containing URL (typically a GitHub
release/commit zip), the file's path inside it, and a count of how many URLs the KB
knows contain this file. The full URL list is not in the dataset, and neither is any
purl/license/version/component metadata. The dataset is a pure recall oracle with a
useful "spread" indicator, not an attribution source.

## Dataset facts (inspected 2026-07-13)

- Download: `https://osskb.st.foundation/osskb-core/` (also FTP). License CC0-1.0.
- `version.json`: KB snapshot `25.09.28` — **~9.5 months behind** the hosted API's
  KB on inspection day (`26.07.13`), despite "continuously updated" positioning.
- Two tables in SCANOSS LDB binary format, 256 shards each (`00.ldb`–`ff.ldb`,
  sharded by first byte of the file MD5):
  - `file-url`: ~97 GiB total (~381 MiB/shard) — file MD5 → record above.
  - `wfp`: ~1.14 TiB total (~4.5 GiB/shard) — winnowing snippet fingerprints
    (shard timestamps 2025-Jul-03; inspected 2026-07-16, see the dedicated
    section below).
- `file-url.cfg` = `16,0,1,0`: 16-byte keys (full MD5), variable-length records.
- Scale estimate from map-slot sampling: ~500M distinct file hashes across all 256
  shards (~2M per shard).

## LDB on-disk format (derived from `scanoss/ldb` source, reimplemented clean-room)

Documented in [`ldb_lookup.py`](ldb_lookup.py) (~60-line pure-Python reader,
no GPL code reused — only the format was learned from the GPL source):

1. Shard file starts with a map: 256³ slots × 5-byte little-endian pointers,
   indexed by MD5 bytes 1–3 (byte 0 = shard filename).
2. Map pointer → list: `[LN(5): ptr to last node][first node…]`.
3. Node: `[NN(5): next-node ptr, 0 = last][TS(2 LE): data bytes][data]`.
4. Node data: groups of `[subkey(12) = MD5 bytes 4–15][GS(2 LE)]` followed by
   records, each `[size(2 LE)][payload]`.

All integers little-endian. Records for one key can span multiple nodes
(appended over time); a lookup walks the whole list.

## Empirical lookups (3 shards downloaded: `0b`, `39`, `c9`)

| File (ground truth) | MD5 | Open-dataset record | Reading |
|---|---|---|---|
| `core_cm4.h` CMSIS 5.9.0, byte-identical in upstream Arm `CMSIS_5`, ST, NXP, thousands of repos | `0b5047…` | 1 record: path inside **arduino-pico `rp2040-3.9.5.zip`** (pico-sdk→btstack→renesas-port→CMSIS_5 nesting), count **1564** | Exemplar URL is an arbitrary deep-vendored artifact, not upstream; count correctly signals "this file is everywhere" |
| `FreeRTOS_CLI.c` from FreeRTOS umbrella repo | `39952b…` | 1 record: `freertos/freertos` commit zip, count **8** | Containing repo (not a canonical component identity); no version/license |
| `bignum.c` from real ESP-IDF mbedTLS fork (Espressif patches) | `c9a1ea…` | 1 record: **`espressif/esp-idf` v5.3.2 release zip**, count **5** | Happens to be the right vendor fork — but the hosted API attributed the same file to Realtek `ameba-rtos`, proving exemplar choice is arbitrary in both directions |
| `core.c` from Reliance-Edge (GPLv2, vendored verbatim in FreeRTOS umbrella repo) | `39675d…` | **0 records — absent** | Recall gap: the hosted API matches this file 100%, the 2M-repo offline subset doesn't contain it at all |

## Record anatomy — worked examples (extracted 2026-07-16)

Kept here as a durable reference for what a `file-url` record actually contains,
so future sessions don't have to re-download a shard to remember. Produced with
[`ldb_pretty.py`](ldb_pretty.py) (`random` mode for arbitrary entries, `prefix`
mode to re-find the ground-truth files by their documented MD5 prefixes).

Every record is keyed by the **MD5 of the file's raw content** (16 bytes; byte 0
selects the shard file, so `39952b…` lives in `39.ldb`). The payload is one
CSV-ish text record with exactly three fields — and nothing else:

```
<path-inside-artifact> , <one exemplar download URL> , <count>
```

Three ground-truth files from this repo's corpus, plus two random entries showing
the extremes of the `count` field:

```
file MD5 : 0b50476c9eb684ea3d9e3c1c08aa24bd        <- core_cm4.h (CMSIS 5.9.0)
  path   : pico-sdk/lib/btstack/port/renesas-ek-ra6m4a-da14531/e2-project/ra/arm/CMSIS_5/CMSIS/Core/Include/core_cm4.h
  url    : https://github.com/earlephilhower/arduino-pico/releases/download/3.9.5/rp2040-3.9.5.zip
  count  : 1564

file MD5 : 39952bdb1285b8553c0cbf96013a39c0        <- FreeRTOS_CLI.c (FreeRTOS umbrella repo)
  path   : FreeRTOS-Plus/Source/FreeRTOS-Plus-CLI/FreeRTOS_CLI.c
  url    : https://github.com/freertos/freertos/archive/680a125.zip
  count  : 8

file MD5 : c9a1eaf1be80997078c630d56455228f        <- bignum.c (Espressif-patched mbedTLS)
  path   : components/mbedtls/mbedtls/library/bignum.c
  url    : https://github.com/espressif/esp-idf/releases/download/v5.3.2/esp-idf-v5.3.2.zip
  count  : 5

file MD5 : 39952b552ffea54da3fb6c4d7ae405a4        <- random entry, mid-count
  path   : patches.suse/platform-x86-amd-hsmp-Cache-pci_dev-in-struct-hsmp_socket.patch
  url    : https://github.com/openSUSE/kernel-source/archive/rpm-6.4.0-150600.10.34.zip
  count  : 143

file MD5 : 39ca264e2a569731ce81b39e49a70648        <- random entry, count = 1
  path   : minimal/capella/ssz_static/PendingAttestation/ssz_lengthy/case_28/roots.yaml
  url    : https://github.com/ethereum/consensus-spec-tests/releases/download/v1.3.0-rc.0/minimal.tar.gz
  count  : 1
```

What these examples demonstrate about usable signal:

- **Recall oracle**: MD5 in → "known to open source, yes/no" out, ~3 disk seeks,
  fully offline.
- **`count` as routing signal**: `core_cm4.h` at count 1564 = "ubiquitous file,
  exemplar URL worthless as provenance, route to curated attribution";
  count 1 = "exemplar URL likely *is* the origin" (38% of sampled files).
- **The exemplar URL is arbitrary**: the CMSIS entry points at a copy vendored
  four levels deep inside an Arduino board package, not Arm's upstream repo.
- **The path field is an underexplored identity hint**: even when the URL is
  junk, the path often contains the true component identity
  (`…/CMSIS_5/CMSIS/Core/Include/core_cm4.h`,
  `components/mbedtls/mbedtls/library/bignum.c`). A path-suffix matcher could
  recover component hints the URL doesn't give — not yet investigated.
- **The KB indexes everything inside release artifacts, not just source**: the
  wider random dumps (2026-07-16, ~130 entries across the three shards) included
  compiled `.class`/`.jar`/`.o`/`.pyc`/`.dll` files, PNGs, JSON datasets,
  generated HTML docs, and contents of `.deb`/`.rar`/`.7z` release bundles. For
  a C-source use case most of this is filterable noise — the ~500M-hash scale
  substantially overstates *source-code* coverage. All sampled URLs were
  GitHub-hosted (matching the schema-statistics finding below).

## Schema statistics ([`ldb_sample.py`](ldb_sample.py), 23,319 records sampled from shard `39`)

- 100% of records parse as `path,url,count` (one non-UTF8 outlier).
- 100% of sampled URLs are `github.com` (release/commit archive zips).
- `count` distribution: min 1, median 3, p90 28, p99 210, max 12,486;
  38% of files have count = 1 (unique to a single URL).

## The `wfp` table (inspected 2026-07-16) — offline snippet matching works

**Question**: the `file-url` table only covers verbatim files (exact MD5 —
any one-byte modification defeats it). Can the offline dataset also serve the
repo's *primary* target, locally-modified vendored source, via its winnowing
(`wfp`) table? One shard (`wfp/39.ldb`, 4.41 GiB) was downloaded and the
format cracked the same clean-room way (layout learned from `scanoss/ldb`
sources, reimplemented in [`wfp_lookup.py`](wfp_lookup.py)).

**Answer: yes, mechanically.** The table is an inverted index
`32-bit winnowing hash → list of (file MD5, line number)`, and a
vote-across-snippet-hashes matcher over it reproduces the hosted API's
modified-file recall entirely offline — with the same attribution
limitations as `file-url`, since file MD5s still resolve only to
`path, exemplar-URL, count`.

### Format (differs from `file-url` in three ways)

`wfp.cfg` = `4,18,1,0`: 4-byte keys, **fixed 18-byte records**.

1. The key (the winnowing hash, big-endian hex as emitted in `.wfp` files) is
   fully consumed by shard byte + 3 map-index bytes — nodes carry **no subkey**.
2. For fixed-record tables the node's 2-byte size field counts **records, not
   bytes** (LDB writes `records` there when `rec_ln > 0`, byte-length otherwise
   — the file-url reader misparses wfp nodes as "1 byte of data" silently).
3. Node data is raw concatenated 18-byte records — no group headers, no
   per-record size prefixes.

Record layout, empirically validated: `[file MD5 (16)][line number (2 LE)]`.
For two corpus files whose exact version is in the KB (`bignum.c` ESP-IDF fork,
`core_cm4.h` CMSIS 5.9.0), every snippet hash landing in shard `39` (5/5 and
6/6) returned a record with **that file's exact MD5 and the exact line number**
from a locally generated `scanoss-py wfp` fingerprint (little-endian confirmed,
big-endian 0 matches).

### Worked examples — what a wfp lookup actually returns (extracted 2026-07-16)

Kept verbatim (like the `file-url` examples above) so future sessions can see
the shape of the data without re-downloading a shard. Produced with
`wfp_lookup.py lookup` against `wfp/39.ldb`; the "local .wfp says" annotations
come from fingerprinting the corpus files with `scanoss-py wfp`.

```
== bignum.c (ESP-IDF fork): snippet hash 3959dcd4 (local .wfp: line 1648) -> 177 records
   [   0] md5=05b9e69994fe67a1eaa34a43a0f2b280 line=11667
   [   1] md5=05ec094ebbec83f2d48b689dc31217b8 line=68
   [   2] md5=0657be7e3198b0dedeb445c7d6fce4b3 line=53
   [   3] md5=0b9f689e2a7a1061286fe123276d0487 line=10325
   ...
   [ 132] md5=c9a1eaf1be80997078c630d56455228f line=1648   <-- ground-truth file, exact line

== bignum.c (ESP-IDF fork): snippet hash 399df0bf (local .wfp: line 671) -> 285 records
   [   0] md5=007b9bcafc173bf1f90dea42364c1110 line=535
   [   1] md5=00ae0549f74c81b3094440cfe13509aa line=736
   ...
   [ 224] md5=c9a1eaf1be80997078c630d56455228f line=671    <-- ground-truth file, exact line

== core_cm4.h (CMSIS 5.9.0): snippet hash 39541f1a (local .wfp: line 994) -> 736 records
   [   0] md5=0005379845514c3b3019df75e0cd5d3e line=939
   [   1] md5=0090ac54a11bd24c007c8e0a20283c40 line=864
   [   2] md5=01b1162f6b1eb3c20e082cf9979a7187 line=849
   ...
   [  34] md5=0b50476c9eb684ea3d9e3c1c08aa24bd line=994    <-- ground-truth file, exact line
```

Reading these: one 32-bit snippet hash maps to **hundreds of files** that all
contain that snippet — each record is just "this file MD5 contains it at this
line". The same code fragment sits at line 68 in one file and line 11667 in
another (vendored inside amalgamations/different versions). Nothing identifies
which record is "right"; identification comes only from the *co-occurrence* of
many snippet hashes agreeing on the same MD5 (the vote in `wfp_pipeline.py`),
and the returned MD5s must still be resolved through `file-url` (or better) for
any naming — the two-level `hash → MD5 → exemplar-URL` chain is the entire
offline story.

### Scale and fanout (shard `39` sampling)

- ~10.4% of the 16.7M map slots are occupied → ~1.7M distinct hashes/shard,
  ~450M across 256 shards (~10% of the 32-bit hash space).
- Mean ~143 records per hash (random keys); for *our* C-corpus snippet hashes
  the fanout is heavier: median ~300, max 1,982 records per hash. Total table
  ≈ 64 billion (MD5, line) pairs ≈ 1.14 TiB.
- Nodes are append-granular (many single-record nodes observed), so one lookup
  may walk a long node chain — fine for research, would want re-collation for
  production hosting.
- **Staleness**: wfp shards are dated 2025-Jul-03 — ~3 months *older* than the
  file-url table (`25.09.28`), i.e. ~12.5 months behind the live KB at
  inspection time. The two tables are not even mutually consistent snapshots.

### End-to-end modified-file demo ([`wfp_pipeline.py`](wfp_pipeline.py))

Ground truth: `tasks.c` from the real ESP-IDF FreeRTOS fork (Espressif-patched,
this exact version absent from the KB snapshot — 0 of its snippet hashes'
records contain its MD5). Pipeline: local `.wfp` → shard lookup for the 11
hashes with first byte `0x39` → vote over returned MD5s → resolve candidates
via the downloaded `file-url` shards:

```
tasks.wfp: md5 9e1201e368c44994f161a5833d048e41, 3589 snippet hashes, 11 usable
distinct candidate file md5s: 2536; 8 md5s hit 11/11 votes
best resolvable candidate (8/11 votes, md5 0b63a3f1…):
  -> components/freertos/FreeRTOS-Kernel/tasks.c
     https://github.com/espressif/esp-idf/archive/v5.1.2.zip (count 10)
```

The modified file was pinned to its own vendor-fork lineage (an earlier
esp-idf release) using nothing but offline data — the snippet analogue of the
hosted API's 84%-match result. Caveats: with all 256 wfp shards the vote would
use all 3,589 hashes, not 11; the 2,159 count-1 candidates show snippet noise
needs the co-occurrence vote (single shared hashes mean little); and candidate
MD5s still inherit `file-url`'s arbitrary-exemplar attribution problem.

### Consequences

- The offline dataset can cover **both** detection tiers — verbatim
  (`file-url`) *and* modified-copy (`wfp`) — at a storage price: 97 GiB vs
  1.24 TiB. A custom matcher is a few hundred lines of Python, no GPL runtime
  needed (format knowledge only).
- Attribution remains the missing layer in both tables; the wfp path
  *amplifies* the need for canonical resolution because it emits candidate
  *sets* (here: 8 equally-voted MD5s, presumably adjacent esp-idf releases).
- Line numbers in records enable range/coverage scoring (contiguous matched
  regions vs scattered single hashes) — same signal the hosted engine uses for
  its match percentage.

## Consequences for the reuse-first strategy

1. **Attribution post-processing cannot ride on the offline dataset** — the
   "intersect all containing repos" idea (open item 1) has no offline data source;
   the URL list exists only inside SCANOSS's full (non-open) KB.
2. **The count field is genuinely valuable signal** the hosted API doesn't return:
   count 1 ≈ strong provenance (the exemplar URL likely *is* the origin);
   high count ≈ "ubiquitous file, canonical resolution required, exemplar
   untrustworthy". A detection pipeline could use it to route files between
   trust-the-URL and needs-curated-attribution paths.
3. **Coverage is real but incomplete** (Reliance-Edge miss) and **staleness is
   material** (~9.5 months at inspection; anything released since 2025-09 is
   invisible to the offline data).
4. Dataset-only is viable as an **offline Tier-3 recall net + spread indicator**
   (97 GiB `file-url` table is trivially hostable; exact-hash lookups need ~3 disk
   seeks), but attribution/metadata must come from elsewhere: curated per-component
   reference DBs, the hosted API, or self-mining (`minr`) — reshaping open items
   1 and 4 accordingly.

Scripts — all operate on locally downloaded shard files (~381 MiB per
`file-url` shard, ~4.5 GiB per `wfp` shard), **not** checked into this repo:

- [`ldb_lookup.py`](ldb_lookup.py) — `file-url` single-key lookup (16-byte-key,
  variable-record LDB reader).
- [`ldb_sample.py`](ldb_sample.py) — `file-url` random-sampling schema statistics.
- [`ldb_pretty.py`](ldb_pretty.py) — pretty-print `file-url` records (random or
  by MD5-prefix search) — produced the worked examples above.
- [`wfp_lookup.py`](wfp_lookup.py) — `wfp` table reader (4-byte-key,
  fixed-18-byte-record variant) + `check` mode that cross-validates a local
  `scanoss-py` `.wfp` fingerprint file against a shard.
- [`wfp_pipeline.py`](wfp_pipeline.py) — end-to-end offline snippet matcher:
  `.wfp` → wfp-shard votes → `file-url` resolution (the modified-`tasks.c` demo).
