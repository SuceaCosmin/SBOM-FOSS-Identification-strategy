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
    (not inspected in this experiment; shard timestamps 2025-Jul-03).
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

Scripts: [`ldb_lookup.py`](ldb_lookup.py) (single-key lookup),
[`ldb_sample.py`](ldb_sample.py) (random-sampling schema statistics),
[`ldb_pretty.py`](ldb_pretty.py) (pretty-print sample records — random entries or
by MD5-prefix search — used to produce the worked examples above). All operate
on shard files downloaded to a local directory; shards are ~381 MiB each and are
**not** checked into this repo.
