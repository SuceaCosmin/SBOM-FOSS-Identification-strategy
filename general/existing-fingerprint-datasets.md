# Existing precomputed fingerprint datasets — can we reuse instead of build?

**Question** (the "reference corpus question" left open in [CLAUDE.md](../CLAUDE.md)):
now that the per-component version-fingerprint approach has stabilized across three
components, do precomputed fingerprint/hash datasets of OSS components already exist
that an eventual SBOM scanner could reuse, instead of (or alongside) building curated
per-component reference DBs from scratch?

**Answer in one paragraph**: yes, reusable datasets exist — the most relevant is
SCANOSS/Software Transparency Foundation's OSSKB (free winnowing-fingerprint API over
~250M indexed URLs, plus a CC0-licensed downloadable core dataset, plus a GPL-2.0
open-source engine/mining stack for self-hosting). Tested empirically against this
repo's ground-truth corpus (2026-07-08), OSSKB's **recall is excellent** — every real
vendor-fork file matched, including a synthetically modified file no public repo
contains (84% snippet match). But its **attribution is exactly what our research has
been showing is the hard part**: it names *some* public repo containing matching code,
not the canonical upstream component, and its version/license output describes that
containing repo, which can be badly wrong. These datasets solve "is this code known
OSS?" (recall); they do not solve "which component, which version, under which
license?" (attribution) — which is precisely what the curated per-component reference
DBs from our experiments do. The two are complementary layers, not substitutes.

## The landscape

| Source | What it is | Fingerprint type | Reusable? |
|---|---|---|---|
| [SCANOSS OSSKB](https://osskb.org) (run by the [Software Transparency Foundation](https://www.softwaretransparency.org)) | Free, no-key API over fingerprints mined from ~250M URLs / 100M+ files | Winnowing (WFP) — same algorithm family as our experiments; file- and snippet-level | Yes — free API, fair-use terms |
| [osskb-core-open-dataset](https://github.com/Software-Transparency-Foundation/osskb-core-open-dataset) | Downloadable fingerprints of ~2M most-popular GitHub repos, via HTTPS/FTP (`osskb.st.foundation`) — inspected 2026-07-13: ~1.2 TiB LDB shards, records carry one exemplar URL + count, **no metadata** (see below) | LDB tables: exact MD5 (`file-url`) + winnowing (`wfp`) | Yes — **CC0-1.0**, unrestricted |
| SCANOSS open stack: [engine](https://github.com/scanoss/engine), [minr](https://github.com/scanoss/minr), LDB | Self-hostable matching engine + mining tool to build your **own** KB in the same format | Winnowing | Yes — **GPL-2.0** (matters if embedded in a product; fine if invoked as a separate process/service) |
| [Software Heritage](https://archive.softwareheritage.org/api/) | Content-addressed archive of (approximately) all public source code; `content/sha256:<h>` lookup + provenance endpoints | Exact hashes only (sha1, sha1_git, sha256) — no fuzzy matching | Yes — free API (rate-limited anonymous tier) |
| [ClearlyDefined](https://docs.clearlydefined.io/docs/get-involved/using-data) | License/attribution metadata per package coordinate, harvested-data includes per-file sha1/sha256 | Exact hashes, keyed by package coordinates | Yes, but license-metadata-focused and coordinate-centric |
| [AboutCode PurlDB / MatchCode](https://github.com/aboutcode-org/purldb) | Open-source package DB + matching pipelines (exact sha1, HaloHash directory/file fingerprints, snippet work in progress) | Mixed | Open stack, but **purl/package-manager-centric** — weakest fit for our "no package manager" embedded vendoring scope |
| [CENTRIS (ICSE 2021)](https://seulbae-security.github.io/pubs/centris-icse21.pdf) and successors (Tiver, ICSE 2025) | Academic modified-OSS-reuse detectors over 10k+ C/C++ repos; function-level hashed signatures | Function-level hashes | Research-grade code/dataset on GitHub; a technique reference more than an operational dataset |
| Black Duck KB, FossID, et al. | Commercial knowledge bases behind the major SCA products | Proprietary | No — the datasets are the product |

## Empirical test against this repo's ground-truth corpus (2026-07-08)

Method: `pip install scanoss`, `scanoss-py scan <dir>` against the free OSSKB API
(no key; KB version at test time: monthly `26.06`, daily `26.07.08`). Files taken
directly from `components/*/corpus/` — all with known ground truth.

| File scanned (ground truth) | OSSKB result | Attribution quality |
|---|---|---|
| `core_cm4.h` from real ST STM32CubeF4 checkout (byte-identical to upstream) | 100% file match → `pkg:github/arm-software/cmsis_5`, versions 5.8.0-rc..5.9.0, Apache-2.0 | **Correct upstream**, version range matches our own reference-DB answer |
| `tasks.c` from real ESP-IDF FreeRTOS fork (Espressif SMP patches) | 100% file match → `pkg:github/espressif/esp-idf`, versions v6.0-dev..v6.0.1 | Fork repo named, **not FreeRTOS-Kernel**; version range is ESP-IDF's, not a FreeRTOS kernel version |
| `bignum.c` from real ESP-IDF mbedTLS fork (hardware-accel patches) | 100% file match → `pkg:github/ameba-aiot/ameba-rtos` (Realtek SDK!), `library/bignum.c` | **Arbitrary containing repo** — not mbedTLS upstream, not even the right vendor; Realtek evidently ships an identical copy |
| `aes.c` from real ST `stm32-mw-mbedtls` (SPDX-line-only divergence) | 100% file match → `pkg:github/stmicroelectronics/stm32-mw-mbedtls`, Apache-2.0 | Fork repo named, not upstream; license *happens* to reflect ST's re-licensing here — but only because the fork repo was the repo returned |
| Negative control: cJSON's `cJSON.c` saved as `aes.c` | 100% file match → `pkg:github/davegamble/cjson`, MIT | **Correctly identified true origin despite misleading filename** — matching is content-based, filename-independent |

### Stress test: locally modified file that exists in no public repo

Our priority-1 detection target is vendored source with *local* modifications. To test
it, ST's `aes.c` was synthetically perturbed the way a firmware team would (company
banner comment, an internal identifier renamed throughout, a project-specific
`#ifdef`-gated hardware-DMA hook inserted mid-file, `MBEDTLS_SELF_TEST` tail deleted —
78,778 → 52,417 bytes) and rescanned:

- **Detection survived**: snippet match, 84% of lines matched, 224 hits — recall on
  modified copies is real, not just whole-file hashing.
- **Attribution collapsed**: matched to `pkg:github/oldes/rebol3` (the Rebol language
  interpreter, which vendors mbedTLS at `src/core/mbedtls/aes.c`), reported as
  "version 3.17.0" (a *Rebol* version), with a license list of Rebol3's repo-level
  license files — JasPer-2.0, Info-ZIP, MIT-CMU, CMU-Mach, Cornell-Lossless-JPEG… —
  **none of which is mbedTLS's actual license**.

Software Heritage, for comparison, confirmed it knows the exact unmodified ST file by
sha256 (returned its SWHID `swh:1:cnt:e1b81a...`) — useful as a free "does this exact
file exist anywhere in public OSS?" oracle, but exact-match only by design.

## Follow-up: free-API availability / rate-limit test (2026-07-13)

Motivation: an HTTP 503 "rate limit reached" response was encountered when using the
free REST API directly, raising the suspicion that the public endpoint might be
flooded to the point of being unusable. Tested
by scanning progressively larger slices of a real checkout of the
[FreeRTOS/FreeRTOS](https://github.com/FreeRTOS/FreeRTOS) umbrella repo with
`scanoss-py` 1.54.0 (no API key):

| Scan target | Files returned | Wall time | Errors |
|---|---|---|---|
| `FreeRTOS-Plus/Source/FreeRTOS-Plus-CLI` | 3 | ~5 s | none |
| `FreeRTOS-Plus/Source/Reliance-Edge` | 64 | 7.9 s | none |
| `Demo/CORTEX_MPU_M7_NUCLEO_H743ZI2_GCC_IAR_Keil` | 317 | 64 s | none |
| `Demo/Common` | 546 | 24 s | none |

~930 files scanned back-to-back in one sitting, **zero 503s**, KB current (daily
version `26.07.13` — same-day freshness). The API is not persistently flooded.

The documented limits explain the 503 seen earlier: the Software Transparency
Foundation's [limit page](https://www.softwaretransparency.org/limit) states
**10,000 API calls per hour for anonymous users** (50,000 for sponsors), returning
**503** when exceeded — and notes the trigger can be "too many API calls from your
location", i.e. the quota is per source location/IP. Two practical consequences:

- A 503 can be caused by *other* users behind the same NAT/CGNAT or by regional
  bursts, and clears on its own — treat it as transient back-pressure, not outage.
- Client batching matters enormously for staying under the quota: `scanoss-py`
  POSTs WFP fingerprints in multi-file batches, so ~930 files consumed only a
  handful of API calls; naive one-request-per-file REST usage burns the same quota
  ~two orders of magnitude faster. Any generator using the free API should batch
  WFPs, and needs 503-aware retry/backoff regardless.

### Reproduced same-day with SBOM Workbench — the trigger is request *rate*, not volume

The 503 was reproduced the same evening with **SCANOSS SBOM Workbench 1.26.1**
scanning the full FreeRTOS checkout (11,584 files after filtering). The Workbench's
`project.log` + `bad_request-*.txt` debug dumps made the mechanics fully visible:

- The Workbench (via its bundled `scanoss.js` scanner) **does batch** — the failed
  request carried an 11-file WFP payload — but the batches are tiny and dynamic:
  878 requests carried 4,060 files, **avg 4.6 files/request** (215 requests carried
  a single file; max seen was 16). Batch size is not user-configurable anywhere in
  the UI or project config.
- Those 878 requests went out in **under 2 minutes (~8 requests/second)** before the
  server answered `503 {"error":"Rate limit exceeded","retry_after":18905}` — a
  ~5.25-hour penalty, far longer than a rolling one-hour window would produce.
- **The ban is location/IP-wide and shared across clients** — with one nuance.
  One minute after the Workbench's 503, a tiny 1-POST `scanoss-py` scan from the
  same machine *succeeded* (initially suggesting a per-client limiter). But ~18
  minutes later a 64-file `scanoss-py` scan got 503 with `retry_after: 17832` —
  exactly the Workbench's 18,905-second window counting down. So all clients behind
  the IP share one bucket; the limiter merely tolerates an occasional small request
  (trickle refill) while sustained multi-request scans are refused for the full
  window.
- On 503, `scanoss-py` logs "Aborting current thread" — it does **not** sleep out
  the server's `retry_after` and resume. Its `--retry` flag covers transient
  failures, not rate-limit bans.

Practical read for the eventual generator: the free API is genuinely usable for
scans in the thousands-of-files range, but the anonymous per-location bucket is
shallow enough that one full-firmware-tree scan with an inefficient client
(~2,500 small requests for 11.5k files) exhausts it and locks the whole IP out
for ~5 hours. Batching fat and pacing slow stretches the same bucket much
further; an API key (sponsor/commercial tier) raises it; and any tool built on
the free tier must parse the 503 body and honour `retry_after` itself. For
full-tree scans in SBOM Workbench specifically there is no batching knob to
turn — pre-filter the tree or use a key.

### Configuring `scanoss-py` batching properly for large scans

`scanoss-py` batches by **payload size, not file count**: it concatenates per-file
WFP fingerprint blocks and flushes a POST to `/scan/direct` whenever the buffer
reaches `--post-size` (in KB, default 32), with `--threads` (default 5) concurrent
posting threads. Measured on this repo's FreeRTOS corpus, a C source file averages
~3.2 KB of WFP (546 files in `Demo/Common` → 1.77 MB), so the defaults translate to
roughly **10 files per request** — for reference, SBOM Workbench 1.26.1's
non-configurable scanner averaged 4.6.

The knobs that matter, and a configuration that stretches the anonymous quota:

```
scanoss-py scan <dir> \
  --post-size 128 \   # KB per POST (default 32) → ~40 C files/request instead of ~10
  --threads 2 \       # concurrent posts (default 5) → tame the requests-per-second rate
  --retry 5 \         # transient-failure retries (default 5); does NOT handle 503 bans
  --timeout 300 \     # per-request timeout in seconds (default 180); raise with big posts
  --output results.json
```

- `--post-size` is the request-count lever: quadrupling it cuts the number of API
  calls ~4× for the same tree. Larger payloads take longer per request, so raise
  `--timeout` alongside. (Upper bound accepted by the server not probed — the
  rate-limit ban landed before that experiment; treat 64–256 KB as the sane range.)
- `--threads` is the request-rate lever: the empirical difference between tripping
  the limiter (~8 req/s) and not (~2 req/s) was pacing, so fewer threads is the
  conservative choice for big trees.
- Trim the payload before it exists: `--skip-extension`/`--skip-folder`/
  `--skip-size` exclude noise files client-side (the KB happily matches `.url`
  shortcuts and other non-source files, which is pure quota waste). Do **not**
  use `--skip-snippets` to save quota for this repo's use case — snippet matching
  is precisely what detects locally-modified vendored code (the priority-1
  target).
- Decouple fingerprinting from scanning for resumability:
  `scanoss-py fingerprint <dir> -o tree.wfp` runs fully offline (no API calls),
  then `scanoss-py scan --wfp tree.wfp` posts it. On a rate-limit abort, the
  fingerprints survive and the scan can be re-run after `retry_after` without
  re-hashing the tree; splitting the `.wfp` on `file=` boundaries also allows
  resuming from where the 503 struck.

### New attribution data points from the same scans

The FreeRTOS umbrella repo is itself a vendoring aggregate, so these scans doubled as
fresh attribution evidence — all consistent with the 2026-07-08 pattern, and adding
one worse case:

- **Verbatim, unmodified third-party files can get an actively wrong license, not
  just a wrong repo**: all 64 files of Reliance-Edge (Datalight/Tuxera's filesystem,
  file headers plainly **GPLv2**-or-commercial) came back attributed to
  `pkg:github/freertos/freertos` with license **MIT** (`component_declared` of the
  containing repo). The 2026-07-08 tests needed a *modified* file to break license
  attribution; this shows byte-identical vendored files break it too whenever the
  matcher picks the aggregate repo. For a license-compliance consumer this is the
  worst failure mode: copyleft reported as permissive.
- **lwIP split across two containing repos**: the same `Demo/Common` scan attributed
  100 files to `pkg:github/ajaybhargav/lwip_nat` (a personal fork) and 72 to the
  canonical `pkg:github/lwip-tcpip/lwip` — one component, two purls, neither pinned
  to an lwIP release. Cross-file consistency checking would flag this immediately;
  per-file answers hide it.
- **CMSIS attributed to a personal Bitbucket mirror**: `pkg:bitbucket/rsherrymsa/cmsis-5`
  (5 files) beat `pkg:github/arm-software/cmsis_5` (3 files) within a single scan;
  other files went to one-off hobbyist repos (`ua3reo-ddc-transceiver`,
  `stm32cubeide-workshop-2019`).
- Minor but telling: OSSKB matched a Windows `ReadMe.url` shortcut file at 100% — the
  KB indexes everything in mined repos, so non-source noise comes back with confident
  matches and needs filtering client-side.

None of this changes the reuse-first stance; it sharpens open item 1 (attribution
post-processing) with a stronger requirement: the fix must work even for *verbatim*
files inside aggregate repos (Reliance-Edge case), not just modified ones, and item 3's
question — whether the offline dataset exposes **all** containing repos per fingerprint
— becomes the crux, since the lwIP/CMSIS splits show the API's single-repo answer is
close to arbitrary.

## What this means: recall vs. attribution are different problems

The empirical pattern is consistent: OSSKB answers **"which public repo contains code
matching this file?"** and answers it very well. It does not attempt what our
experiments do — resolve to a **canonical upstream component**, pin a **component
version**, or check **cross-file version consistency** ([general/README.md](README.md#multi-file-components-need-cross-file-corroboration-not-per-file-matching)):

- The returned repo is effectively arbitrary among the many repos containing the same
  file (the `ameba-rtos` result for an Espressif-patched mbedTLS file is the clearest
  case). This is the [attribution/stacked-components problem](README.md#attribution-vendored-integrations-are-often-multiple-stacked-components)
  reflected back at us from inside an external database.
- Reported "version" ranges are releases *of the containing repo*, not of the
  component (ESP-IDF v6.0.x tells you nothing about which FreeRTOS kernel version is
  inside without a second mapping step).
- Reported licenses are the containing repo's license inventory — actively misleading
  in the modified-file case, and only accidentally correct in the ST re-licensing case.
  (Consistent with the [license-divergence finding](README.md#detection-technique-patterns):
  license accuracy needs its own check regardless of what any content matcher says.)
- Per-file independent answers: no notion of "these five files should agree on a
  version," so the mixed-version integration case our experiments flag explicitly would
  come back as five unrelated matches.

## Tradeoffs for the eventual generator (build vs. reuse)

Reuse (OSSKB API or the CC0 dataset / self-hosted mined KB) buys:

- **Breadth we can never build**: coverage of *unanticipated* components — the long
  tail beyond whatever curated list we support. A file that matches OSSKB but no
  curated component is a high-value "unknown OSS present, needs investigation" signal.
- **Recall on modified copies for free** (the 84% snippet match above).
- Filename-independence (the cJSON negative control).
- The winnowing/WFP format is the same algorithm family our experiments already use,
  so fingerprints are conceptually compatible; `minr` even allows mining *our* curated
  component list into a self-hosted KB rather than hand-rolling storage.

Reuse does **not** buy (and curated per-component reference DBs remain necessary for):

- Canonical-upstream resolution (component identity, correct PURL — see
  [PURL/CPE granularity](README.md#sbom-identifiers-purl-and-cpe-disagree-on-granularity)).
- Component-version pinning and mixed-version detection (cross-file consistency).
- License accuracy on vendored/modified copies.
- Offline operation: the free API is online-only, against the repo's
  [offline-first requirement](README.md#recommended-default-offline-first-online-as-an-additive-fallback);
  the CC0 core dataset is downloadable but sized for a server, not an offline CLI
  bundle (it covers 2M repos). Also, scanning sends WFP fingerprints of (possibly
  proprietary) firmware source to a third-party service — fingerprints don't reveal
  code text, but some organizations' policies will treat even that as exfiltration.
- License-clean embedding: engine/minr/LDB are GPL-2.0 (process-boundary use is fine;
  linking into a differently-licensed product is not). The *dataset* being CC0 is the
  permissive part.

## Strategic stance (established 2026-07-08)

**Reuse-first.** Wherever an existing dataset/knowledge base can carry part of the
pipeline, prefer reusing it over building our own — we cannot realistically match the
effort the OSS community has already invested in mining (OSSKB alone indexes ~250M
URLs; Software Heritage archives essentially all public source). Building our own
artifacts (like this repo's curated per-component reference DBs) is justified only for
**demonstrated gaps** in what the existing datasets provide, not as the default.

The bar the datasets have to clear is set by the **end goal**: strategies to
efficiently *identify* components **and map their associated information** (canonical
identity/PURL/CPE, version, license, supplier) well enough to generate SBOMs — and for
those SBOMs to then drive **vulnerability scanning**. That last step is what makes the
attribution gap found above consequential rather than cosmetic: a vulnerability lookup
keyed on `pkg:github/oldes/rebol3` (or `pkg:github/ameba-aiot/ameba-rtos`) will not
surface mbedTLS CVEs. Identification without correct upstream mapping produces SBOMs
that *look* complete but fail their primary downstream consumer.

So the honest current status is: published datasets demonstrably cover the
recall/identification half; whether they can be made to cover the attribution/mapping
half **on top of their own data** (rather than replaced by curated DBs) is unproven
either way — this session only showed their *raw* output doesn't. That is the main
open investigation, deliberately left for future sessions:

### Open investigation items (future sessions)

1. **Attribution post-processing over reused data** — can OSSKB's "containing repo"
   answer be resolved to the canonical upstream automatically, staying reuse-first?
   Candidate mechanisms to test: querying with a component's *whole characteristic file
   set* and intersecting the returned repos; preferring the repo whose returned
   `file` path is shallowest (`library/aes.c` vs `src/core/mbedtls/aes.c` — the
   vendored copy sits deeper); fork-relationship lookups via the GitHub API; a small
   curated repo→upstream alias table (orders of magnitude cheaper than curating
   fingerprint DBs).
2. **Vulnerability-scanning fitness test** — take OSSKB's raw purl+version output for
   our ground-truth corpus and run it through OSV.dev; compare the CVE sets against
   what the *correct* upstream purl+version returns. This quantifies exactly how much
   the attribution gap costs at the vuln-scanning end, on real data.
3. ~~**The downloadable CC0 dataset** (`osskb-core-open-dataset`) — fetch and inspect~~
   **RESOLVED 2026-07-13** — inspected empirically, see
   [experiments/osskb-open-dataset](experiments/osskb-open-dataset/README.md) and
   the "Open-dataset inspection" section below. Verdict: the offline data exposes
   **one** exemplar URL per file hash plus a *count* of containing URLs — not the
   list. Attribution post-processing (item 1) cannot be built on it; the count is
   however a valuable new routing signal. Item 1 therefore depends on the hosted
   API, self-mining, or GitHub-side resolution — not on the offline dataset.
4. **Self-mining implications (`minr`) — designated next investigation
   (task added 2026-07-13, elevated by the open-dataset findings above).**
   With item 3 resolved negatively (the offline dataset can't carry attribution),
   self-mining is the remaining reuse-first path to an offline KB that *can*. The
   task, concretely:
   - **Baseline experiment**: mine the three researched components (FreeRTOS,
     mbedTLS, CMSIS — upstreams plus the known vendor forks from `components/*/
     corpus/`) into a self-hosted LDB KB with `minr`, and compare match quality
     against this repo's bespoke per-component reference DBs on the existing
     ground-truth corpus. If equivalent, the generator can adopt SCANOSS's open
     WFP/LDB format and tooling instead of a bespoke format.
   - **Attribution by construction**: when we choose what to mine, every mined URL
     is a known component/version — the arbitrary-exemplar problem disappears for
     curated components. Verify the mined KB reproduces what the curated DBs
     already do: canonical identity, version pinning, cross-file consistency
     inputs.
   - **The URL-list gap**: check whether mining the same file from multiple
     sources (upstream + several vendor forks) yields *all* containing URLs per
     hash in the local KB — i.e. whether self-mining recovers exactly the
     multiplicity data the open dataset withholds (its `count` field proves the
     full KB has it; item 3 showed the CC0 export drops it).
   - **Operational cost**: measure mining time, KB size, and update effort per
     component/release — the numbers that decide whether "mine the supported
     component list" scales to a company-standard scanner (the 50+-project
     scenario in the feasibility section above) or stays a research tool.
   - **License boundary**: `minr`/LDB/engine are GPL-2.0 — validate the
     service/process-boundary integration pattern (mine and query as separate
     processes; no linking into differently-licensed code) and document it as a
     constraint for the generator repo.
   - **Hybrid check**: can a `minr`-mined curated KB and the CC0 `file-url` table
     coexist in one lookup path (curated-first, open-dataset fallback with
     count-based routing), giving offline attribution for supported components
     *and* offline recall for everything else?
5. **Metadata-mapping layers** — evaluate ClearlyDefined and PurlDB as the
   "associated information" enrichment step (license, declared metadata) on top of
   whatever identification layer wins; also check Software Heritage's provenance
   (`whereis`) endpoints for earliest-occurrence data as a tiebreaker between
   containing repos.

## Open-dataset inspection (2026-07-13) — what the offline CC0 data actually is

Full experiment write-up:
[experiments/osskb-open-dataset](experiments/osskb-open-dataset/README.md)
(includes a clean-room ~60-line Python LDB shard reader and sampling stats).
Headline facts:

- Two LDB-format tables: `file-url` (~97 GiB — file MD5 → record) and `wfp`
  (~1.14 TiB — winnowing fingerprints), 256 hash-prefix shards each; downloadable
  per-shard, so targeted inspection cost only ~5.5 GiB (3 file-url shards +
  1 wfp shard).
- **`wfp` table inspected 2026-07-16**: an inverted index
  `32-bit winnowing hash → (file MD5, line)` pairs (~450M distinct hashes,
  ~64B records; ~143 records/hash mean, heavier for common C code). Format
  cracked clean-room; **offline snippet matching validated end-to-end** — the
  Espressif-modified `tasks.c` (exact MD5 absent from the snapshot) was pinned
  to its own esp-idf lineage by vote-across-snippet-hashes using one wfp shard
  plus the file-url shards. Modified-copy detection therefore *can* ride the
  offline dataset (at a 1.24 TiB storage price); attribution still can't.
  Note the wfp shards (2025-Jul-03) are ~3 months staler than file-url —
  the two tables aren't mutually consistent snapshots.
- **Snapshot staleness is material**: dataset `version.json` says KB `25.09.28`,
  while the hosted API served KB `26.07.13` the same day — the open data trails
  the live KB by ~9.5 months.
- **Record schema is `path, exemplar-URL, count`** — one arbitrary containing URL
  (in a 23k-record sample: 100% GitHub archive zips), plus a count of how many
  URLs the KB knows contain the file (median 3, p99 210, max 12,486; 38% count=1).
  No purl, no license, no version, no component name, no full URL list.
- Ground-truth lookups mirror the API's attribution behavior: upstream-identical
  `core_cm4.h` → an **arduino-pico release zip** (count 1564); ESP-IDF's patched
  `bignum.c` → the esp-idf zip (right vendor by luck — the API said Realtek
  `ameba-rtos` for the same hash); Reliance-Edge `core.c` → **absent entirely**
  (recall gap vs the hosted KB, which matches it 100%).

Net: the open dataset is an offline **recall oracle with a spread indicator**, not
an attribution source. The count field is real added value (count 1 → exemplar URL
is probably the true origin; high count → ubiquitous file, exemplar meaningless,
canonical resolution mandatory) — a signal the hosted API doesn't even return.

## Feasibility: OSSKB as the backbone of a company-standard SBOM scanner (assessed 2026-07-13)

Scenario assessed: an internal SBOM generator rolled out as the standard across
50+ projects with large codebases. Conclusions from the empirical work above:

- **Free API tier: not viable as the standard path.** The anonymous quota
  (10k calls/hour) is per-location and shared: all CI runners and developers
  behind one corporate NAT share a single bucket, one inefficient client locks
  everyone out for ~5 hours (demonstrated first-hand), and there is no SLA. Fine
  for research, prototyping, occasional scans.
- **Sponsored tier (50k/hour): arithmetically workable, structurally fragile.**
  Same shared bucket, same lockout failure mode, same no-SLA fair-use terms, and
  the same data-egress objection (WFP fingerprints of proprietary firmware leave
  the network). Usable as a transition step, not as a foundation.
- **Open dataset only (no self-hosted SCANOSS services): not sufficient alone.**
  CC0 licensing, fully offline, no rate limits, no egress — the best operational
  profile of all options, and the `file-url` table is trivially hostable
  (97 GiB). But per the inspection above it carries no attribution metadata at
  all, misses files the live KB has, and trails it by months. It can serve as the
  offline Tier-3 recall net + count-based routing signal — nothing more.
- **What a company-grade architecture actually needs**: (a) an identification
  layer — offline `file-url` exact-hash + (if snippet recall on modified code is
  required) either the `wfp` table with a custom matcher (validated feasible
  2026-07-16 — a few hundred lines of Python, no GPL runtime; see the
  experiment) or a self-hosted GPL engine behind a service boundary; (b) an attribution layer — this repo's
  curated per-component reference DBs and/or `minr`-mined KBs of the supported
  component list (open item 4), since neither API nor dataset provides canonical
  identity; (c) incremental scanning with content-hash caching so re-scans only
  touch changed files; (d) if the hosted API is used at all, WFP batching, paced
  request rates, and `retry_after`-aware backoff (see the `scanoss-py`
  configuration section above).

## Recommendation (interim, pending the investigation above)

Slots into the existing [two-tier design](README.md#recommended-default-offline-first-online-as-an-additive-fallback)
as a **third, additive layer**, with the reuse-first caveat that Tier 2's long-term
form depends on how investigation items 1–4 turn out:

1. **Tier 1 (unchanged)** — bundled structural/metadata signals per curated component.
2. **Tier 2** — attribution, version pinning, cross-file consistency, and license
   checks. Currently only our curated per-component reference DBs are *proven* to do
   this; whether a reused dataset plus post-processing can replace or shrink this
   layer is exactly open items 1–3. Until then the curated DBs stay the validated
   mechanism — but should be treated as the gap-filler, not the center of gravity.
3. **Tier 3 (new, optional)** — OSSKB as a breadth/recall net for files matching no
   curated component: emit "unidentified OSS detected (containing repos: …)"
   findings and use them as the signal for which component to support next. Two
   forms, now both validated: the online API (full KB, freshest, rate-limited,
   egress concerns) and the offline CC0 `file-url` table (97 GiB, self-hostable,
   ~9-month-stale snapshot, exact-hash only — but adds the containing-URL *count*
   as a routing signal: count 1 → trust the exemplar URL as origin; high count →
   requires canonical resolution). Software Heritage's exact-hash lookup is a
   second free oracle for "is this exact file public?"
