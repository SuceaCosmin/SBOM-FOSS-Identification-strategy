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
| [osskb-core-open-dataset](https://github.com/Software-Transparency-Foundation/osskb-core-open-dataset) | Downloadable fingerprints of ~2M most-popular GitHub repos, via HTTPS/FTP (`osskb.st.foundation`) | Same WFP format | Yes — **CC0-1.0**, unrestricted |
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

## Strategic stance (established with Cosmin, 2026-07-08)

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
3. **The downloadable CC0 dataset** (`osskb-core-open-dataset`) — fetch and inspect:
   actual size, record format, and critically whether the offline data exposes *all*
   containing repos per fingerprint (the free API returns one), which would make
   attribution post-processing (item 1) much stronger.
4. **`minr` self-hosting experiment** — mine our three researched components into a
   self-hosted LDB knowledge base and compare match quality against this repo's
   bespoke reference DBs; if equivalent, the generator can adopt SCANOSS's open
   WFP/LDB format instead of a bespoke one (reuse of *format and tooling*, not just
   data).
5. **Metadata-mapping layers** — evaluate ClearlyDefined and PurlDB as the
   "associated information" enrichment step (license, declared metadata) on top of
   whatever identification layer wins; also check Software Heritage's provenance
   (`whereis`) endpoints for earliest-occurrence data as a tiebreaker between
   containing repos.

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
3. **Tier 3 (new, optional, online)** — OSSKB (or a self-hosted mined KB) as a
   breadth/recall net for files matching no curated component: emit "unidentified OSS
   detected (containing repos: …)" findings and use them as the signal for which
   component to support next. Software Heritage's exact-hash lookup is a second free
   oracle for "is this exact file public?"
