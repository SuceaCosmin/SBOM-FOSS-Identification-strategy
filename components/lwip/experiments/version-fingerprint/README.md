# lwIP version fingerprinting (phase 2)

**Question**: given a vendored lwIP source tree, can exact-hash + winnowing similarity
over a small set of tracked core files pin the upstream release it came from — including
when a silicon vendor has patched it, and *without* trusting the version macro?

**Answer**: yes, on all seven corpus entries, and two of the results are only correct
*because* the version macro was not trusted. Two findings came out of it that generalize
beyond lwIP: upstream's own git tags contain a **phantom release** that no shipped
artifact ever matched, and **basename-keyed file matching is unsafe** for this component.

## Approach

Same two-tier scheme as the FreeRTOS / Mbed TLS / CMSIS experiments, shared verbatim via
the `research-component` skill template ([lwip_fingerprint.py](lwip_fingerprint.py)):
comments stripped and whitespace collapsed, then (1) SHA-256 of the normalized text for
exact matching and (2) winnowing fingerprints (30-char grams, 50-gram windows) compared by
Jaccard similarity for modified copies.

Two things differ from the template, both forced by phase-1 evidence — see
[../../README.md](../../README.md) sections 3 and 7.

### Tracked files, picked by measurement

Discrimination was measured before choosing: for each candidate file, how many *distinct*
normalized contents it has across the 11 releases from 1.4.1 to 2.2.1 (higher = separates
more releases).

| Tracked file | Distinct contents / 11 releases | Why it's in the set |
|---|---|---|
| `src/include/lwip/init.h` | 10 | version-macro carrier **and** top discriminator |
| `src/core/tcp.c` | 10 | top discriminator |
| `src/core/tcp_in.c` | 9 | |
| `src/core/init.c` | 9 | |
| `src/api/sockets.c` | 9 | covers the socket API layer, absent in raw-API-only trees |
| `src/core/pbuf.c` | 8 | **untouched by all four real forks** — the base-version anchor |
| `src/core/udp.c` | 8 | |

Rejected despite being obvious candidates: `src/core/ip.c` (2 distinct contents across 11
releases — nearly useless), `src/core/sys.c` and `src/core/inet_chksum.c` (4). Deliberately
narrow research scope: 7 files out of ~90 in `src/`, not a claim to be *the* minimal lwIP
signature set.

`pbuf.c` earning its place was a prediction from phase 1 (none of ST, Espressif, NXP or
Xilinx patch it) that the corpus then confirmed: it is the file that pins the base release
in two of the three modified-fork cases.

### Files are located by path suffix, not basename

lwIP is the first component here where basename matching is actively wrong. ST's shipped
middleware contains its own port header `system/arch/init.h` next to upstream's
`src/include/lwip/init.h`; upstream itself has both `lwip/init.h` and `core/init.c`. So
tracked files are matched on path suffix (`lwip/init.h`, `core/init.c`, …).

Measured consequence: scoring ST's `system/arch/init.h` (1804 bytes of ST port code)
against the reference DB as if it were `lwip/init.h` yields **0.000 similarity to every
release**. A basename-keyed scan that happened to walk into `system/` first would
therefore trip the no-similarity floor and report **NOT_THIS_COMPONENT for a tree whose
lwIP core is byte-identical to upstream 2.1.3** — a false negative on a real, shipping
vendor tree.

### Anchor quorum

Requiring all 7 files reports INCOMPLETE for legitimately partial vendoring (raw-API-only
trees ship no `src/api/`). Instead ≥2 of the 3 anchors (`lwip/init.h`, `core/tcp.c`,
`core/pbuf.c`) must be present to claim lwIP at all; every other present tracked file
tightens the version intersection. Same design as the widened FreeRTOS 7-file DB.

## Reference DB size

17 release tags (1.3.0 → 2.2.1) × 7 files → **792 KiB**, 91 unique file-contents
(15 `init.h`, 14 `tcp.c`, 13 `tcp_in.c`, 13 `init.c`, 13 `sockets.c`, 12 `pbuf.c`,
11 `udp.c`). Measured, not assumed — see
[general/README.md](../../../../general/README.md#reference-db-size-scales-with-component-shape-not-a-fixed-constant).

For comparison: FreeRTOS core-file DB 1.7 MB (7 files × 62 tags), its port DB 6.6 MB.
lwIP lands small because the release count is small — 17 releases in 22 years. Note the
unique-content counts are *below* the tag count for every file: adjacent releases leave
several tracked files untouched, which is exactly why single-file matching is
insufficient and cross-file intersection does the real work here.

Built from a **local clone** (`build_reference_db.py --clone <dir>`) rather than
per-file HTTP fetches — the repo is 23 MB and it removes the rate-limit pacing entirely.

## Results

Seven corpus entries, all resolving as expected. `Detected` is what the matcher output;
`Ground truth` is what phase-1 diffing established independently.

| Corpus entry | What it is | Ground truth | Detected | Verdict |
|---|---|---|---|---|
| `st-stm32-mw-2.1.3` | ST `stm32-mw-lwip` @ `v2.1.3_20241213`, plus its `system/arch/` port files as decoys | verbatim 2.1.3 | **CONFIRMED 2.1.3** | ✅ all 7 files exact; decoy `system/arch/init.h` correctly ignored |
| `savannah-zip-2.0.2` | the official `lwip-2.0.2.zip` from Savannah | 2.0.2 as actually released | **CONFIRMED 2.0.2** (via `STABLE-2_0_2_RELEASE_VER` only) | ✅ phantom tag excluded by cross-file intersection |
| `esp-lwip-2.2.0-esp` | Espressif fork, 54 patched files | 2.2.0 base | **PARTIALLY_MODIFIED 2.2.0** | ✅ `pbuf.c` exact-pins the base; 6 files modified |
| `nxp-mcux-2.16.100` | NXP fork, 102 patched files | post-2.2.0 master (declares 2.2.1-dev) | **PARTIALLY_MODIFIED 2.2.1** | ✅ pinned by `pbuf.c`/`tcp_in.c`; *not* reported as "MCUX_2.16.100" |
| `xilinx-lwip220` | AMD/Xilinx `embeddedsw` `lwip220` | 2.2.0, 7/20 core files patched | **PARTIALLY_MODIFIED 2.2.0** | ✅ agrees with the `lwip-2.2.0/` path claim, independently of it |
| `mixed-version-synthetic` | `init.h`+`sockets.c` from 2.1.2, core from 2.0.3 | deliberately mixed | **MIXED_VERSION** {2.0.2, 2.0.3, 2.1.1, 2.1.2} | ✅ no common release; both eras surfaced |
| `negative-control-cjson` | cJSON 1.7.18 saved under every tracked path | not lwIP | **NOT_THIS_COMPONENT** (all scores 0.000) | ✅ |

## Finding 1: upstream's tag set contains a phantom release

`STABLE-2_0_2_RELEASE` and `STABLE-2_0_2_RELEASE_VER` are two different commits. They
differ in exactly one line of one file:

```
-#define LWIP_VERSION_REVISION   1        (STABLE-2_0_2_RELEASE)
+#define LWIP_VERSION_REVISION   2        (STABLE-2_0_2_RELEASE_VER)
```

So the commit tagged `STABLE-2_0_2_RELEASE` **declares itself to be 2.0.1**; upstream
noticed and re-tagged the fix as `..._VER`. Downloading the official
`lwip-2.0.2.zip` from Savannah and comparing all 7 tracked files settles which one
shipped: the zip is byte-identical to `STABLE-2_0_2_RELEASE_VER`, and differs from
`STABLE-2_0_2_RELEASE` in `init.h` alone (the other six files are identical in all three).

Two consequences, both general:

- **Git tags are not release artifacts.** A reference DB mined from tags — ours, and any
  tag-mining KB such as the `minr` pipeline — contains a "2.0.2" entry that no shipped
  artifact ever matched. For projects that release by zip rather than by tag (lwIP here;
  FatFs per the roadmap is the extreme case) the mined tag needs to be validated against
  the published artifact, or the artifact mined directly.
- **Cross-file intersection repairs it for free.** The `savannah-zip-2.0.2` entry resolves
  to `STABLE-2_0_2_RELEASE_VER` alone, not because anything special was coded, but because
  6 of 7 files match both tags and `init.h` matches only one — the intersection eliminates
  the phantom. This is the strongest argument yet for the repo's cross-file consistency
  rule: it corrects an error in the *reference data*, not just in the target.

Both tags are deliberately kept in the DB rather than pruned. Pruning would hide the
evidence; the matcher maps both to version `2.0.2` and the intersection disambiguates.

## Finding 2: the version macro is wrong or misleading in 3 of 7 corpus entries

`LWIP_VERSION_MAJOR/_MINOR/_REVISION/_RC` is the cleanest declared-version signal of any
component researched here — and trusting it would have produced a wrong answer three times:

| Tree | Version macro says | Content says | |
|---|---|---|---|
| `STABLE-2_0_2_RELEASE` (upstream tag) | 2.0.1 | 2.0.2 | upstream's own un-bumped macro |
| `esp-lwip-2.2.0-esp` | 2.2.0**d** (DEVELOPMENT) | 2.2.0 | Espressif flips `_RC` to `LWIP_RC_DEVELOPMENT` |
| `nxp-mcux-2.16.100` | 2.2.1**d** | 2.2.1 base, heavily patched | tag name says `MCUX_2.16.100`, an SDK version |

The `d` (DEVELOPMENT) suffix is genuine information rather than an error — it means "a git
snapshot between releases", which a version *window* can express and a point version
cannot. Recorded as corroboration-tier evidence, per
[general/README.md](../../../../general/README.md#detection-technique-patterns).

## Known limitations / next steps

- **Adjacent releases are not always separable.** `udp.c` is identical across 2.0.2 and
  2.0.3; `pbuf.c` across 2.0.2/2.0.3. Any single-file match in that era returns a set,
  not a point. The 7-file intersection resolves the corpus cases, but a tree vendoring
  only `src/core/` from that era may legitimately stay a 2-release window.
- **1.3.0 has no version macros at all** (`LWIP_VERSION_*` was introduced in 1.3.1), so
  the oldest release in the DB is content-matchable but not self-declaring.
- **The port layer is not covered here.** `arch/cc.h`, `sys_arch.c` and `lwipopts.h` are
  project-authored by lwIP's porting contract, so they are neither matched nor scored.
  Whether lwIP needs its own port-layer detector (as FreeRTOS got, because a CVE was
  scoped to a port) is answered in phase 3 — see
  [../../README.md](../../README.md) section 8.
- **`src/netif/ppp/polarssl/` is untracked**, so the vendored PolarSSL 0.10.1 subtree
  documented in phase 1 is invisible to this experiment. Detecting it is a
  *different* component's job, not a wider lwIP file set.
- Winnowing thresholds are the shared template defaults (30/50), never tuned against
  lwIP's file sizes; the observed modified-fork similarities (0.93–0.99) sit far from the
  0.05 floor, so no tuning pressure showed up.
- Only release tags are in the DB. A vendor that forks from master between releases (NXP
  effectively does) is reported as its nearest release plus PARTIALLY_MODIFIED, which is
  the honest answer but not a precise one.

## Files

- [`lwip_fingerprint.py`](lwip_fingerprint.py) — normalization, hashing, winnowing
  (shared algorithm, unmodified from the skill template).
- [`build_reference_db.py`](build_reference_db.py) — mines the 7 tracked files across 17
  release tags from a local clone → `reference/lwip_fingerprints.json`.
- [`match_target.py`](match_target.py) — suffix-keyed scan + anchor quorum + cross-file
  consistency. Exposes a print-free `resolve_group()` / `scan_tree()` API for phase 3.
- [`reference/lwip_fingerprints.json`](reference/lwip_fingerprints.json) — the DB
  (pretty-printed per repo convention).
- [`../../corpus/`](../../corpus/) — the seven ground-truth trees.
