# zlib

All three phases of the
[`research-component`](../../.claude/skills/research-component/SKILL.md) workflow
(distro landscape, version fingerprinting, advisory-source mapping), run 2026-08-18. Picked as roadmap
[Tier 1 #2](../../general/component-roadmap.md) after lwIP, for two detection questions no
component researched so far has stressed: **partial (subset) vendoring** and **identifier
renaming**. This document is phase 1; phase 2 is
[experiments/version-fingerprint](experiments/version-fingerprint/README.md).

Every distribution claim below was verified against real source — upstream tags cloned
from `github.com/madler/zlib`, the fork trees fetched at their current `master`/`main`,
and diffed. Where a fork's own provenance file disagrees with the diff, both are stated.

**Headline for this component**: zlib's version-declaring *header* is routinely deleted or
gutted by exactly the carriers most likely to appear in embedded firmware, so the
`ZLIB_VERSION` anchor that carried FreeRTOS, mbedTLS and lwIP detection is not available.

> **Refined by [phase 2](experiments/version-fingerprint/README.md) (same day).** zlib
> declares its version in **three** independent places, not one: `ZLIB_VERSION` in
> `zlib.h`, and two **string literals** — `inflate_copyright[]` in `inftrees.c` and
> `deflate_copyright[]` in `deflate.c` (`" inflate 1.3.2 Copyright 1995-2026 Mark Adler "`).
> Being literals rather than comments, they survive comment-stripped normalization, and
> they are why those two files separate all 55 releases. **No carrier keeps all three, and
> two carriers keep none** — U-Boot retains only `deflate_copyright` (and it says 1.2.5,
> contradicting U-Boot's own prose claim of 1.2.3); the Linux kernel deletes all three.
> The operative conclusion is unchanged — the verdict must come from content — but the
> declared strings are a real corroboration signal where they survive, and a real
> *falsehood* where zlib-ng supplies one.

Section 7 below states the detection implications; phase 2 tested them.

---

## 1. Governance and licensing history

- **Authors**: Jean-loup Gailly (deflate side) and Mark Adler (inflate side), first
  released 1995. Mark Adler is effectively the sole active maintainer today.
- **Canonical home**: `https://zlib.net`. **Canonical VCS**: `github.com/madler/zlib` —
  a personal-account repo, not an organization. This matters for PURL stability: unlike
  the `ARMmbed` → `Mbed-TLS` rename that shifted mbedTLS's purl, zlib's coordinate has
  never moved, but it is anchored to one person's GitHub account.
- **License**: the zlib License (SPDX `Zlib`), permissive, unchanged for the project's
  entire history. **No dual-licensing**, so the license-divergence failure mode found on
  ST's mbedTLS fork (a single-license re-release invisible to comment-stripped matching)
  has no upstream basis here. No fork examined re-licensed the core.
- **Copyright-line era heuristic**: the notice reads `(C) 1995-<year>`, and the trailing
  year advances with releases (`1995-2026` at v1.3.2). This is the cheap version-era
  signal described in [general/README.md](../../general/README.md#detection-technique-patterns),
  and it is present in nearly every source file's header — but see §7, several carriers
  keep a stale year from the era they branched at, which makes it an *era* signal, never
  a version signal.
- **Release cadence and the 4-component version**: releases were sparse for years
  (1.2.11 Jan 2017 → 1.2.12 Mar 2022), then 1.2.13 (Oct 2022), 1.3 (Aug 2023), 1.3.1
  (Jan 2024), **1.3.1.2 (Dec 2025)**, **1.3.2 (Feb 2026)**. Note the four-component
  `1.3.1.2`: historically zlib used `x.y.z.n` tags for *development snapshots* between
  releases (`v1.2.3.4`, `v1.2.4-pre1`, …), and 78 of the repo's tags are of that kind.
  A reference DB must decide which tags are releases; see §7.

**Git tags vs. released artifacts — checked, and clean.** The lwIP pass found a *phantom*
release tag whose content no shipped artifact ever matched, so this was verified rather
than assumed: `zlib-1.3.1.tar.gz` from `zlib.net/fossils/` was diffed file-by-file against
git tag `v1.3.1`. All 8 core sources plus `zlib.h` are **byte-identical**, and the tarball
contains no file absent from the tag. zlib's tags are trustworthy release artifacts —
the opposite of lwIP's result, and a useful data point that the
[general note](../../general/README.md#git-tags-are-not-release-artifacts--validate-one-against-the-other-before-mining)
prescribes *validation*, not suspicion.

## 2. Component granularity

zlib is a **single component with one nested sub-component that has its own CVE stream**.

- The **core** (root directory) is one coherent library: `adler32.c crc32.c deflate.c
  infback.c inffast.c inflate.c inftrees.c trees.c zutil.c` plus the gz-file layer
  (`gzclose.c gzlib.c gzread.c gzwrite.c`) and the convenience wrappers
  (`compress.c uncompr.c`). One version number covers all of it.
- **`contrib/minizip`** is a *different project by a different author* — Gilles Vollant's
  MiniZip, with Zip64 work by Even Rouault and Mathias Svensson, and its **decryption code
  derived from Info-ZIP's `crypt.c`** (upstream added an explicit `LICENSE.Info-Zip` file
  to that directory in 1.3.2). It ships inside the zlib tarball, has no independent
  version number there, and is very commonly copy-pasted *standalone* into projects.
- `contrib/` also carries several other independently-authored pieces
  (`blast`, `puff`, `infback9`, `ada`, `delphi`, `dotzlib`, `iostream*`, `pascal`,
  `testzlib`, `crc32vx`). Most are not C libraries anyone vendors, but **`puff.c`** is —
  it is a tiny standalone inflate implementation that shows up in bootloaders precisely
  because it is small.

This is the third confirmation of the
[stacked-components rule](../../general/README.md#attribution-vendored-integrations-are-often-multiple-stacked-components):
lwIP vendors PolarSSL and pppd; zlib vendors MiniZip which vendors Info-ZIP. **Unlike the
lwIP case, this one has direct advisory consequences** — see §4.

## 3. What layers stack on top — four real carriers, four different shapes

Diffs below are `diff | grep -c '^[<>]'` (changed lines, both directions) between the
fork's file and the named upstream tag.

### 3.1 U-Boot (`lib/zlib/`) — amalgamation by `#include`, version header deleted

U-Boot's `lib/zlib/zlib.c` is not a source file in the ordinary sense; it is a **build
amalgamation** that `#include`s the individual `.c` files:

```c
/* This file is derived from various .h and .c files from the zlib-1.2.3
 * distribution ... with some additions by Paul Mackerras to aid in
 * implementing Deflate compression and decompression for PPP packets.
 * ... added Z_PACKET_FLUSH ... added inflateIncomp
 */
#ifdef CONFIG_GZIP_COMPRESSED
#include "deflate.c"
#include "trees.c"
#endif
#include "inffast.c"
#include "inftrees.c"
#include "inflate.c"
#include "zutil.c"
#include "adler32.c"
```

Three findings from this one file:

- **This is the repo's first real amalgamated case.** CLAUDE.md names amalgamation as
  priority detection pattern #2; every component researched so far turned out not to have
  one (lwIP: "not a release shape"). U-Boot's is *conditional* amalgamation — whether
  `deflate.c`/`trees.c` are part of the translation unit depends on a Kconfig symbol.
  The individual files are still present on disk, so per-file fingerprinting still works
  here; what breaks is any assumption that one `.c` file equals one compilation unit.
- **The Paul Mackerras lineage is the pppd lineage** — the same pppd whose reduced fork
  the [lwIP research](../lwip/README.md) found vendored inside lwIP's `src/netif/ppp/`.
  `Z_PACKET_FLUSH` and `inflateIncomp` are pppd-specific extensions to zlib, so U-Boot's
  copy is not plain zlib-1.2.3 but *pppd's patched zlib-1.2.3*, re-vendored. A detector
  that reports "zlib 1.2.3" here is right about the base and blind to the intermediary.
- **The version macro is gone.** `lib/zlib/zlib.h` is a 17-line glue shim that includes
  `include/u-boot/zlib.h`; that real header is 757 lines derived from upstream's `zlib.h`
  *and* `zconf.h` merged together, and it contains **no `ZLIB_VERSION`, `ZLIB_VERNUM`, or
  any `ZLIB_VER_*` macro at all**. Only a prose comment near the top says "derived from
  zlib-1.2.3".

Nearest-upstream sweep on `inflate.c` (changed lines vs each tag) bottoms out where the
comment claims, but not tightly:

| tag | v1.2.1 | v1.2.2 | **v1.2.3** | v1.2.3.3 | v1.2.4 | v1.2.8 | v1.2.11 | v1.3.2 |
|---|---|---|---|---|---|---|---|---|
| changed lines | 526 | 522 | **510** | 633 | 730 | 810 | 891 | 815 |

510 changed lines at the minimum: this is a **heavily modified** copy, not a patched one.

### 3.2 Linux kernel (`lib/zlib_inflate/`, `lib/zlib_deflate/`) — renamed subset, two eras in one tree

The kernel's copy is the case the roadmap wanted: a **genuine source-level identifier
rename**, applied with a consistent `zlib_` prefix directly in the `.c` files —
`zlib_inflate()`, `zlib_inflateInit2()`, `zlib_inflate_table()`, `zlib_inflateEnd()`.
This is *not* the `Z_PREFIX` mechanism (see §5); the sources themselves were rewritten.

It is also a **subset**: the inflate side keeps `inflate.c inftrees.c inffast.c` and adds
kernel-only `infutil.c/.h` and `inflate_syms.c` (EXPORT_SYMBOL glue); the deflate side is
restructured into `deflate.c deftree.c defutil.h` — file names that no upstream zlib
release ever had. `infback.c`, `gz*.c`, `compress.c`, `uncompr.c`, `crc32.c` are absent.

The decisive finding is in `include/linux/zlib.h`:

```c
/* zlib deflate based on ZLIB_VERSION "1.1.3" */
/* zlib inflate based on ZLIB_VERSION "1.2.3" */
```

**Two different base versions coexisting in one vendored copy** — a real-world mixed-version
tree, not the synthetic kind this repo has been building for corpus validation. Corroborated
by content: retained `infutil.h` carries a `1995-1998` copyright, i.e. zlib 1.1.x vintage,
and the 1.1.x-era file names survive on the deflate side. Note again there is **no
`ZLIB_VERSION` macro** here either — only these two comments.

The nearest-upstream sweep on the kernel's `inflate.c` puts the minimum at **v1.2.2 (812
changed lines)**, not the claimed v1.2.3 (878) — but the spread across v1.2.1/1.2.2/1.2.3
is ~8%, and the file has been restructured for static allocation plus s390 DFLTCC hooks.
The honest reading is that **raw line-diff distance is not a usable base-version estimator
for a heavily restructured subset**; it ranks tags but does not discriminate them. That is
precisely the question phase 2's winnowing similarity has to answer, and this tree is the
adversarial input for it.

### 3.3 Chromium (`third_party/zlib/`) — near-verbatim core, modification lives in *added* files

The reputation of Chromium's zlib is "heavily modified". Measured against **v1.3.2**, the
core is nearly untouched:

| file | changed lines | file | changed lines |
|---|---|---|---|
| `uncompr.c` | **0** | `trees.c` | 54 |
| `zutil.c` | 1 | `crc32.c` | 165 |
| `inftrees.c` | 4 | `deflate.c` | 286 |
| `inflate.c` | **10** | `zlib.h` | 43 |
| `compress.c` | 11 | `zconf.h` | 19 |
| `inffast.c` | 23 | `adler32.c` | 33 |

The heaviness is concentrated exactly where SIMD hooks were inserted (`deflate.c`,
`crc32.c`) and otherwise absent. The *real* modification surface is **files upstream does
not have**: `adler32_simd.c`, `crc32_simd.c`, `crc_folding.c`, `slide_hash_simd.h`,
`cpu_features.c`, `chromeconf.h`, plus `contrib/` variants like `inffast_chunk*`.

Chromium also ships the best provenance artifact seen in this repo so far —
`README.chromium`:

```
Version: 1.3.2
Revision: 09a1572aa624e5ddb6c075dc013880de70b1b9b9
CPEPrefix: cpe:/a:zlib:zlib:1.3.2
License: Zlib
```

plus a `patches/` directory with 20 named patch files enumerating every local change. A
declared **upstream commit SHA** and a declared **CPE** are exactly the harvest-tier inputs
the [TI static-lib work](../../general/experiments/static-lib-identification/README.md)
identified — and here, unlike TI's manifest, spot-checking says it is accurate. It remains
a corroboration tier, not a substitute: it is a file a vendor can forget to update, and a
downstream re-vendorer will usually drop it.

### 3.4 zlib-ng — a rewrite that *declares itself to be zlib*

`zlib-ng/zlib-ng` is a separate project (own maintainer, own repo, own 2.x version line,
C11 rewrite with wide SIMD support), not a fork that tracks upstream. Its own header
declares `ZLIBNG_VERSION "2.3.90"`. But its **zlib-compat mode** emits a `zlib.h` whose
version macros read:

```c
#define ZLIB_VERSION "1.3.1.zlib-ng"
#define ZLIB_VERNUM 0x131f
```

So a metadata/string-heuristic detector keying on `ZLIB_VERSION` reports **"zlib 1.3.1"**
for a codebase that is not zlib 1.3.1, does not share its code, and has its own advisory
stream. This is the exact inverse of the
[nested-component false positive](../../general/experiments/nested-component-attribution/README.md):
there, code matched but the name was wrong; here, the *name and version string match
exactly* while the code does not. It is a strong argument that the metadata tier must stay
**confirm-only** (as CLAUDE.md already scopes it) and can never be promoted to a primary
identity signal — and it is a ready-made corpus entry for phase 2's negative-control slot,
far more adversarial than an unrelated C file.

### 3.5 MCU vendor SDKs — checked, and mostly absent

Contrary to the pattern for mbedTLS/CMSIS/lwIP (bundled in every silicon-vendor SDK), zlib
is **not** broadly present in MCU-class SDKs:

- **TI SimpleLink CC13xx/CC26xx SDK 8.33.00.16** (installed locally, the same tree used for
  the static-lib work): no zlib, no `inflate.c`, nothing zlib-named anywhere in the tree.
- **NXP MCUXpresso** (`nxp-mcuxpresso/mcux-sdk`): no zlib middleware component.
- **ESP-IDF**: no zlib in the framework tree. The only Espressif-hosted copy is inside
  `espressif/binutils-esp32ulp` — i.e. zlib vendored into **GNU binutils**, which is in
  turn vendored into a toolchain distribution. A three-level nesting, and a reminder that
  *toolchains shipped alongside firmware* are a carrier class of their own.

Read-across: zlib's embedded footprint is concentrated in **bootloaders (U-Boot),
OTA/update paths, Linux-class carriers, and application-processor stacks**, not in
Cortex-M vendor middleware. That shifts where corpus effort should go in phase 2 and is
worth flagging against the roadmap's automotive-first prioritization — zlib is very common
in vehicles, but mostly on the Linux/IVI/telematics side rather than in classic ECU
firmware.

## 4. Naming a detected zlib component in an SBOM

**PURL**: `pkg:github/madler/zlib@<version>`. `pkg:generic/zlib` is the alternative when
provenance is a tarball rather than the repo.

**CPE**: `cpe:2.3:a:zlib:zlib` is the live coordinate. The NVD dictionary also contains a
**fully deprecated `cpe:2.3:a:gnu:zlib` line** covering 1.0 through 1.2.11 — a
misattribution (zlib is not a GNU project) that was retired in favour of the `zlib:zlib`
vendor. Both appear in `keywordSearch=zlib` results, so a mapping layer must pick the
non-deprecated one rather than the first hit. This is a fourth instance of the
[PURL/CPE disagreement note](../../general/README.md#sbom-identifiers-purl-and-cpe-disagree-on-granularity).

**GHSA per-repository feed** (`/repos/madler/zlib/security-advisories`): **empty**. Upstream
does not self-publish advisories, so the path that worked for FreeRTOS-Kernel does not
apply — NVD/CPE is the source for zlib. Recorded as coverage, not as "no known vulns".

### Two advisory findings that matter more than the CVE list

**(a) The CVE's own prose disclaims what its CPE asserts.** `CVE-2023-45853` is a MiniZip
flaw. Its NVD description says, verbatim:

> MiniZip in zlib through 1.3 has an integer overflow ... **NOTE: MiniZip is not a
> supported part of the zlib product.**

Yet the only zlib-side machine-readable binding on the record is
`cpe:2.3:a:zlib:zlib:*` with `versionEndExcluding 1.3.1`. So **any** tree detected as zlib
< 1.3.1 is reported AFFECTED — including the very common case of a tree that vendored only
the core and never took `contrib/minizip` at all. The machine coordinate over-claims
relative to the record's own text, and the only thing that can resolve it is **sub-component
detection**: is `contrib/minizip` actually present? This is the same shape as FreeRTOS's
ARMv7-M-MPU-only CVE-2024-28115 — an applicability condition expressed in prose while the
range is expressed in machine-readable form — now on a third component, and here the
condition is *which files were vendored* rather than which port.

**(b) A zlib CVE's CPE list is dominated by carriers.** `CVE-2018-25032` carries ~75 CPE
matches; exactly **one** is `zlib:zlib`, the rest are downstream products that bundle it
(Python, MariaDB, Node.js, Apple OSes, NetApp appliances, Siemens SCALANCE switches, Azul
Zulu, Oracle). This is the **mirror image** of the lwIP finding that advisories are often
filed *against the carrier instead of* upstream: for zlib both bindings exist. Practically
this is good news for us — querying `cpe:2.3:a:zlib:zlib` with a detected version is precise
and unambiguous — but it confirms that identity → CPE is one-to-many in both directions
(architecture rec. 11's carrier clause).

**(c) A prose-only applicability condition on the other headline CVE too.**
`CVE-2022-37434`: "*NOTE: only applications that call `inflateGetHeader` are affected.*"
Not expressible in any range field; recorded, not evaluated — deciding whether a given
firmware calls that function is triage, which is
[explicitly not this repo's job](../../CLAUDE.md).

## 5. `Z_PREFIX` is not a source-level rename — the roadmap's premise was half wrong

The roadmap entry motivating this component said zlib is "often vendored with
`Z_PREFIX`-style renaming — stresses partial-copy and identifier-rename tolerance". The
partial-copy half is right (§3.2, §6). The rename half needs correcting.

`Z_PREFIX` is a **compile-time macro remap declared entirely inside `zconf.h`**:

```c
#ifdef Z_PREFIX
#  define adler32               z_adler32
#  define deflate               z_deflate
#  define inflate               z_inflate
   ... ~130 more
#endif
```

The `.c` files are **not modified at all**. Consequences, and they point in opposite
directions per tier:

- **Source-hash / winnowing tier: unaffected.** A `Z_PREFIX`-built zlib is byte-identical
  to a normal one except that `./configure --zprefix` may flip the `#ifdef` to `#if 1` in
  the shipped `zconf.h`. Identifier-rename tolerance is *not* stressed by `Z_PREFIX`.
- **Symbol-set tier: fully defeated.** The
  [symbol-set fingerprinting](../../general/experiments/static-lib-identification/README.md)
  built for TI's prebuilt `.a` files matches on defined-symbol *names*. A `Z_PREFIX` build
  exports `z_deflate`/`z_inflate`/`z_crc32`, so a reference symbol set mined from upstream
  headers misses every one. The fix is cheap and should be recorded now: **strip a leading
  `z_` before matching, or mine both variants**, since the mapping is a fixed, published
  table living in `zconf.h`.

The genuine source-level rename case is the Linux kernel's `zlib_` prefix (§3.2), which is
a hand-applied rewrite with no macro table behind it — and *that* is the one that stresses
identifier-rename tolerance, at the source tier, for real.

## 6. Subset vendoring is the normal case, not the exception

A decompression-only integration — by far the most common in bootloaders and OTA paths —
needs only `inflate.c inftrees.c inffast.c adler32.c crc32.c zutil.c` plus their headers
and `zlib.h`/`zconf.h`. Deflate (`deflate.c`, `trees.c`), the gz-file layer
(`gz*.c`, ~4 files), `compress.c`/`uncompr.c`, and `infback.c` are all droppable. Both the
Linux kernel (§3.2) and U-Boot's default config (§3.1) do exactly this.

This directly threatens the **match-ratio floor** currently being designed as the
[resolver evidence rule](../../general/experiments/nested-component-attribution/README.md):
a legitimate zlib integration may present only 6 of ~15 core files, so a naive
matched/expected ratio would score it ~0.4 and risk rejecting a true positive — while the
lwIP false positive that motivated the rule scored 1/309. The two cases are far apart
numerically, but zlib is the component that will set the floor's lower bound, and the rule
needs a notion of **which files are individually droppable** rather than a flat ratio. Worth
feeding back when that work resumes.

## 7. Detection implications

1. **No usable version macro in the carriers that matter.** `ZLIB_VERSION` exists upstream
   and in Chromium, but U-Boot's merged header dropped it entirely and the Linux kernel
   replaced it with two prose comments naming *two different* base versions. Every prior
   component in this repo had a reliable version-macro anchor; zlib is the first where the
   anchor must be assumed absent. Version evidence has to come from file content.
2. **Metadata can actively lie.** zlib-ng compat mode declares `ZLIB_VERSION "1.3.1.zlib-ng"`.
   Any promotion of the metadata tier above confirm-only produces a confident wrong answer
   here.
3. **Two real mixed-version trees exist in the wild** (Linux: inflate 1.2.3 + deflate 1.1.3;
   U-Boot: zlib 1.2.3 via pppd). This repo has been synthesizing mixed-version corpus
   entries; zlib supplies real ones, and they should be used as such.
4. **Tag scope for a reference DB.** ~78 tags, of which many are `-pre`/`x.y.z.n`
   development snapshots. Proposed scope for phase 2: the **1.2.x and 1.3.x release line**
   (`v1.2.0` … `v1.3.2`), including the four-component tags, since the Linux/U-Boot copies
   sit at 1.1.3/1.2.3 and Chromium at 1.3.2 — plus `v1.1.3` and `v1.1.4` specifically to
   cover the kernel's deflate side. Tags are confirmed equal to release artifacts (§1), so
   tag mining is safe here.
5. **Candidate tracked files.** Evidence-based, per the skill's rule:
   - `inflate.c` — present in *every* carrier examined, including subset copies. The
     primary anchor.
   - `inftrees.c` — present everywhere and barely touched by Chromium (4 lines) and
     U-Boot's minimum (33), i.e. a good "survives modification" file — zlib's analogue of
     lwIP's `pbuf.c`.
   - `inffast.c`, `adler32.c`, `zutil.c` — present in every subset copy.
   - `deflate.c`, `trees.c` — present only in full copies; useful for distinguishing
     subset from full, and for the kernel's 1.1.3-era deflate side.
   - `zlib.h` — the version carrier when it survives; explicitly *not* relied on.
   Per-file discrimination across releases should be **measured** before fixing this list,
   the way lwIP's was.
6. **Locate by path suffix, not basename.** Already a
   [general rule](../../general/README.md#locate-tracked-files-by-path-suffix-not-by-basename);
   zlib reinforces it — U-Boot has *two* files named `zlib.h` (a 17-line glue shim in
   `lib/zlib/` and the real 757-line header in `include/u-boot/`), and matching on basename
   would pick the shim and score ~0.
7. **`contrib/minizip` needs its own detection decision**, because CVE-2023-45853 binds a
   MiniZip flaw to the zlib CPE (§4a). Detecting "zlib < 1.3.1" without knowing whether
   minizip was vendored produces a false AFFECTED on the common core-only integration.

## 8. Advisory-source mapping (phase 3)

Run 2026-08-18. Full write-up, including the coverage table and the four interface
findings, in
[general/experiments/advisory-fitness](../../general/experiments/advisory-fitness/README.md#zlib-2026-08-18--the-third-loop-and-the-first-sub-component-refinement).
Scripts: `end_to_end_zlib.py` there, plus a `pkg:github/madler/zlib` entry in
`nvd_vuln_lookup.py`.

**Fit source: NVD/CPE**, `cpe:2.3:a:zlib:zlib` — real version discrimination, verified
with an impossible-version control:

| version | 1.1.4 | 1.2.3 | 1.2.11 | 1.2.13 | 1.3.2 | **99.0.0** |
|---|---|---|---|---|---|---|
| CVEs | 5 | 7 | 4 | 3 | 0 | **0** |

GHSA's per-repository feed for `madler/zlib` is **empty** (upstream does not self-publish),
and OSV is unfit. Both are recorded as coverage with reasons, not as "no known vulns".

**The loop is closed**: all ten corpus trees produce the expected verdict, including both
negatives. The four findings that generalise:

1. **§2's nested-component point has direct advisory consequences, twice over.**
   `CVE-2023-45853` (MiniZip) *and* `CVE-2026-22184` (`contrib/untgz`) are both bound
   machine-readably to the core `zlib:zlib` CPE while each record's own prose says the
   core is unaffected. Two independent instances make this a pattern, not an outlier —
   the same shape as FreeRTOS's prose-only MPU condition, but with **which files were
   vendored** as the applicability axis, so the evidence is cheap file presence rather
   than a fingerprint DB. `end_to_end_zlib.py` implements the refinement under the same
   three safety rules; on two trees at the *same* version it cuts the core-only tree's
   finding list from 3 CVEs to 1, each exclusion carrying its advisory quote.
2. **"Absent" needs its own evidence.** Most of this component's corpus trees are
   *extracts*, so "no `unzip.c` found" says nothing — Chromium ships minizip per its own
   `README.chromium`, yet the extract has none. Sub-component absence is only claimed for
   trees that look like complete distributions; everything else reports UNKNOWN and keeps
   the conditioned CVEs suspended.
3. **Two silent ways to get the CPE coordinate wrong**, both found here: the deprecated
   `cpe:2.3:a:gnu:zlib` returns **0 for every version** (so a mapping layer that takes the
   first `keywordSearch` hit gives every zlib a clean bill of health); and a CPE listed in
   a CVE's configuration with `vulnerable: false` is a *precondition*, not the flaw —
   `CVE-2025-0725` is a **libcurl** overflow that lists zlib ≤1.2.0.3 as its environment,
   and the NVD query API returns it for a zlib query anyway. The shared
   `nvd_vuln_lookup.py` was capturing that flag without consulting it; fixed, with lwIP's
   and FreeRTOS's runs re-verified for regression.
4. **Phase 2's Chromium result becomes an advisory problem.** That tree resolves only to
   the *nearest* release (1.3.2) because its actual content is an untagged post-release
   commit. Here it happens to return NOT_AFFECTED correctly — 1.3.2 has 0 CVEs — but had a
   CVE been fixed between the nearest tag and the real commit, nearest-release resolution
   would have produced a confident false AFFECTED. It is right by luck, which is the
   concrete cost of mining tags rather than artifacts.

Consistent with the repo's [scope boundary](../../CLAUDE.md), this stops at "which CVEs map
to this identity + version + composition". Whether a present `unzip.c` is ever compiled or
reachable is triage, and belongs to the SBOM consumer's VEX process.

## Open questions / next steps

- **Phase 2 (version-fingerprint experiment)** — **DONE 2026-08-18**:
  [experiments/version-fingerprint](experiments/version-fingerprint/README.md). 55 release
  tags × 8 tracked files → a 1.4 MiB DB, validated against 8 corpus trees with every
  ground truth correct. Both questions answered *yes*: winnowing pins the restructured
  kernel subset where line-diff distance could not (`inftrees.c` → v1.2.3.x @0.81, and the
  deflate side → 1.1.x — independently reproducing the two-era split the kernel states in
  prose), and a decompression-only subset resolves CONFIRMED with no penalty for the files
  it is *supposed* to lack. Two results beyond the plan: the experiment found that
  **U-Boot's deflate side is 1.2.5**, an era its own provenance comment doesn't mention;
  and the template's per-file reject rule had to be rebuilt around positive evidence after
  the corpus showed genuine-fork and reimplementation per-file scores **overlap**.
- **Phase 3 (advisory-source mapping)** — **DONE 2026-08-18**, see §8 above. NVD/CPE is
  the fit source and the loop is closed over all ten corpus trees. The CVE-2023-45853
  minizip case was handled as predicted *and* turned out to have a twin
  (`CVE-2026-22184`, `contrib/untgz`), which is what promoted the sub-component
  refinement from a one-off to a general mechanism.
- **`Z_PREFIX` in the symbol tier** — record and implement the `z_`-prefix normalization in
  the static-lib symbol matcher (§5). Cheap, and the published macro table makes it exact.
- **Is `puff.c` worth a detection target of its own?** It is a standalone single-file
  inflate, plausible in bootloaders, and would be missed entirely by a zlib-core signature.
  Unresolved; parked as a policy question, not a research gap.
- **`miniz` look-alike** — a separate single-file project offering a zlib-compatible API
  with different code. Not examined; the zlib-ng finding (§3.4) suggests API-compatible
  look-alikes are a recurring false-positive class worth one consolidated look rather than
  per-component treatment.

## Sources

Upstream:
- `https://github.com/madler/zlib` — cloned; tags `v1.1.3`…`v1.3.2` inspected, HEAD at
  `e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca` (2026-04-05).
- `https://zlib.net/fossils/zlib-1.3.1.tar.gz` — release tarball, diffed against tag `v1.3.1`.
- `ChangeLog`, `LICENSE`, `zconf.h`, `zlib.h`, `contrib/minizip/unzip.c` at `v1.3.2`.

Forks/carriers (fetched at `master`/`main`, 2026-08-18):
- `https://github.com/u-boot/u-boot` — `lib/zlib/` (incl. `zlib.c`, `zlib.h`) and
  `include/u-boot/zlib.h`.
- `https://github.com/torvalds/linux` — `lib/zlib_inflate/`, `lib/zlib_deflate/`,
  `include/linux/zlib.h`.
- `https://github.com/chromium/chromium` — `third_party/zlib/` incl. `README.chromium`
  (declares upstream revision `09a1572aa624e5ddb6c075dc013880de70b1b9b9`) and `patches/`.
- `https://github.com/zlib-ng/zlib-ng` — `zlib.h.in`, `zlib-ng.h.in`, `README.md` at `develop`.
- `https://github.com/espressif/esp-idf`, `https://github.com/nxp-mcuxpresso/mcux-sdk` —
  searched, zlib absent (§3.5).
- TI SimpleLink CC13xx/CC26xx SDK 8.33.00.16, local install — searched, zlib absent.

Advisory sources:
- NVD CPE dictionary, `keywordSearch=zlib` (225 results; `zlib:zlib` live, `gnu:zlib`
  deprecated).
- NVD CVE API records for `CVE-2018-25032`, `CVE-2022-37434`, `CVE-2023-45853`,
  `CVE-2016-9841`.
- GitHub `/repos/madler/zlib/security-advisories` — empty.
