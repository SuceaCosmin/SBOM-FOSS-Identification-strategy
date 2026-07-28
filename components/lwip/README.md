# lwIP

Research notes on identifying **lwIP** (lightweight IP — the embedded TCP/IP stack) when
it has been vendored into a firmware source tree. Picked as the fourth component per
[general/component-roadmap.md](../../general/component-roadmap.md) Tier 1 #1: it is *the*
embedded TCP/IP stack (automotive Ethernet / DoIP endpoints, and every silicon-vendor SDK
ships a copy), and its stated detection interest was the **port-layer-vs-core** question —
a cleaner instance of the "vendor integration layer" problem first seen in Mbed TLS.

Everything below was verified against real source (clones and blob-SHA comparisons of four
real vendor forks against the matching upstream release tag), not against vendor
documentation — see the "Sources" section for the exact refs diffed.

Phase 2 (version-fingerprint experiment): [experiments/version-fingerprint](experiments/version-fingerprint/README.md).
Phase 3 (advisory-source mapping): see section 8 below.

## 1. Governance and licensing history

- Originally written by **Adam Dunkels** at the Computer and Networks Architectures lab,
  **Swedish Institute of Computer Science (SICS)**, ~2001. Now maintained by a
  distributed group of developers; no corporate owner, no foundation, no rebrand.
  Contrast with Mbed TLS (PolarSSL → ARM → TrustedFirmware) — **lwIP has had no
  governance change to leave a copyright-header fingerprint**, so the "copyright wording
  shift as a version-era heuristic" trick documented in
  [general/README.md](../../general/README.md) does not apply here. Nearly every file
  still carries the same `Copyright (c) 2001-2004 Swedish Institute of Computer Science`
  block it was born with.
- **License: BSD-3-Clause throughout** (`COPYING`), single-licensed. There is no
  dual-license, so there is no "vendor drops one license" divergence of the kind found in
  Mbed TLS — but see section 5, which found a *different* and messier divergence.
- **Canonical VCS is Savannah, not GitHub.** Development lives at
  `git.savannah.gnu.org/cgit/lwip.git` (project page `savannah.nongnu.org/projects/lwip`).
  The GitHub repo `lwip-tcpip/lwip` self-describes as *"lwIP mirror from
  http://git.savannah.gnu.org/cgit/lwip.git"* — it is an official mirror with the full tag
  set, but it is a mirror. This matters for identifiers (section 4).
- **Releases are distributed as zips on Savannah**, not GitHub release assets: the
  download area `download.savannah.nongnu.org/releases/lwip/` holds `lwip-<x.y.z>.zip` for
  every release 1.4.0 → 2.2.1 (plus `.sig` files, an `older_versions/` and a `drivers/`
  area). The GitHub releases API returns nothing. A vendored copy therefore may have come
  from a zip that has no git provenance at all — the tarball/zip shape, not `git clone`,
  is the likely origin of a copy-pasted tree.
- Release cadence is slow and gets slower: 1.4.1 (2012-09-26), 2.0.0 (2016-11-10),
  2.0.3 (2017-09-15), 2.1.0 (2018-09-26), 2.1.3 (2021-11-10), 2.2.0 (2023-09-25),
  2.2.1 (2025-02-05). Long-lived releases mean a detected version is often *years* old
  and still in the field — good for fingerprinting (files are stable across long spans,
  which is also what makes adjacent releases hard to separate).

## 2. Component granularity

Simpler than FreeRTOS or CMSIS, with one wrinkle and one surprise.

- **`src/` is the stack itself** — core (`src/core`, incl. `ipv4`/`ipv6`), the API layers
  (`src/api`: netconn + BSD sockets), `src/netif` (incl. `netif/ppp`), and `src/apps`
  (httpd, mqtt, sntp, snmp, mdns, tftp, lwiperf, smtp, netbiosns, altcp_tls). The apps are
  *in-tree and version-locked to the stack* — unlike FreeRTOS-Plus, they are **not**
  separately versioned, so they do not create extra SBOM entries.
- **`contrib/` was a separate repo until 2018.** Ports (`contrib/ports/{unix,win32,freertos}`),
  example apps and addons lived in `lwip-contrib` on Savannah and shipped as their *own*
  release zip (`contrib-1.4.0.zip` … `contrib-2.1.0.zip`, versioned in lockstep with the
  stack). It was imported into the main repo on **2018-10-02** (commit `ac46e42a`, "Import
  lwIP contrib rep"), just after 2.1.0. Consequence: for a pre-2.1.1 vendored tree,
  `src/` and `contrib/` are *two* upstream artifacts that were separately downloaded and may
  be at different versions; after 2.1.1 they are one. The old `lwip-tcpip/lwip-contrib`
  GitHub repo now returns zero refs.
- **Surprise: lwIP is itself a vendoring carrier.** Two third-party bodies of code are
  copy-pasted into the stack, both documented in-tree (which per the skill's rule counts as
  stronger ground truth than any diff):
  - `src/netif/ppp/` — *"based from pppd 2.4.5 (http://ppp.samba.org) with huge changes to
    match code size and memory requirements for embedded devices"* (`PPPD_FOLLOWUP`), with
    a running log of which upstream pppd and Debian patches were merged.
  - `src/netif/ppp/polarssl/` — `md5.c`, `sha1.c`, `des.c`, `arc4.c`, `md4.c` *"fetched
    from the latest BSD release of the PolarSSL project (**PolarSSL 0.10.1-bsd**) … cleaned
    to contain only the necessary struct fields and functions"* (`polarssl/README`). Headers
    still carry `Copyright (C) 2009 Paul Bakker <polarssl_maintainer@polarssl.org>` and
    `Based on XySSL: Copyright (C) 2006-2008 Christophe Devine`.

  So a firmware that vendors lwIP has, transitively, vendored a **reduced fork of
  PolarSSL 0.10.1** — the direct ancestor of the Mbed TLS this repo already researched.
  This is the nested-vendoring case the roadmap listed against MCUboot, showing up
  unannounced here. Detection consequence in section 7.
- Separately, lwIP *optionally links against* Mbed TLS for TLS (`src/apps/altcp_tls/
  altcp_tls_mbedtls.c`) — a build-time dependency, not a copy. So lwIP touches Mbed TLS
  twice, in two different relationships, and only one of them is a vendored copy.

## 3. What layers stack on top — four real forks, four different shapes

Each fork below was fetched as a git remote of the upstream clone and diffed against the
upstream release tag it is based on. This is the section the skill's "verify against real
source" rule is aimed at, and it paid off: the naive expectation ("vendors patch the core")
is true for two of the four and flatly false for the other two.

| Fork | Ref examined | Core (`src/`) vs upstream | Port layer | Version as declared |
|---|---|---|---|---|
| **STMicroelectronics** `stm32-mw-lwip` | `v2.1.3_20241213` | **byte-identical** (empty diff) | added under `system/` | tag `<upstream>_<date>` |
| **STMicroelectronics** | `v2.2.0_20250106` | 3 files, **4 doxygen `@ingroup` comment lines** + one 10-line removal in `snmp_traps.c` | added under `system/` | tag `<upstream>_<date>` |
| **Espressif** `esp-lwip` | branch `2.2.0-esp` | **54 files patched**, +3446/−257, incl. whole new features (`ip4_napt.c`, 1089 lines) | in `esp-idf`, not this repo | `init.h` says 2.2.0 **DEVELOPMENT** |
| **NXP** `nxp-mcuxpresso/lwip` | tag `MCUX_2.16.100` | **102 files patched**, +12462/−1279 | in the SDK, not this repo | `init.h` says 2.2.1 DEVELOPMENT; tag says `MCUX_2.16.100` |
| **AMD/Xilinx** `embeddedsw` | `xilinx_v2024.1`, `ThirdParty/sw_services/lwip220` | **7 of 20 core `.c` files differ** (blob-SHA comparison) | `src/contrib` + adapter makefiles | **version encoded in the path**: `lwip220/src/lwip-2.2.0/` |

Details worth keeping:

- **ST is the verbatim case.** For 2.1.3 the `src/` diff against `STABLE-2_1_3_RELEASE` is
  *empty* — a real, shipping, silicon-vendor middleware whose lwIP core is byte-identical
  to upstream. For 2.2.0 the only core changes are doxygen grouping fixes
  (`@ingroup tcp` → `@ingroup tcp_raw`, `@ingroup ip5addr` → `@ingroup ipaddr` — ST fixing
  upstream typos). This repeats the CMSIS result: **real vendor forks are frequently
  verbatim**, and a detector tuned only for heavy modification will over-engineer.
- **ST adds a port layer in a directory that does not exist upstream**: `system/arch/`
  (`cc.h`, `cpu.h`, `sys_arch.h`, `bpstruct.h`, `epstruct.h`, `perf.h`, `lib.h`, `init.h`)
  and `system/OS/sys_arch.c` (513 lines, ST's FreeRTOS/CMSIS-OS glue). Upstream's own ports
  live at `contrib/ports/`. Path-based identification of the port layer is therefore
  unreliable in exactly the way the FreeRTOS port-layer experiment found for ESP-IDF's
  `portable/xtensa/`.
- **ST also checks in ~1300 generated doxygen HTML/JS files** under `doc/doxygen/output/`
  (~177k lines of the 2.2.0 diff). Pure scanner noise; worth an ignore rule.
- **Espressif flips the version macro.** `esp-lwip` changes exactly one line of
  `src/include/lwip/init.h`: `LWIP_VERSION_RC` from `LWIP_RC_RELEASE` to
  `LWIP_RC_DEVELOPMENT`, so `LWIP_VERSION_STRING` evaluates to `"2.2.0d"` rather than
  `"2.2.0"`. The metadata still names the right base release, but the exact hash of the
  version-carrier file no longer matches any upstream release — the same shape as the Mbed
  TLS "ST edits one header line and the whole tree falls to the snippet tier" finding.
- **NXP superimposes SDK versioning on the upstream tag set.** Its fork keeps every
  upstream `STABLE-*` tag *and* adds `MCUX_2.12.0` … `MCUX_2.16.100` plus
  `Real-Time-Edge-v3.x-YYYYMM` tags. Resolving "which tag is this tree at" inside the NXP
  fork yields an **SDK** version, not an lwIP version — the same trap as FreeRTOS's
  AWS-distribution versioning, and the reason section 8 checks version *schemes* rather
  than assuming.
- **Xilinx declares the version in the directory name** (`lwip220`, and the nested
  `src/lwip-2.2.0/` holding a full upstream tree) — a free, high-confidence corroboration
  signal when present, of the kind classed as metadata/confirm-only in
  [general/README.md](../../general/README.md). It is corroboration, not proof: 7 of the
  20 core `.c` files under that `lwip-2.2.0/` directory are *not* upstream 2.2.0
  (`def.c`, `init.c`, `mem.c`, `netif.c`, `tcp_out.c`, `timeouts.c`, `udp.c`).

## 4. Naming a detected lwIP component in an SBOM

- **CPE**: `cpe:2.3:a:lwip_project:lwip:<version>:*:*:*:*:*:*:*` — part `a`, vendor
  `lwip_project` (the NVD placeholder-vendor convention for projects with no corporate
  owner). 32 dictionary entries exist, `0.2` through **`2.1.2`**, plus a version-less
  `-` entry. **There is no CPE for 2.1.3, 2.2.0 or 2.2.1** — the three most recent
  releases, covering everything shipped since 2021. A CPE-based lookup for a
  correctly-detected modern lwIP has no dictionary entry to bind to; see section 8.
- **PURL**: `pkg:github/lwip-tcpip/lwip@STABLE-2_2_1_RELEASE` is what the detection
  evidence supports, but it names **the mirror**, not the canonical VCS. The alternative
  (`pkg:generic/lwip@2.2.1` with a `download_url` qualifier pointing at the Savannah zip)
  names the actual release artifact most vendored copies came from. This is a milder form
  of the FatFs no-git-upstream problem: a git URL exists and is official, it just is not
  where the project lives. Recommendation: emit `pkg:github/lwip-tcpip/lwip` as the
  canonical identity (it is stable, resolvable, and what every public dataset keys on),
  and carry the Savannah release zip as provenance rather than as the identity.
- **GHSA/OSV**: see section 8 — neither carries usable lwIP entries; NVD is where lwIP
  advisories live.
- The version string to emit is the **upstream release** (`2.2.0`), never the fork's own
  (`MCUX_2.16.100`, `v2.2.0_20250106`, `lwip220`). All four vendor schemes seen here are
  distribution versions layered over an upstream release.

## 5. License divergence: two contradictory license statements in the same shipped tree

Checked because the Mbed TLS pass found ST re-licensing its copy. lwIP is single-licensed
upstream, so the Mbed TLS *shape* of divergence (dropping one of two licenses) cannot
occur — but ST's tree contains a different and arguably worse inconsistency:

- Root **`LICENSE.md`** (added 2023-08-18 per `st_readme.txt`) is plain **BSD-3-Clause**
  ("Portions COPYRIGHT 2016 STMicroelectronics" + the SICS copyright, with the standard
  three clauses).
- **`st_readme.txt`**'s own header block carries ST's older **five-clause license**, whose
  clause 4 is a field-of-use restriction: *"This software, including modifications and/or
  derivative works of this software, must execute solely and exclusively on microcontroller
  or microprocessor devices manufactured by or for STMicroelectronics."* That is not an
  open-source license (it fails the OSD's no-discrimination-against-fields-of-endeavour
  criterion).
- Meanwhile **ST-authored port files carry no ST copyright at all**: `system/OS/sys_arch.c`
  and `system/arch/cc.h` open with the unmodified
  `Copyright (c) 2001-2003 Swedish Institute of Computer Science` BSD-3-Clause block,
  despite being wholly ST's own integration code.

So one tree yields three different answers depending on which file the scanner reads:
BSD-3-Clause (root license file), a restrictive ST license (the provenance readme), or
"SICS BSD-3-Clause" attributed to ST-authored files. The practically important direction is
the last one — it is the CMSIS `Device/<vendor>` finding again (**path and file header say
upstream; content is the vendor's**), now with a licensing consequence rather than just an
attribution one.

## 6. Amalgamation: not a release shape for lwIP

Explicitly checked, since the repo scope names amalgamated/single-header libraries as a
priority integration pattern. There is **no** amalgamation: no amalgamation script in the
tree, no single-file release artifact in the Savannah download area (only `lwip-x.y.z.zip`
full-source archives), and no mention of "amalgam*" anywhere in the repo. lwIP is
distributed only as a multi-file source tree, so the amalgamation detection case has to be
tested against a different component (SQLite or miniz per the roadmap).

## 7. Detection implications

1. **The version-macro carrier is `src/include/lwip/init.h`** (`LWIP_VERSION_MAJOR` /
   `_MINOR` / `_REVISION` / `_RC`) — a clean, machine-readable, in-source declared version,
   which FreeRTOS and Mbed TLS also have and CMSIS only half has. But two of the four real
   forks edit it: Espressif flips `_RC` to `LWIP_RC_DEVELOPMENT`, NXP ships `2.2.1` +
   DEVELOPMENT (i.e. a post-release master snapshot). Treat the macro as a **strong
   corroborating claim, not ground truth**, exactly as `general/README.md` says of
   metadata signals — and note the DEVELOPMENT flag is itself information: it means "a git
   snapshot between releases", which a version *window* expresses correctly and a point
   version does not.
2. **Port layer must be identified by content, not path.** Upstream ports live in
   `contrib/ports/`; ST's live in `system/`; Espressif's and NXP's live in their SDK repos
   entirely. Any vendored tree's `arch/cc.h`, `sys_arch.c` and `lwipopts.h` are
   *project-authored by definition* — lwIP's porting contract is precisely that these files
   are supplied by the integrator. They should be recognized as **"lwIP port layer,
   vendor-authored"** and excluded from core version evidence, not scored against upstream
   files they were never copies of.
3. **`lwipopts.h` is configuration evidence, not identity.** It is the lwIP analogue of
   `FreeRTOSConfig.h`: never upstream, always project-authored, and it decides which
   features are compiled in. The FreeRTOS port-layer experiment showed that a config macro
   can flip a CVE verdict; lwIP has far more such macros, and several advisories are
   scoped to optional features. Worth reading as build evidence, never as a version signal.
4. **Nested components must be attributed separately.** `src/netif/ppp/polarssl/*.c` will
   look like PolarSSL/Mbed TLS to any content matcher, because it *is* PolarSSL 0.10.1 code
   — reduced, but not rewritten. Two failure modes to avoid: reporting "Mbed TLS detected"
   for a tree that only vendors lwIP (over-reporting a component that is not independently
   present), and suppressing it entirely (under-reporting real 2009-era crypto code with
   its own vulnerability history). The correct output is a **contained-component
   relationship**: lwIP 2.x, containing a reduced copy of PolarSSL 0.10.1-bsd, containing a
   reduced copy of pppd 2.4.5. This is the concrete case for the multi-component
   attribution rules in
   [general/README.md](../../general/README.md#attribution-vendored-integrations-are-often-multiple-stacked-components).
5. **Expect verbatim more often than modified.** Two of four forks (ST, and Xilinx for 13
   of 20 core files) are effectively upstream. The exact-hash tier will carry more of the
   load here than the FreeRTOS/Mbed TLS experience suggested.
6. **Slow release cadence + large stable files = narrow discriminating evidence.** Files
   like `src/core/init.c` change little between adjacent point releases; the version
   signal concentrates in whichever files a given release actually touched. This is the
   cross-file-consistency argument from `general/README.md` in its strongest form, and it
   is what phase 2 measures.

## 8. Advisory-source mapping (phase 3)

Run 2026-07-29. Full write-up, probes and the end-to-end run live in
[general/experiments/advisory-fitness](../../general/experiments/advisory-fitness/README.md#lwip-2026-07-29--the-second-loop-closed-through-nvdcpe-this-time);
summarized here.

| Source | lwIP's coordinate | Verdict |
|---|---|---|
| **NVD/CPE** | `cpe:2.3:a:lwip_project:lwip` | **fit** — real version-range matching; impossible-version control (@99.0.0) returns 0 |
| **GHSA per-repo** | `lwip-tcpip/lwip` | **0 advisories** — lwIP does not self-publish (the repo is itself a mirror) |
| **OSV** | `pkg:github/lwip-tcpip/lwip` | **0**; bare name `lwip` returns only Debian/Ubuntu/openEuler distro records |

The loop was closed end-to-end over all 8 corpus trees (`end_to_end_lwip.py`), each
producing the expected verdict — `upstream-1.4.1` → **AFFECTED** by CVE-2014-4883 (range
`<=1.4.1`), the mixed tree → **AFFECTED** by CVE-2020-22284 (2.1.2 really is present),
every modern tree → NOT_AFFECTED, negative control → NOT_QUERYABLE. This is the repo's
first loop closed through **NVD/CPE** (FreeRTOS's went through the GHSA repo feed), and it
needed a new reusable module, `nvd_vuln_lookup.py`.

Four findings, all about the identity→advisory interface rather than lwIP itself:

1. **Advisories for a vendored component are frequently filed against the carrier.** Of 6
   NVD CVEs mentioning lwIP, only 3 are bound to `lwip_project:lwip`; the others are filed
   under `microchip:advanced_software_framework` (lwIP's example DHCP server bundled in
   ASF) and `espressif:esp-idf` (an OOB read in ESP-IDF's *own* `dhcpserver.c` — a file
   that lives in esp-idf, not even in Espressif's `esp-lwip` fork). A correct upstream
   identity therefore does **not** reach them: identity→CPE must be one-to-*many*, adding
   the carrier's CPE once detection establishes which vendor distribution a tree is. This
   is the mirror image of the FreeRTOS problem (there NVD used the distribution's
   *versions*; here it uses the distribution's *product name*). Cheap carrier
   discriminators exist — `src/core/ipv4/ip4_napt.c` appears in Espressif's fork and in no
   upstream release.
2. **A CPE bound to the literal version `-` is unmatchable and must not read as
   "not affected".** CVE-2020-22283 is bound that way, so naive range evaluation silently
   reports NOT_AFFECTED for every version. Reported as UNDETERMINED, with the reason.
3. **The CPE dictionary lags the release stream**: entries stop at 2.1.2 — nothing for
   2.1.3/2.2.0/2.2.1. Range-based queries still work, but CVE-2026-8836 (a genuine
   upstream SNMPv3 flaw, "lwIP up to 2.2.1") has **no CPE at all**. Its advisory names the
   fix commit, which `git tag --contains` places in *no* release — a usable answer from a
   commit coordinate where the CPE coordinate had none.
4. **The nested pppd's CVEs are reachable only through a nested identity.** `DEBIAN-CVE-2020-8597`
   (pppd `eap.c` overflow, ppp 2.4.2–2.4.8) brackets the pppd 2.4.5 lwIP vendored, and
   lwIP 2.2.1 still ships that `eap.c`. Whether the reduced copy is exploitable is triage
   and out of scope — but an SBOM naming only lwIP cannot surface the CVE from any source
   tested.

**Does lwIP need a port-layer detector like FreeRTOS's?** No — and the phase-3 evidence is
what settles it. FreeRTOS needed one because a CVE was scoped to a *port*
(ARMv7-M/ARMv8-M MPU). None of lwIP's advisories are scoped to a port or an `lwipopts.h`
macro; the applicability axis that actually appears is **which distribution the code came
from**. So the granularity worth sharpening for lwIP is carrier/fork identification (per
finding 1), not the port layer. The port layer still matters for *detection hygiene* —
which phase 2 handles by suffix-matching so vendor port files never contaminate core
version evidence.

## Open questions / next steps

- Phase 2 version-fingerprint experiment: [experiments/version-fingerprint](experiments/version-fingerprint/README.md).
- Whether the vendored PolarSSL 0.10.1 subtree should be emitted as its own SBOM entry or
  only as a contained-component relationship of lwIP is a **policy** question, not a
  research gap — it needs a decision, like the CMSIS Device Family Pack question.
- The pre-2.1.1 split `lwip` + `lwip-contrib` release pairing is documented but untested
  against a real old vendored tree (1.4.1-era trees are still in the field).
- Xilinx's `lwip220` was verified by blob-SHA comparison over `src/core` only; the rest of
  its tree (and its `src/contrib` adapter layer) was not diffed.

## Sources

- Upstream repo (mirror), tags and history: `https://github.com/lwip-tcpip/lwip` —
  described as a mirror of `http://git.savannah.gnu.org/cgit/lwip.git`.
- Release archive listing: `http://download.savannah.nongnu.org/releases/lwip/`.
- In-tree provenance files, at `STABLE-2_2_1_RELEASE`: `COPYING`, `README`, `FILES`,
  `src/netif/ppp/PPPD_FOLLOWUP`, `src/netif/ppp/polarssl/README`,
  `src/include/lwip/init.h`.
- Espressif fork: `https://github.com/espressif/esp-lwip`, branch `2.2.0-esp`, diffed
  against upstream `STABLE-2_2_0_RELEASE`.
- ST fork: `https://github.com/STMicroelectronics/stm32-mw-lwip`, tags `v2.1.3_20241213`
  and `v2.2.0_20250106`, diffed against `STABLE-2_1_3_RELEASE` / `STABLE-2_2_0_RELEASE`;
  `st_readme.txt`, `LICENSE.md`, `system/arch/cc.h`, `system/OS/sys_arch.c`.
- NXP fork: `https://github.com/nxp-mcuxpresso/lwip`, tag `MCUX_2.16.100`, diffed against
  `STABLE-2_2_0_RELEASE`.
- AMD/Xilinx: `https://github.com/Xilinx/embeddedsw`, ref `xilinx_v2024.1`,
  `ThirdParty/sw_services/lwip220/src/lwip-2.2.0/src/core` — compared by git blob SHA
  against upstream `STABLE-2_2_0_RELEASE:src/core`.
- NVD CPE dictionary: `https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=lwip`
  (32 entries, `cpe:2.3:a:lwip_project:lwip`, newest `2.1.2`).
