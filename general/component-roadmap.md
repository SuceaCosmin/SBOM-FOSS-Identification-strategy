# Component research roadmap

A prioritized list of FOSS C components worth researching in this repo, ordered by
**likelihood of appearing (vendored/copy-pasted) in automotive products** — AUTOSAR and
non-AUTOSAR alike — automotive-first prioritization decided 2026-07-08. Within each
tier, components are
roughly ordered by expected prevalence × detection-research value.

Already researched (see `components/`): **FreeRTOS**, **mbedTLS**, **CMSIS**.

Scope reminders that shaped this list (from [CLAUDE.md](../CLAUDE.md)):

- **C only** — this excludes several automotive-famous OSS projects outright (see the
  "explicitly out of scope" section at the bottom).
- Integration pattern of interest is **copy-paste vendoring**, possibly locally modified,
  possibly amalgamated. Components that are almost always consumed via a Linux package
  manager / Yocto recipe (rather than dropped into a source tree) are deprioritized even
  if they are common in vehicles.
- Each entry notes **why automotive** and **what new detection question it would stress**
  — a component that only re-validates what FreeRTOS/mbedTLS/CMSIS already proved is less
  interesting than one that exercises a new dimension, even at equal prevalence.

## Tier 1 — high likelihood in automotive ECUs (classic microcontroller firmware)

These show up in AUTOSAR-adjacent projects (bootloaders, complex device drivers, CDD
layers, non-AUTOSAR partitions) and in plain RTOS/bare-metal ECU firmware. Most are also
bundled — often patched — inside the vendor SDKs (STM32Cube, MCUXpresso, ESP-IDF,
S32 SDK, Aurix SDK) that automotive Tier-1s build on, i.e. the exact "vendor integration
layer" pattern already documented for mbedTLS and CMSIS.

1. **lwIP** — *the* embedded TCP/IP stack; automotive Ethernet (100BASE-T1) ECUs, DoIP
   endpoints, SOME/IP-on-lwIP setups, and every ST/NXP/Espressif SDK ships a patched
   copy with vendor netif/port layers. Detection interest: the port layer
   (`arch/`, `lwipopts.h`) is always project-authored while the core is upstream —
   a cleaner version of the mbedTLS "vendor integration layer" question; long release
   history (1.3.x → 2.2.x) with slow-moving files, good fingerprint stress test.
2. **zlib** — compression inside OTA updaters, bootloaders, logging, and *statically
   embedded inside other libraries*; one of the most-vendored C codebases in existence
   and a recurring CVE source (CVE-2018-25032, CVE-2022-37434) which makes it a perfect
   fitness test for the vuln-scanning end goal. Detection interest: frequently vendored
   as a *subset* of files, often with `Z_PREFIX`-style renaming — stresses partial-copy
   and identifier-rename tolerance.
3. **FatFs (ChaN)** — FAT driver for logging/media/USB-storage in ECUs, IVI, dashcams;
   bundled in STM32Cube and MCUXpresso middleware. Detection interest: **no official
   git repo** — upstream is zip archives on elm-chan.org, so Software Heritage/OSSKB
   coverage and purl mapping are genuinely unclear; versioning is in-file
   (`FF_DEFINED` / `_FATFS` macro per revision R0.xx); the config header `ffconf.h` is
   always locally edited. Likely the best single test of how the reuse-first dataset
   stance handles a non-GitHub-native upstream.
4. **wolfSSL / wolfCrypt** — the other big embedded TLS stack; strong automotive
   presence (marketed for V2X, DO-178/26262 contexts, wolfBoot secure bootloader),
   FIPS-certifiable, common where mbedTLS isn't. Detection interest: GPLv2/commercial
   dual license means detecting it has direct compliance consequences; validates
   whether the mbedTLS experiment approach transfers to a same-domain competitor.
5. **littlefs** — Arm's power-fail-safe flash filesystem; default FS in Zephyr/Mbed and
   increasingly in ECU data/OTA storage. Detection interest: tiny file count (~4 core
   files) — how well does per-file fingerprinting work when there are almost no files?
6. **micro-ecc (uECC)** and **TinyCrypt** — minimal ECC/crypto for secure boot and
   immobilizer-class ECUs where mbedTLS is too big. Both effectively **abandoned/frozen
   upstream** while still being vendored everywhere (micro-ecc's last release predates
   many of its deployments). Detection interest: 2–4-file libraries, often copied as a
   single `.c/.h` pair — approaches the amalgamation/single-header target; also tests
   how the pipeline reports a component whose upstream is dead (no version to map to?).
7. **MCUboot** — the de-facto open secure bootloader (Zephyr, Mbed, NXP, Infineon
   integrations); automotive-relevant wherever OTA + secure boot meets Cortex-M.
   Detection interest: typically integrated *with* a port layer and heavy `mcuboot_config`
   editing; also pulls in its own vendored copies of TinyCrypt/mbedTLS — a nested-vendoring
   attribution problem (which component "owns" a shared file?).
8. **CANopenNode** — the main open-source CANopen stack (Apache-2.0); commercial
   vehicles, off-highway, agriculture, EV charging. Detection interest: generated
   object-dictionary files (`OD.c`/`OD.h`) are project-specific while the stack core is
   upstream — another flavor of the "which files are actually the component" question.
9. **Open-SAE-J1939** and **iso14229 (UDS)** — young open-source implementations of
   automotive protocol stacks (J1939 for commercial vehicles; UDS/ISO 14229 diagnostics),
   plus **XCPlite** for XCP measurement/calibration. Individually less proven than the
   rest of this tier, but *uniquely* automotive — nothing else vendors these. Detection
   interest: small, fast-moving repos with unstable APIs — users pin random commits, so
   version mapping degrades to commit-level identification.
10. **LVGL** — the dominant open-source embedded GUI library (MIT, C); instrument
    clusters, HVAC panels, e-bike/EV displays; bundled in NXP/ST SDK demos. Detection
    interest: hundreds of files with strong internal naming conventions (`lv_*`) —
    metadata/string heuristics should work almost too well; good baseline for technique 3.
11. **FreeRTOS+TCP, coreMQTT, coreHTTP, coreJSON (FreeRTOS/AWS ecosystem)** — connected
    TCU/telematics firmware built on FreeRTOS almost always vendors these siblings.
    Detection interest: extends the existing FreeRTOS work cheaply (same org, same
    release conventions, LTS bundling — the "pack version vs component version" layering
    already seen in CMSIS).
12. **Eclipse ThreadX** (ex Azure RTOS, ex Express Logic) and **µC/OS-II/III (Micrium,
    now Apache-2.0 as Cesium/"Micrium OS")** — historically *proprietary* RTOSes with
    real automotive/safety pedigree that were later open-sourced. Detection interest:
    decades of deployed copies predate the open-source license — the license/provenance
    answer *depends on which era the copy is from*, a genuinely new attribution problem
    (contrast with ST's mbedTLS re-licensing finding, which was vendor-side).
13. **Newlib / newlib-nano** — the libc actually linked into most GCC-built ECU
    firmware; occasionally source-vendored (syscalls stubs always are). Detection
    interest: toolchain-supplied vs source-vendored boundary; probably a short
    research note rather than a full two-phase treatment.
14. **mpaland/eyalroz `printf`** — the tiny embedded printf replacement, vendored as a
    single `.c/.h` pair into countless firmware trees (and *into other projects*, e.g.
    SEGGER examples). Detection interest: canonical **single-file vendoring + fork
    lineage** case (eyalroz fork superseded the abandoned mpaland original — which purl
    is correct?).
15. **TinyUSB** — USB device/host stack bundled in nearly every MCU vendor SDK;
    automotive-relevant for diagnostics/media/CarPlay-adjacent USB endpoints.
    Detection interest: vendor SDKs pin odd snapshots; port layer vs core split again.
16. **bsdiff / heatshrink / LZ4 / miniz** (OTA-delta & compression family) — delta
    updates and compressed assets in OTA pipelines. Detection interest: bsdiff is
    famously vendored-and-locally-patched (the original is a 2003-era tarball, every
    consumer modifies it) — a *worst-case* provenance test; miniz is a deliberate
    **amalgamation** (single `miniz.c`), directly on-target for the priority-2
    integration pattern.

## Tier 2 — automotive Linux side (IVI, telematics, gateways)

Common in vehicles but usually consumed via Yocto/BitBake recipes rather than
copy-paste vendoring — research value here is mostly about *confirming* they're
out-of-pattern, plus the few genuinely-vendored exceptions.

17. **SQLite** — IVI media indexes, telematics event stores, map caches. The exception
    to the "Linux side is package-managed" rule: upstream *officially recommends*
    vendoring the **amalgamation** (`sqlite3.c`, ~250k lines, one file). This is the
    single best real-world test of the amalgamated-library detection target and should
    arguably be pulled forward into Tier 1 on detection-research grounds alone.
18. **cJSON / JSMN / TinyCBOR / nanopb** — serialization for telematics and config;
    all small, all C, all routinely copy-pasted (cJSON and JSMN are 1–2 files; nanopb
    adds generated `.pb.c/.pb.h` files mixing upstream and generated code). Group them
    into one "tiny parsers" research pass.
19. **curl (libcurl)** and **OpenSSL** — famously in a very large share of vehicles
    (curl's author has written about finding it in car infotainment head units), but on
    the Linux/POSIX side and rarely bare-metal-vendored. Worth a short landscape note
    (they'd dominate any IVI SBOM) rather than a full experiment.
20. **BusyBox, expat, dbus, glibc-family** — same category: Yocto-managed, out of the
    copy-paste pattern; note-only.

## Tier 3 — general embedded, lower automotive specificity

Common in embedded broadly; research when Tiers 1–2 are exhausted or when one suddenly
appears in a real target.

21. **Zephyr subsystems** — Zephyr is west/package-managed as a whole, but individual
    subsystems (littlefs already listed, `crc`, `ring_buffer`, shell) get cherry-picked
    into non-Zephyr trees.
22. **SEGGER RTT** — debug channel code that ships in production firmware more often
    than intended; license is SEGGER's own permissive-with-conditions text, *not* an
    OSI license — interesting for license-classification edge cases.
23. **FlashDB, lwrb, EasyLogger, letter-shell** and similar single-purpose utility libs
    — long tail; treat opportunistically.
24. **TF-M (Trusted Firmware-M)** — PSA secure-partition firmware for Cortex-M33-class
    parts; more IoT than automotive today, and typically integrated whole-tree rather
    than file-vendored.

## Explicitly out of scope (and why it's worth saying so)

- **vsomeip / CommonAPI (COVESA)** — the flagship automotive OSS (SOME/IP) is **C++**;
  excluded by the C-only scope. Worth remembering when someone asks "why isn't the most
  automotive library on the list?".
- **Lely CANopen, OpenDDS, Apache Thrift, protobuf (full)** — C++.
- **Automotive Grade Linux / AGL stack** — distro-level, package-managed.
- **Arctic Core / open-source AUTOSAR implementations** — effectively dead upstreams
  with negligible field deployment; revisit only if a real target surfaces one.
- **Unity / CMock / Ceedling / CppUTest** — heavily vendored but **dev/test-time only**;
  they don't ship in the firmware image, so they matter for a *source* SBOM but not for
  the vuln-scanning end goal. Deliberately parked.

## How to pick the next one

Prevalence alone over-selects components that would just re-validate existing findings.
Suggested pairing of "next pick" to open detection questions:

| Open detection question | Best next component |
|---|---|
| Amalgamated single-file target (priority-2 integration pattern, still untested) | **SQLite** (or miniz as the small warm-up) |
| Non-GitHub upstream / purl-mapping stress for the reuse-first dataset stance | **FatFs** |
| Port-layer vs core separation, at scale | **lwIP** |
| Partial vendoring + rename tolerance + vuln-scan fitness | **zlib** |
| Dead-upstream / commit-pinned attribution | **micro-ecc**, **iso14229** |
| License-era ambiguity (proprietary→OSS transitions) | **ThreadX**, **µC/OS** |
| Nested vendoring (component inside component) | **MCUboot** |

The two that combine highest automotive prevalence with the most *new* detection
research per unit effort are **lwIP** and **zlib**; the one that unblocks the untested
priority-2 integration pattern (amalgamation) is **SQLite**.
