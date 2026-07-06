# Mbed TLS corpus

Real-world (and two deliberately-assembled) sets of the five files tracked by the
[version-fingerprint experiment](../experiments/version-fingerprint/) —
`include/mbedtls/version.h`, `library/bignum.c`, `library/ecp.c`, `library/aes.c`,
`library/ecdsa.c` — with known ground truth.

- **`esp-idf-fork/`** — Espressif's fork, fetched from `espressif/mbedtls`
  (`mbedtls-3.6.2-idf` branch). Ground truth: real, in-place patches to `bignum.c` and
  `ecp.c` (hardware bignum/ECC acceleration, `#if !defined(MBEDTLS_MPI_MUL_MPI_ALT)`-style
  guards) confirmed by diffing against upstream `v3.6.2`. `aes.c`, `ecdsa.c`, and
  `version.h` turned out untouched — a real case of a fork modifying only some files, not
  all (see [components/mbedtls/README.md §3](../README.md#3-what-layers-typically-stack-on-top)).
- **`stm32-mw-mbedtls/`** — STMicroelectronics's middleware, fetched from
  `STMicroelectronics/stm32-mw-mbedtls` (`v3.6.6_20260511` tag). Ground truth: `ecdsa.c`
  carries a real functional patch (ST's "double signature check" feature) and `bignum.c`
  is also modified (surfaced by this experiment, not previously diffed directly - see the
  experiment's results table); `aes.c` and `version.h` differ from upstream by only the
  `SPDX-License-Identifier` line in their header comment (ST re-licenses to Apache-2.0-only
  - [components/mbedtls/README.md §5](../README.md#5-licensing-can-diverge-from-upstream-in-a-vendored-copy-without-any-content-change)),
  which normalizes away to an exact match; `ecp.c` is unmodified.
- **`nxp-mcuxpresso-fork/`** — NXP's fork, fetched from `nxp-mcuxpresso/mbedtls`
  (`release/25.12.00` branch, tracking upstream 2.28.10). Ground truth: all four library
  files (`bignum.c`, `ecp.c`, `aes.c`, `ecdsa.c`) are genuinely modified for ELS/PKC
  hardware acceleration, confirmed by diffing against upstream `mbedtls-2.28.10`; only
  `version.h` is untouched. The most heavily-modified real corpus entry in either this or
  the FreeRTOS experiment (4 of 5 tracked files changed).
- **`mixed-version-synthetic/`** — **synthetic**, built by combining real per-tag files
  that were never released together: `bignum.c` from v3.5.0, `ecp.c` from v3.6.0,
  `aes.c`/`ecdsa.c`/`version.h` from v3.6.0. Constructed to validate the cross-file
  version-consistency check, mirroring the FreeRTOS corpus's equivalent entry.
- **`unrelated-negative-control/`** — **synthetic**, a well-known unrelated C file
  (`DaveGamble/cJSON`'s `cJSON.c`) saved under all five tracked filenames. Used to confirm
  the matcher correctly refuses to confirm Mbed TLS from unrelated code - this is the
  entry that surfaced a real verdict-logic bug (see the experiment README's "A real bug
  this experiment's negative control caught").

The first three were fetched directly from their respective vendor GitHub repos (not
hand-modified) so they reflect real vendoring behavior, not synthetic test data; only
`mixed-version-synthetic/` and `unrelated-negative-control/` are assembled rather than
observed as-is.
