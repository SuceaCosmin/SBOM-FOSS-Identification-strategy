# FreeRTOS corpus

Real-world (and one deliberately-assembled synthetic) `tasks.c`/`queue.c`/`list.c` sets
with known ground truth, used to validate the
[version-fingerprint experiment](../experiments/version-fingerprint/).

- **`esp-idf-fork/`** — Espressif's SMP-modified fork, fetched from `espressif/esp-idf`
  (`master` branch, `components/freertos/FreeRTOS-Kernel/`). Ground truth: a genuine
  kernel-level fork, based on FreeRTOS-Kernel v10.5.1 per Espressif's own docs (see
  [components/freertos/README.md §3](../README.md#3-what-layers-typically-stack-on-top-of-the-kernel)).
  `tasks.c` and `queue.c` are heavily modified (dual-core scheduler changes); `list.c`
  turned out to be **untouched** — it exact-matches several stock releases
  (V10.5.0–V10.6.2). Represents both the "locally modified vendored copy" pattern and
  the realistic case where a fork only modifies some files, not all.
- **`nxp-mcux-vendored/`** — NXP's vendored mirror, fetched from
  `nxp-mcuxpresso/FreeRTOS-Kernel` (`release/26.03.00` branch). Ground truth: content-
  identical (modulo comments/whitespace) to upstream FreeRTOS-Kernel V11.2.0 across all
  three files — an unmodified verbatim vendored copy, distributed via NXP's MCUXpresso
  SDK integration layer.
- **`mixed-version-synthetic/`** — **synthetic**, built by combining real per-tag files
  that were never actually released together: `tasks.c` + `list.c` from V10.4.3, `queue.c`
  from V11.0.0. Constructed to reproduce a real pattern observed in practice — a project
  where a partial upgrade replaced only some kernel files, leaving the rest on an older
  release. Ground truth is known exactly because we built it; used to validate the
  cross-file version-consistency check in `match_target.py`.

- **`armv8m-config-synthetic/`** — **synthetic but internally coherent** (added
  2026-07-28 for the [port-layer experiment](../experiments/port-layer/README.md)): the
  six core kernel `.c` files *and* the `portable/GCC/ARM_CM33/non_secure` port, both taken
  verbatim from upstream **V10.5.1**, plus a hand-written `FreeRTOSConfig.h` setting
  `configENABLE_MPU 0`. Ground truth: V10.5.1 is inside CVE-2024-28115's affected range,
  but the ARMv8-M port has the MPU disabled, so the CVE does not apply to this build —
  the entry exists to exercise the *build-configuration* dimension of advisory
  applicability. Flipping the macro to `1` flips the verdict back to AFFECTED (verified).

**Port-layer files added to the real entries (2026-07-28)**: `nxp-mcux-vendored/` gained
its `portable/GCC/ARM_CM4_MPU/` files (verbatim upstream MPU port, ground truth
V11.2.0 — matching the core files' independent result), and `esp-idf-fork/` gained its
`portable/xtensa/` port. The latter is the interesting one: Espressif's Xtensa port is
their own code at a path that exists nowhere upstream, so the correct answer is
"unidentified port, and definitely not an ARM MPU port" — which is what rules
CVE-2024-28115 out for that tree despite its affected kernel version.

The first two were fetched directly from their respective upstream/vendor GitHub repos
(not hand-modified) so they reflect real vendoring behavior, not synthetic test data —
only `mixed-version-synthetic/` is assembled rather than observed as-is.
