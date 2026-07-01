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

The first two were fetched directly from their respective upstream/vendor GitHub repos
(not hand-modified) so they reflect real vendoring behavior, not synthetic test data —
only `mixed-version-synthetic/` is assembled rather than observed as-is.
