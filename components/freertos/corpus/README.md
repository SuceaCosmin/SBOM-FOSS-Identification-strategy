# FreeRTOS corpus

Real-world `tasks.c` samples with known ground truth, used to validate the
[version-fingerprint experiment](../experiments/version-fingerprint/).

- **`esp-idf-fork/tasks.c`** — Espressif's SMP-modified fork, fetched from
  `espressif/esp-idf` (`master` branch,
  `components/freertos/FreeRTOS-Kernel/tasks.c`). Ground truth: a genuine kernel-level
  fork, based on FreeRTOS-Kernel v10.5.1 per Espressif's own docs (see
  [components/freertos/README.md §3](../README.md#3-what-layers-typically-stack-on-top-of-the-kernel)),
  with dual-core scheduler modifications layered on top. Represents the "locally
  modified vendored copy" integration pattern.
- **`nxp-mcux-vendored/tasks.c`** — NXP's vendored mirror, fetched from
  `nxp-mcuxpresso/FreeRTOS-Kernel` (`release/26.03.00` branch). Ground truth: content-
  identical (modulo comments/whitespace) to upstream FreeRTOS-Kernel V11.2.0 — an
  unmodified verbatim vendored copy, distributed via NXP's MCUXpresso SDK integration
  layer.

Both fetched directly from their respective upstream/vendor GitHub repos (not
hand-modified) so they reflect real vendoring behavior, not synthetic test data.
