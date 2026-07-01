# FreeRTOS distribution landscape

First research pass: understanding how many distinct "FreeRTOS" things exist in the
wild and who distributes them, before attempting to detect vendored copies. Triggered
by a real observation in a project containing both Amazon/AWS FreeRTOS references and
an NXP layer around it, plus a separate NXP-promoted RTOS.

## 1. Governance and licensing history

- FreeRTOS was originally written by Richard Barry (~2003) while at WITTENSTEIN High
  Integrity Systems (WHIS).
- In 2017, stewardship passed to AWS. License changed at that point from a modified
  GPLv2 (with a static-linking exception) to plain **MIT**.
- "Amazon FreeRTOS" (the AWS IoT-flavored distribution bundling connectivity/security
  libraries) and plain "FreeRTOS" were unified in naming/branding after 2017 — AWS now
  stewards the upstream project itself.
- Upstream lives at [github.com/FreeRTOS](https://github.com/FreeRTOS). The pure
  scheduler kernel is its own repo,
  [FreeRTOS/FreeRTOS-Kernel](https://github.com/FreeRTOS/FreeRTOS-Kernel), submoduled
  into the umbrella `FreeRTOS/FreeRTOS` repo and various vendor forks.
- Copyright header pattern shifted with governance: pre-2017 headers reference
  WHIS/Real Time Engineers Ltd wording; post-2017 headers read
  `Copyright (C) <year> Amazon.com, Inc. or its affiliates.` under MIT. This shift is
  itself a usable era/version heuristic.

## 2. What "layers" typically stack on top of the kernel

The kernel itself (`tasks.c`, `queue.c`, `list.c`, `timers.c`, `event_groups.c`,
`stream_buffer.c`, `croutine.c`, `portable/<compiler>/<arch>/...`) is usually vendored
close to verbatim by downstream distributors. What varies is what gets bolted around it:

- **Silicon-vendor SDK integration layer** — vendor doesn't fork the scheduler; they
  vendor upstream FreeRTOS-Kernel largely unmodified and add their own adaptation code:
  driver wrappers, tickless-mode glue, RTOS-aware filesystem bindings. This is a
  **separate, distinctly-copyrighted component**, not part of FreeRTOS itself, and
  should be a separate SBOM entry.
  - NXP: MCUXpresso SDK integration
    ([README](https://mcuxpresso.nxp.com/mcuxsdk/latest/html/rtos/freertos/freertos-kernel/README.html)),
    driver layer in
    [nxp-mcuxpresso/mcux-freertos-drivers](https://github.com/nxp-mcuxpresso/mcux-freertos-drivers).
  - ST: `stm32-mw-freertos` middleware component, distributed via X-CUBE-FREERTOS
    ([STMicroelectronics/stm32-mw-freertos](https://github.com/STMicroelectronics/stm32-mw-freertos)).
- **CMSIS-RTOS2 API wrapper** — a portability shim (`cmsis_os2.c`) that lets app code
  call a vendor-neutral CMSIS-RTOS2 API regardless of which RTOS backend (FreeRTOS,
  ThreadX/Azure RTOS, etc.) is actually running underneath. Seen in ST's STM32Cube
  packages under `Middlewares/Third_Party/FreeRTOS/Source/CMSIS_RTOS_V2/`. This wrapper
  is its own identifiable component, distinct from both the kernel and the vendor's
  driver layer.
- **Real forks with kernel-level modification** — genuine divergence from upstream, not
  just an adaptation layer around it:
  - Espressif ESP-IDF FreeRTOS: forked from v10.5.1, modified for dual-core SMP
    scheduling (`xTaskCreatePinnedToCore`, per-core scheduler suspension, spinlock-based
    critical sections instead of global interrupt disable). Good corpus candidate for
    the "locally modified vendored copy" detection case.
- **Commercially certified derivatives** — not source-identical to FreeRTOS, relevant in
  safety/AUTOSAR-adjacent contexts:
  - **SafeRTOS** (WHIS) — pre-certified rewrite for IEC 61508 / EN 62304 / FDA 510(k).
  - **OpenRTOS** (WHIS) — commercially licensed, unmodified-kernel + paid support/porting.

## 3. NXP's *other* RTOS is unrelated to FreeRTOS

The "NXP is also promoting some form of RTOS" observation is very likely a *different*
component sharing no code lineage with FreeRTOS:

- **MQX RTOS** — NXP's legacy proprietary RTOS (inherited from the Freescale
  acquisition). Own kernel, own TCP/IP stack (RTCS), own filesystem (MFS), own USB
  stack. Commercially licensed.
- **Zephyr** — Linux Foundation-hosted open-source RTOS; NXP is a major contributor and
  promotes it (incl. via "Real-Time Edge" bundling on i.MX Cortex-A/M parts) as a modern
  alternative to MQX. Also unrelated to FreeRTOS.

If a project shows both FreeRTOS and NXP RTOS references, the likely explanation is a
mixed-RTOS project (e.g. FreeRTOS on one core/subsystem, MQX or Zephyr elsewhere), not a
FreeRTOS variant.

## 4. Detection implications

- **Structural fingerprint**: the FreeRTOS-Kernel file set/naming is distinctive enough
  to flag candidates before any content-level matching — cheap first-pass filter.
- **Version macro**: `tskKERNEL_VERSION_NUMBER` string literal in `tasks.c` (e.g.
  `"V10.4.3"`) gives an exact version even in modified copies, as long as that specific
  line survives editing.
- **Copyright header era**: WHIS-era vs. `Amazon.com, Inc.` header wording is a coarse
  but cheap version-era signal, useful as a metadata heuristic layered on top of
  fingerprint matching.
- **Attribution matters**: a single embedded project can legitimately contain 2-3
  separate SBOM-worthy components stacked together (kernel + vendor adaptation layer +
  CMSIS wrapper). Detection logic should not assume "found FreeRTOS signature" ==
  "one component" — it needs to separate the kernel from what's wrapped around it.

## Open questions / next steps

- Build a corpus entry from the STM32/NXP project where this was originally observed
  (kernel + NXP layer + possibly CMSIS wrapper) to validate the "multiple stacked
  components" detection logic against a real example.
- Espressif ESP-IDF FreeRTOS is a strong candidate for the first fuzzy-hashing
  experiment (real, well-documented kernel-level fork vs. upstream).

Sources:
- [FreeRTOS - Wikipedia](https://en.wikipedia.org/wiki/FreeRTOS)
- [Amazon FreeRTOS FAQs](https://aws.amazon.com/freertos/faqs/)
- [FreeRTOS versions - FreeRTOS](https://docs.aws.amazon.com/freertos/latest/userguide/freertos-versioning.html)
- [MCUXpresso SDK: FreeRTOS Kernel NXP Integration](https://mcuxpresso.nxp.com/mcuxsdk/latest/html/rtos/freertos/freertos-kernel/README.html)
- [nxp-mcuxpresso/mcux-freertos-drivers](https://github.com/nxp-mcuxpresso/mcux-freertos-drivers)
- [MQX RTOS | NXP Semiconductors](https://www.nxp.com/design/design-center/software/embedded-software/mqx-software-solutions/mqx-real-time-operating-system-rtos:MQXRTOS)
- [ESP-IDF FreeRTOS (SMP) Programming Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/freertos-smp.html)
- [WITTENSTEIN high integrity systems](https://www.highintegritysystems.com/)
- [SAFERTOS and OPENRTOS - FreeRTOS Partners](https://www.freertos.org/Partners/Software/SafeRTOS-and-OpenRTOS)
- [STMicroelectronics/stm32-mw-freertos](https://github.com/STMicroelectronics/stm32-mw-freertos)
- [FreeRTOS-Kernel LICENSE.md](https://github.com/FreeRTOS/FreeRTOS-Kernel/blob/main/LICENSE.md)
