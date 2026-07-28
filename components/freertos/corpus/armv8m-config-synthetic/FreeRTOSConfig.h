/*
 * SYNTHETIC corpus file — not taken from any real project.
 *
 * Purpose: exercise the port-layer matcher's *build-configuration evidence* path
 * (components/freertos/experiments/port-layer/match_port.py, read_mpu_config()).
 *
 * The ARMv8-M ports (ARM_CM23/33/35P/55/85) are MPU-*capable*: whether the MPU is used
 * is decided at build time by configENABLE_MPU, so the port files alone cannot answer
 * whether an MPU-scoped advisory (e.g. CVE-2024-28115) applies. This file supplies the
 * missing half of that answer. Only the MPU-relevant macros below are meaningful for the
 * experiment; the rest of a real FreeRTOSConfig.h is deliberately omitted.
 *
 * Ground truth for this corpus entry: FreeRTOS-Kernel **V10.5.1** (core files and the
 * GCC ARM_CM33 non_secure port both taken verbatim from that upstream tag, so the tree is
 * internally coherent) with the MPU switched **off**.
 *
 * Expected verdict: V10.5.1 *is* inside CVE-2024-28115's affected range (<=10.6.1), so a
 * version-only check says AFFECTED — but the advisory applies only to ARMv7-M MPU ports
 * and ARMv8-M ports *with MPU support enabled*, and this build has it disabled. The
 * refined verdict must therefore be NOT_AFFECTED. This is the corpus entry that
 * exercises the build-configuration dimension; flipping the macro below to 1 should flip
 * the verdict back to AFFECTED.
 */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configENABLE_MPU                        0
#define configENABLE_TRUSTZONE                  0
#define configENABLE_FPU                        1
#define configRUN_FREERTOS_SECURE_ONLY          1

#define configUSE_PREEMPTION                    1
#define configCPU_CLOCK_HZ                      ( 100000000UL )
#define configTICK_RATE_HZ                      ( 1000 )
#define configMAX_PRIORITIES                    ( 5 )
#define configMINIMAL_STACK_SIZE                ( 128 )
#define configTOTAL_HEAP_SIZE                   ( 10 * 1024 )

#endif /* FREERTOS_CONFIG_H */
