# lwIP corpus — ground truth

Seven trees used to validate
[../experiments/version-fingerprint](../experiments/version-fingerprint/README.md). Each
holds the 7 tracked files in their upstream-relative layout (`src/core/…`,
`src/api/…`, `src/include/lwip/…`), so the matcher's recursive scan sees them exactly as
a real vendored copy would present them.

All content is BSD-3-Clause (lwIP upstream and all three vendor forks), so it is checked
in directly rather than referenced.

| Entry | Origin (exact ref) | Ground truth |
|---|---|---|
| `st-stm32-mw-2.1.3` | `STMicroelectronics/stm32-mw-lwip` @ tag `v2.1.3_20241213` | **verbatim 2.1.3** — `src/` diff against `STABLE-2_1_3_RELEASE` is empty. Also carries ST's own `system/arch/cc.h`, `system/arch/init.h` and `system/OS/sys_arch.c` as **decoys**: `init.h` deliberately collides on basename with the tracked `src/include/lwip/init.h`. |
| `savannah-zip-2.0.2` | official `lwip-2.0.2.zip`, `download.savannah.nongnu.org/releases/lwip/` | **2.0.2 as actually released** — byte-identical to git tag `STABLE-2_0_2_RELEASE_VER`, *not* to `STABLE-2_0_2_RELEASE` (which still declares 2.0.1 in `init.h`). The release-artifact-vs-tag case. |
| `esp-lwip-2.2.0-esp` | `espressif/esp-lwip` @ branch `2.2.0-esp` | **2.2.0, heavily patched** — 54 files / +3446−257 vs `STABLE-2_2_0_RELEASE`, incl. new NAPT feature files. `init.h` has `LWIP_VERSION_RC` flipped to `LWIP_RC_DEVELOPMENT`. `pbuf.c` unpatched. |
| `nxp-mcux-2.16.100` | `nxp-mcuxpresso/lwip` @ tag `MCUX_2.16.100` | **post-2.2.0 master snapshot, very heavily patched** — 102 files / +12462−1279. Declares 2.2.1 + DEVELOPMENT. The tag name is an *SDK* version, not an lwIP version. |
| `xilinx-lwip220` | `Xilinx/embeddedsw` @ `xilinx_v2024.1`, `ThirdParty/sw_services/lwip220/src/lwip-2.2.0/` | **2.2.0, partially patched** — 7 of 20 core `.c` files differ from upstream by git blob SHA. Version is also declared in the directory path. |
| `mixed-version-synthetic` | built here | **deliberately mixed**: `init.h` + `sockets.c` from `STABLE-2_1_2_RELEASE`, the five core files from `STABLE-2_0_3_RELEASE`. Exercises the MIXED_VERSION branch. |
| `negative-control-cjson` | `DaveGamble/cJSON` @ `v1.7.18` | **not lwIP** — `cJSON.c`/`cJSON.h` saved under every tracked path. Must score ~0 and report NOT_THIS_COMPONENT. |

Rebuild note: the three fork entries were extracted by adding each fork as a git remote of
an upstream lwIP clone (they share history, so `git diff <upstream-tag> <fork-ref>` works
directly) and dumping the tracked paths at the ref above. Xilinx's `embeddedsw` is not a
fork of lwIP, so those files were fetched over raw.githubusercontent.
