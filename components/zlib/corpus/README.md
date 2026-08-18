# zlib corpus — ground truth

Eight trees used to validate
[experiments/version-fingerprint](../experiments/version-fingerprint/README.md). Files were
fetched 2026-08-18 from the sources named below. Each tree keeps the *carrier's own* layout
where it has one (U-Boot and the Linux kernel place zlib under their own paths), because
locating tracked files is part of what is being tested.

| tree | origin | ground truth | expected verdict |
|---|---|---|---|
| `verbatim-1.2.11` | upstream tag `v1.2.11` | unmodified 1.2.11 | CONFIRMED 1.2.11 |
| `subset-inflate-only-synthetic` | upstream `v1.2.13`, inflate side only | complete decompression-only integration — the normal embedded shape | CONFIRMED 1.2.13 |
| `mixed-version-synthetic` | upstream: inflate side `v1.2.13`, deflate side `v1.2.8` | clean two-release mix; isolates the MIXED path from the modification path | MIXED_VERSION, both sides named |
| `uboot-lib-zlib` | `u-boot/u-boot` @ `master`, `lib/zlib/` + `include/u-boot/zlib.h` | pppd-patched, heavily modified; **two-era** — prose says 1.2.3, deflate side is 1.2.5 | INCONSISTENT; deflate ≈1.2.5, inflate ≈1.2.2–1.2.3 |
| `linux-kernel-zlib` | `torvalds/linux` @ `master`, `lib/zlib_inflate/` + `lib/zlib_deflate/` + `include/linux/zlib.h` | renamed (`zlib_` prefix) restructured subset; **two-era**, declared in its own header: inflate 1.2.3, deflate 1.1.3 | INCONSISTENT; deflate ≈1.1.x, inflate ≈1.2.3.x |
| `chromium-third-party-zlib` | `chromium/chromium` @ `main`, `third_party/zlib/` | untagged upstream commit `09a1572a` (2026-02-21), 4 days after v1.3.2; declares 1.3.2 / 1.3.2.1 / 1.3.2.1-motley | LIKELY_CONSISTENT 1.3.2 (nearest release — exact content is not in any tag) |
| `zlib-ng-adversarial` | `zlib-ng/zlib-ng` @ `develop` | **not zlib** — a C11 rewrite with identical filenames, an API-compatible header declaring `ZLIB_VERSION "1.3.1.zlib-ng"`, and no shared implementation | NOT_THIS_COMPONENT |
| `negative-control-cjson` | `DaveGamble/cJSON` @ `master` | unrelated C, saved under each tracked filename | NOT_THIS_COMPONENT |
| `dist-1.2.13-core-only` | upstream `v1.2.13`, all root `.c`/`.h` + build files, **no `contrib/`** | a complete core-only distribution — the shape a scanner can legitimately call "minizip absent" | CONFIRMED 1.2.13 |
| `dist-1.2.13-with-contrib` | same, **plus** `contrib/minizip/` and `contrib/untgz/` | complete distribution including the two sub-components that carry their own CVEs | CONFIRMED 1.2.13 |

## Notes on two of them

**`zlib-ng-adversarial` is the important negative control**, not `negative-control-cjson`.
cJSON scores 0.000 on everything and proves little. zlib-ng matches every *cheap* signal —
filenames, API surface, and a version macro naming a real zlib release — while sharing no
implementation, so it is the case a detector actually has to survive. Its `zlib.h` is
copied from the shipped `zlib.h.in` template, which is what an installed zlib-ng looks
like; without it the metadata tier is never exercised. Its per-file scores (max 0.250)
overlap with the genuine U-Boot fork's low end (0.09–0.21), which is what forced the
matcher's reject rule to be rebuilt around positive evidence — see the experiment README,
"Calibrating the reject rule".

**`uboot-lib-zlib` deliberately includes both files named `zlib.h`** — the 17-line glue
shim at `lib/zlib/zlib.h` and the real merged header at `include/u-boot/zlib.h`. zlib's
flat upstream layout means a tracked path suffix degenerates to a bare basename, so this
tree is what tests the matcher's score-based duplicate resolution. It picks the real header
(0.206) over the shim.

**The two `dist-1.2.13-*` trees exist for phase 3, not phase 2.** They are identical in
version and in every tracked file, and differ only by the presence of `contrib/minizip`
and `contrib/untgz` — which is exactly the axis `CVE-2023-45853` and `CVE-2026-22184` turn
on while being bound to the core zlib CPE (see
[advisory-fitness](../../../general/experiments/advisory-fitness/README.md#zlib-2026-08-18--the-third-loop-and-the-first-sub-component-refinement)).
They are also the only trees here that are *complete distributions* rather than extracts
of the tracked files, which is what lets `end_to_end_zlib.py` claim a sub-component is
ABSENT at all; every other tree correctly reports UNKNOWN.

## Licensing

All content is from permissively-licensed upstreams (zlib License; the Linux kernel's zlib
files carry the zlib License, not GPL; cJSON is MIT; zlib-ng is the zlib License). The
carrier-derived trees hold only the handful of files the experiment tracks; the two
`dist-1.2.13-*` trees are fuller by design (a complete distribution is the point), but are
still plain upstream zlib under its own permissive licence.
