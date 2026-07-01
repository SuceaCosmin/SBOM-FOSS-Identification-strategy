# Corpus

Example embedded C source trees or snippets with **known ground truth** of which OSS
component was vendored in (name, version, upstream URL, and how it was modified if at
all). Used to validate detection techniques from `experiments/` against real cases.

Each example should record at minimum:

- The vendored component's identity (project, version/commit if known)
- Where it came from (upstream repo/URL)
- How it was integrated (verbatim copy, amalgamated single-header, locally modified —
  and if modified, roughly how)
- The embedded context it was found/placed in (e.g. FreeRTOS project, STM32 HAL, AUTOSAR
  toolchain project)
