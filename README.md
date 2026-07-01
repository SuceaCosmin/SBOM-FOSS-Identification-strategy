# SBOM FOSS Identification Strategy

Research on identifying known C open-source components that have been copy-pasted /
vendored into embedded projects (firmware, RTOS, AUTOSAR-style toolchains) without a
package manager. Findings here will inform an SBOM generator built in a separate repo.

See [CLAUDE.md](CLAUDE.md) for the full scope, priorities, and working conventions.

## Layout

- [general/](general/) — cross-cutting principles that apply across components (SBOM
  identifier strategy, detection technique patterns, attribution rules), extracted from
  component research rather than tied to any single one.
- [components/](components/) — one folder per researched component (e.g.
  `components/freertos/`), each with a `README.md` of findings and, once there's
  content, `experiments/` (prototype scripts) and `corpus/` (ground-truth examples)
  subfolders.
