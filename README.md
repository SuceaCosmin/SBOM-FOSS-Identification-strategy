# SBOM FOSS Identification Strategy

Research on identifying known C open-source components that have been copy-pasted /
vendored into embedded projects (firmware, RTOS, AUTOSAR-style toolchains) without a
package manager. Findings here will inform an SBOM generator built in a separate repo.

See [CLAUDE.md](CLAUDE.md) for the full scope, priorities, and working conventions.

## Layout

- [docs/](docs/) — findings, tool surveys, technique comparisons, design notes.
- [experiments/](experiments/) — small prototype scripts testing detection ideas.
- [corpus/](corpus/) — example embedded source trees/snippets with known ground truth,
  used to validate detection techniques.
