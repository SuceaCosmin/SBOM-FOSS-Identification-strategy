# Findings

Written research findings live here: tool/technique surveys, tradeoff analysis, and
design notes intended for the eventual SBOM generator (built in a separate repo).

Suggested starting topics (not yet written):

- Survey of existing tools (ScanCode, ScanOSS, FOSSology, Black Duck snippet matching,
  TrendMicro/OSS tools) and how applicable each is to modified/amalgamated C vendoring.
- Fuzzy hashing / fingerprinting techniques (ssdeep, TLSH, winnowing, MinHash) and their
  fit for detecting locally-modified vendored C code.
- Reference corpus tradeoffs: build-your-own vs. reuse existing databases
  (ClearlyDefined, OSS Index, ScanCode LicenseDB, FOSSology).
