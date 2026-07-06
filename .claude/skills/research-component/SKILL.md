---
name: research-component
description: Research a new FOSS C component for this repo (distro landscape + a version-fingerprint detection experiment), following the same two-phase process already used for FreeRTOS and mbedTLS. Use when starting research on a new component, or resuming/deepening research on one already in progress.
---

# Researching a component (this repo's standard workflow)

This repo (see `CLAUDE.md`) researches how to detect known C FOSS components vendored
into embedded projects. Every component researched so far (FreeRTOS, Mbed TLS) followed
the same two-phase process. This skill codifies it so the next component doesn't require
re-deriving the approach, and so the mechanical parts (fetching, fingerprinting, corpus
building) don't have to be reinvented each time.

**Read `CLAUDE.md` and `general/README.md` first** if not already in context — they hold
the settled scope decisions and the cross-cutting principles extracted so far. Don't
re-litigate settled scope; do flag if this component's findings suggest revisiting one.

## The one rule that matters most

**Verify every distribution/integration claim against real source, not just vendor
documentation or blog posts.** The mbedTLS pass initially wrote up the `_ALT`
hardware-acceleration mechanism as "vendor file replaces upstream file" based on reading
Mbed TLS's own docs — this was wrong. Actually cloning and diffing three real vendor
forks (Espressif, ST, NXP) against the matching upstream tag showed the real pattern is
in-place conditional patching, not file replacement. The correction was only possible
because real files were fetched and diffed. Treat every "vendor X does Y" claim in phase
1 as a hypothesis to confirm with an actual `diff` before it goes in the README — cheap
to check (a handful of `curl`/`git ls-remote` calls), expensive to get wrong (it
determines the detection strategy in phase 2).

## Phase 1 — Distro-landscape research

Goal: understand who forks/vendors this component before attempting detection, and
produce `components/<name>/README.md`.

1. **Governance and licensing history**: original author/project, ownership changes,
   license changes, renames (org/repo renames matter for PURL — e.g. `ARMmbed` →
   `Mbed-TLS`). Note any copyright-header wording shift tied to a governance change (a
   cheap version-era heuristic — see general/README.md).
2. **Component granularity**: is this "one" component, or does the brand name bundle
   several independently-versioned upstream repos (à la FreeRTOS-Kernel vs.
   FreeRTOS-Plus, or Mbed TLS vs. TF-PSA-Crypto)? Getting this wrong means one vendored
   integration produces the wrong number of SBOM entries. See general/README.md's
   component-granularity note.
3. **What layers stack on top** — for each silicon-vendor/RTOS integration you can find:
   - Clone or fetch the vendor's fork/middleware repo at a real tag/branch.
   - Fetch the matching upstream release tag.
   - `diff` the files vendors are documented (or suspected) to touch.
   - Classify what you actually see: byte-identical (verbatim vendoring), whole-file
     replacement (sanctioned override point, e.g. a companion `*_alt.c`-style file with
     the original absent), or in-place patching (real modification — note the *shape*:
     is it wrapped in vendor-recognizable macros/comments, or unstructured?).
   - Check for a vendor-authored changelog/provenance file (e.g. `st_readme.txt`-style)
     — when present, it's stronger ground truth than any diff you could derive yourself.
4. **Naming/identifiers for an SBOM entry**: look up the real NVD CPE dictionary entries
   (`https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=<name>`) — don't
   assume one vendor:product pair covers the whole component's history (old rebrands
   often have their own separate CPE, e.g. PolarSSL vs. mbed). Note the CPE `part` field
   (`a`/`o`/`h`) — don't assume `a`. Derive the PURL from the current (not historical)
   GitHub org/repo name. Note where GHSA/OSV entries are actually keyed.
5. **Does an official amalgamated/single-header release exist?** State this explicitly
   either way — this repo's scope names "amalgamated/single-header" as a priority
   detection case, and it's useful to know up front whether a given component is or
   isn't a candidate for that case.
6. **License divergence check**: if the component is dual/multi-licensed upstream, check
   whether any real vendor fork re-licenses its copy (a single-license redistribution is
   legal and only requires editing the SPDX header line — see general/README.md). If
   found, note explicitly that comment-stripped content matching will not detect this,
   and a separate unnormalized license-line check would be needed.
7. **Write `components/<name>/README.md`**, structured like
   `components/mbedtls/README.md`: numbered sections building toward a "Detection
   implications" section, an "Open questions / next steps" section, and a "Sources" list
   citing every URL actually used (including the specific vendor repo tags/commits
   diffed in step 3 — cite them as sources too, not just docs).
8. **Extract anything generalizable into `general/README.md`**, cross-linked both
   directions (`First observed in: ...` back-reference, and a forward link from the
   component doc to the general note). Only extract what's actually general — don't
   force a component-specific detail into general notes.
9. **Update `CLAUDE.md`'s "Current status" section.**

## Phase 2 — Version-fingerprint detection experiment

Goal: validate exact-hash + winnowing-similarity matching against real corpus data for
this component, producing `components/<name>/experiments/version-fingerprint/`.

### Pick tracked files from evidence, not guesswork

Don't try to track "all" of a large component's files. Pick a small set (FreeRTOS used
3, mbedTLS used 5) based on what phase 1 actually showed:
- At least one file demonstrated to survive vendor modification untouched (a version-
  macro carrier is ideal — it anchors the pinned base version even when other tracked
  files are modified).
- The specific files phase 1's diffing showed vendors actually touch.

State in the experiment README that this is a deliberately narrow research scope, not a
claim that these are "the" minimal signature files for the component (unless they
demonstrably are, the way FreeRTOS's 3 kernel files are).

### Build the reference DB

Copy `templates/fingerprint.py.template` and `templates/build_reference_db.py.template`
into `components/<name>/experiments/version-fingerprint/`, rename, and fill in:
`REPO`, `FILES` (paths relative to repo root), and the tag-scope filter (`TAG_RE` and
whatever version-range/era exclusion applies — e.g. exclude a pre-rebrand era, or a
too-new post-split era not yet in scope).

Before running it for real, do a **quick tag-count sanity check** first (see "Known
pitfalls" below) — `git ls-remote --tags <repo-url> | wc -l` — so you know roughly how
many fetches you're about to make and can adjust the request-pacing delay if needed.

Run it (`python build_reference_db.py`) as a **background** task — even a paced fetch
over a few hundred tags takes minutes, and there's no reason to block on it. Move on to
building the corpus while it runs.

### Build the corpus from real forks — not synthetic examples only

For each vendor/fork identified in phase 1, fetch the *actual* tracked files at a real
tag/branch into `components/<name>/corpus/<vendor-or-fork-name>/`, preserving the
upstream repo's relative directory structure (so `match_target.py`'s recursive scan finds
them exactly as a real vendored copy would lay them out). Aim to cover, per the FreeRTOS/
mbedTLS precedent:
- At least one real fork with genuine modification.
- A synthetic **mixed-version** case (tracked files deliberately pulled from two
  different real releases) — validates the MIXED VERSION WARNING branch.
- A negative control: an unrelated real C file (e.g. a well-known small library) saved
  under each tracked filename — validates that unrelated code scores near zero and isn't
  falsely confirmed.

### Match and write up

Copy `templates/match_target.py.template`, rename, adjust the tracked-filename list.
Run it against every corpus entry once the reference DB build finishes. Write
`experiments/version-fingerprint/README.md` mirroring
`components/freertos/experiments/version-fingerprint/README.md`'s structure: the
question being answered, the approach, a "Reference DB size" note (see general/README.md
— measure it, don't assume it from another component), a results table per corpus entry,
a "Result"/conclusion paragraph, and "Known limitations / next steps."

Finish by updating the component's README "Open questions" section and `CLAUDE.md`'s
status section to point at the completed experiment.

## Known pitfalls (learned the hard way, don't rediscover these)

- **raw.githubusercontent.com rate-limits unauthenticated bursts (HTTP 429).** Pace
  requests (a fraction of a second between fetches) and retry with exponential backoff on
  429. The templates already do this — don't strip it out to go faster.
- **A repo can have far more tags than releases** (mbedTLS had 537 total tags but only
  116 unique commits after dedup in the 2.x/3.x range — old naming schemes, `-rc`/`-beta`
  suffixes, unrelated non-release refs like `yotta-*` or `mbedos-*` all show up in
  `git ls-remote --tags`). Filter with a tag-name regex scoped to real releases, and
  **dedup by commit SHA** (use the peeled `^{}` SHA from `git ls-remote` output) *before*
  fetching — don't rely on post-fetch content-hash dedup alone when a repo is known to
  double-tag releases, since that still wastes the fetch.
- **On Windows, prefer running Python scripts via the PowerShell tool (or explicit
  Windows-style paths), not Git Bash's `/tmp`/`/c/...` paths.** Native Windows Python
  does not resolve MSYS-style paths — a script or file that Bash can read/write fine at
  `/tmp/x` may not exist as far as Windows Python is concerned. Use `cygpath -w` to
  convert a path if a Bash-written file needs to be handed to a Windows tool.
- **Don't write a distro-landscape finding from a vendor's documentation alone** — see
  "The one rule that matters most" above.
