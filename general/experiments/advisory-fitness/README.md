# Advisory-source fitness — do our results drive standard vuln databases?

**Question**: this whole repo exists to produce SBOMs that drive **vulnerability
scanning**. Every prior experiment stopped at producing `purl + version` (or a
version *window*). This experiment feeds that output into the **standard
advisory sources a real scanner queries** and asks: do the right, real CVEs come
back? It is open item 2 in
[../../existing-fingerprint-datasets.md](../../existing-fingerprint-datasets.md),
designated next-up 2026-07-18. Sources covered so far (run **2026-07-22**):
[OSV.dev](https://osv.dev), [NVD](https://nvd.nist.gov)/CPE, and the
[GitHub Advisory Database](https://github.com/advisories) (GHSA). The full menu
of sources still to test is in
[../../advisory-source-roadmap.md](../../advisory-source-roadmap.md).

Three sub-questions per source: (1) does it recognize the coordinates we produce
(GitHub-flavored purl, upstream semver)? (2) does a **version** actually filter
the CVE set, or is matching inert? (3) which of our components does it **cover**?

Reproduce (read-only public APIs, no keys): `python osv_probe.py --json
osv_results.json`, `python nvd_probe.py --json nvd_results.json`,
`python ghsa_probe.py --json ghsa_results.json`. The `*_results.json` are
committed snapshots — CVE *counts* drift as sources ingest advisories; the
*shape* of the findings is the durable result.

**Follow-up run 2026-07-28**: the fitness question is answered, so the loop was
*closed* — see [Closing the loop](#closing-the-loop--detected-version--applicable-cve-end-to-end-2026-07-28)
for the first end-to-end detection → CVE result (`ghsa_vuln_lookup.py`,
`end_to_end_freertos.py`).

## Comparative verdict — NVD/CPE is the primary fit source; GHSA is fit only via its per-repo feed; OSV is not

| source | mbedTLS coverage | version discrimination | FreeRTOS | CMSIS | our-coordinate that works |
|---|---|---|---|---|---|
| **NVD/CPE** | ✓ `arm:mbed_tls` | ✓ **real** (@99.0.0 → 0) | CVEs exist, AWS-versioned | `cmsis-rtos` only | **canonical identity → CPE 2.3** |
| **OSV.dev** | distro advisories only | ✗ **inert** (@99.0.0 → 83) | **absent** | **absent** | none upstream (distro purl / GIT-commit) |
| **GHSA (global feed)** | unreviewed CVE mirror, no ecosystem | ✗ none | ✗ absent via `affects=` | absent | none (no C/C++ ecosystem) |
| **GHSA (per-repo feed)** | ✗ upstream doesn't self-publish | ✓ **real** for self-publishers | ✓ **kernel-semver range** (CVE-2024-28115 `<=10.6.1`) | absent | **`{owner}/{repo}` → repo advisory feed** |

> **Correction (2026-07-23):** the original run (2026-07-22) tested only GHSA's
> *global* `/advisories` feed (`affects=`, `cve_id=`) and concluded GHSA was flatly
> "least fit." That missed a second access path — the per-repository
> `/repos/{owner}/{repo}/security-advisories` feed — where maintainers who self-publish
> carry **real, version-ranged** advisories keyed to the *upstream* version scheme. For
> FreeRTOS-Kernel this is materially better than NVD (see the GHSA section below). The
> global-feed findings stand; the "GHSA is useless for embedded C" conclusion does not.

The headline: **NVD/CPE gives the version-accurate matching the whole pipeline
was built to feed** — an impossible version returns 0 where OSV returns the
entire historical pile. The generator's vuln-lookup mapping should target
**CPE 2.3** as the primary coordinate, with OSV's GIT-commit CVE records as an
upstream-accurate secondary (usable because we already mine per-release tags),
and OSV package / GHSA queries as at-best coarse nets. Per-source detail below.

## OSV.dev — not directly fit for embedded C

The naive integration a reader would assume — declare a canonical upstream purl
+ version, query OSV, get that version's CVEs — **fails in three independent
ways**, each demonstrated below. Coverage is distro-repackaging-shaped, not
upstream-shaped; our own coordinates don't resolve; and the one query form that
returns anything is version-inert.

### Finding 1 — the declared (GitHub) purl returns nothing

| query | raw vulns | CVEs |
|---|--:|--:|
| **control** `pkg:pypi/django` @3.0.0 | 31 | 21 |
| `pkg:github/mbed-tls/mbedtls` @2.28.0 | **0** | **0** |
| `pkg:github/freertos/freertos-kernel` @10.4.3 | **0** | **0** |
| `pkg:github/arm-software/cmsis_5` @5.9.0 | **0** | **0** |
| `pkg:github/nanopb/nanopb` @0.3.9.3 | **0** | **0** |

The PyPI control returns 21 CVEs, so the purl-query technique is correct — the
zeros are a **real coverage gap**. OSV indexes ecosystem purls (`pkg:pypi/…`,
`pkg:npm/…`, `pkg:golang/…`, `pkg:deb/…`) but **not `pkg:github/…`**. Our
canonical attribution identity (rec. 7) — deliberately upstream/GitHub-flavored
so it's *correct* — is exactly the wrong key for OSV lookup. Identity and
vuln-lookup coordinate are **different keys**; the generator must map between
them, not assume the SBOM purl is queryable.

### Finding 2 — bare-name matching is version-inert (returns all history)

Dropping to a bare `name` (no ecosystem) *does* return results — but the same
CVE set regardless of version:

| query | raw vulns | distinct CVEs |
|---|--:|--:|
| `mbedtls` @2.28.0 (real) | 179 | **83** |
| `mbedtls` @3.6.2 (real, much newer) | 158 | **83** |
| `mbedtls` @99.0.0 (**impossible future**) | 125 | **83** |
| `mbedtls` @3.5.0 (TI `libmbedcrypto`) | 164 | **83** |
| `mbedtls` @2.22.0 (Wi-SUN EOL) | 179 | **83** |

An **impossible future version returns the same 83 CVEs** as a real one. Without
an ecosystem, OSV can't order versions, so name+version degenerates to "every
mbedtls advisory across every distro" (Alpine, Debian, Ubuntu, SUSE, Mageia,
Echo). A naive `name+version → OSV` integration would therefore report the
**identical CVE list for every version** — flagging a fully-patched build as
vulnerable and claiming a precision it does not have. This is the dangerous
failure mode for a tool whose output drives remediation. All the effort spent
pinning 2.22.0 vs 3.5.0 (the symbol-tier work) buys **nothing** on this path.

### Finding 3 — ecosystem-qualified queries discriminate, but need distro identity we don't have

Add a real ecosystem and version filtering partly wakes up:

| query | CVEs |
|---|--:|
| `mbedtls` + `Debian` @2.28.0-1 (real) | 49 |
| `mbedtls` + `Debian` @99.0.0 (impossible) | 43 |
| `pkg:deb/debian/mbedtls` @2.28.0 | 52 |

Better (49 ≠ 43), but (a) it needs **distro coordinates** (`Debian`,
`2.28.0-1`) our upstream detection never produces — and shouldn't, since the
firmware isn't running Debian's package; (b) even here the impossible version
returns 43, so it's still leaky; (c) it answers "what CVEs would Debian's
mbedtls package at this version have," a **different question** from "what CVEs
affect this vendored upstream source."

### Finding 4 — coverage is component-specific; FreeRTOS/CMSIS are invisible

- **FreeRTOS**: 0 under every coordinate tried (declared purl, `freertos`,
  `freertos-kernel`, `amazon-freertos`). A **known** FreeRTOS-Kernel CVE
  (`CVE-2021-31571`) is not even retrievable by ID from OSV. A Tier-1 component
  with **zero** OSV coverage.
- **CMSIS**: 0 under purl and bare name. (The umbrella-granularity question is
  moot — there's nothing to be granular about.)
- **nanopb**: declared purl 0, but bare `nanopb` → 5 CVEs (it has a PyPI
  presence). Partial, accidental coverage.

The generator must therefore track, **per component, which vuln source actually
covers it**, and treat an empty result as *"not covered"* — never silently as
*"no known vulnerabilities."* Those are opposite meanings and only per-component
coverage metadata distinguishes them.

## The one upstream-accurate path OSV does offer — and why *we* can use it

OSV *does* carry the raw CVE records for mbedTLS (e.g. `CVE-2024-45157`,
`CVE-2024-28960`), fetched by ID — but their affected ranges are **GIT-commit
ranges only** (`introduced`/`fixed` commit SHAs, no package name, no semver):

```
CVE-2024-45157  range GIT  introduced e483a77c… fixed 5e146ade…
                           introduced 3aef7670… fixed 71c569d4…
```

Unusable with a plain semver version in general — you'd need to resolve the
version to a commit and test range membership on the git DAG. **But this repo's
reference DBs already mine per-release *git tags*** (the version-fingerprint and
symbol-tier experiments check tags out by name), so a tag→commit map is free on
our side. That turns OSV's otherwise-unusable raw-CVE feed into a viable
**upstream-accurate** lookup: resolve our detected version to its release commit,
test membership in each CVE's introduced..fixed GIT range. Logged as the
concrete follow-up below, not built here.

## NVD/CPE — the fit source: real version-range discrimination

NVD is CPE-based, and CPE 2.3 match ranges are *upstream* version ranges. The
same matrix, via `virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>`:

| query (CPE `arm:mbed_tls`) | CVEs |
|---|--:|
| @2.28.0 (real) | 23 |
| @3.6.2 (real, newer) | 11 |
| @2.22.0 (Wi-SUN EOL, older) | 37 |
| @3.5.0 (TI `libmbedcrypto`) | 12 |
| **@99.0.0 (impossible)** | **0** |

This is exactly the discrimination OSV lacked: the impossible version returns
**0**, older versions carry more CVEs than newer (37 > 11), and every count is a
plausible per-version answer — genuine range matching against
`versionStartIncluding`/`versionEndExcluding`. **NVD/CPE is the upstream-accurate
path**, and the mapping the generator needs is **canonical identity → CPE 2.3**
(`pkg:github/mbed-tls/mbedtls` → `cpe:2.3:a:arm:mbed_tls`), with the detected
version tested against CPE ranges.

Coverage of the other components is more nuanced than OSV's flat zero:

- **FreeRTOS** *has* CPEs (`amazon:freertos` → 11 CVEs, `amazon:
  amazon_web_services_freertos` → 14) — unlike OSV, it's present. **But** these
  are the 2018 AWS-FreeRTOS TCP-stack CVEs keyed to **AWS-distribution
  versioning**, so our kernel semver `10.4.3` matches **0** of them. Coverage
  exists; the blocker is a **version-scheme mismatch** (kernel semver vs AWS
  distribution vs the FreeRTOS+TCP component) — a mapping/granularity problem,
  not an absence. This is the FreeRTOS instance of the component-granularity
  question already logged for CMSIS.
- **CMSIS**: only `arm:cmsis-rtos` has a CPE (0 CVEs at 5.9.0); Core/DSP/NN have
  none — the RTOS-classification gotcha documented in
  [../../README.md](../../README.md). Effectively uncovered, but for a
  *structural CPE-dictionary* reason, which is actionable (request/track CPEs)
  rather than a flat miss.

So NVD's failure modes are **mapping problems** (identity→CPE, version-scheme,
missing CPE names) — solvable in the mapping layer — whereas OSV's are
**structural** (no upstream feed, inert matching). That asymmetry is why NVD is
the primary target.

## GHSA — two access paths with opposite verdicts

GHSA has **two** query surfaces, and they behave completely differently for
embedded C. The first version of this experiment tested only the first and wrongly
concluded GHSA was useless.

### Path A — global `/advisories` feed: unfit (no C/C++ ecosystem)

The global feed is ecosystem-scoped and its ecosystems are npm / pip / go / maven /
rubygems / nuget / composer / … (confirmed: the 100 most-recent advisories are all
`{npm, pip, maven, composer}`, no C/C++) — **there is no C/C++ ecosystem**.
Consequences:

- `affects=mbedtls` → **0**, `affects=freertos` → **0**. No package-queryable
  coverage for any embedded-C component.
- A known mbedTLS CVE (`CVE-2024-45157`) *is* present as `GHSA-cvp8-hm87-hr8x`,
  but as an **unreviewed** advisory with an **empty ecosystem/package** — a bare
  CVE mirror with no version range. You can only retrieve it if you *already*
  have the CVE ID, which adds nothing over querying NVD directly. (Note: some
  repo-published advisories don't surface here at all — CVE-2024-28115 below returns
  **0** from the global feed even by `cve_id=`.)

### Path B — per-repository `/repos/{owner}/{repo}/security-advisories`: fit for self-publishers

Advisories a repo's *own maintainers* publish are reachable through the repository
endpoint, and these carry real version ranges — even under a **non-standard ecosystem
name** the global feed would never index:

| repo | advisories | version range (ecosystem / range) |
|---|--:|---|
| **FreeRTOS/FreeRTOS-Kernel** | 1 | `freertos-kernel` / **`<=10.6.1`**, patched `>=10.6.2` (CVE-2024-28115, HIGH) |
| FreeRTOS/FreeRTOS | 1 | `pip`-labelled / `202212.01, 202112.00` (AWS-distribution versioning) |
| FreeRTOS/coreMQTT | 1 | `v5.0.0` (CVE-2026-8686) |
| Mbed-TLS/mbedtls | **0** | — (mbedTLS self-publishes on its own advisory site + NVD, not GitHub) |

Two things make the FreeRTOS-Kernel row important, not a footnote:

1. **The range is keyed to kernel semver** (`<=10.6.1`) — *exactly the version scheme
   this repo's fingerprint detector outputs*. This is strictly better than NVD/CPE for
   FreeRTOS, where the CVEs use AWS-distribution versioning that our kernel semver
   `10.4.3` matches none of (the version-scheme mismatch logged for NVD). For a
   component whose maintainer self-publishes, the GHSA repo feed sidesteps the
   FreeRTOS version-scheme mapping problem entirely.
2. **It's only reachable via the repo endpoint.** GHSA-xcv7-v92w-gq6r returns **0**
   from the global `/advisories` feed even by `cve_id=CVE-2024-28115` — so a scanner
   querying only the standard global feed (as most do, and as our first run did) never
   sees it.

The catch is that Path B is **component-specific and non-uniform**: it works only for
components whose upstream is a GitHub repo *and* whose maintainers publish repository
advisories. FreeRTOS does; mbedTLS returns 0 (wrong source for it — use NVD).
So the GHSA repo feed is a **per-component opt-in source**, discovered from the
canonical identity's `{owner}/{repo}`, not a general fallback. This reinforces the
per-component coverage-metadata requirement: which source covers a component is itself
a mapped, per-component fact.

## Closing the loop — detected version → applicable CVE, end to end (2026-07-28)

The fitness tests above stop at "which source *could* answer". This section runs the
whole chain for real, on the FreeRTOS corpus: **vendored source tree → detected
version → advisory range membership → CVE verdict**. It is the first end-to-end
SBOM-to-vuln result in the repo. Deliberately narrow: the FreeRTOS-Kernel/GHSA-repo
pair is the one path that needs *no* version-scheme reconciliation (Path B above), so
it isolates the loop-closing question from the paused mapping-layer work.

Scripts (both reproduce offline from the committed advisory cache):

- **`ghsa_vuln_lookup.py`** — canonical identity → `{owner}/{repo}` → cached repo
  advisory feed → parse `vulnerable_version_range` → membership test → verdict.
  `python ghsa_vuln_lookup.py --component freertos-kernel --version V10.4.3`
  (`--refresh` re-fetches all mapped repos into `ghsa_repo_advisories.json`).
- **`end_to_end_freertos.py`** — chains the FreeRTOS matcher's new `scan_tree()` into
  that lookup and runs it over the corpus. Snapshot: `end_to_end_freertos_results.json`.

### Result: all three corpus ground truths resolve correctly

| corpus tree | detection | version(s) | verdict |
|---|---|---|---|
| `nxp-mcux-vendored` (verbatim V11.2.0) | CONFIRMED | `V11.2.0` | **NOT_AFFECTED** (post-fix) |
| `esp-idf-fork` (modified, ~10.5.1 base) | PARTIALLY_MODIFIED | `V10.5.1`, `V10.6.0` | **AFFECTED** — CVE-2024-28115 |
| `mixed-version-synthetic` | MIXED | 10.4.x tags **+** `V11.0.0/V11.0.1` | **AFFECTED** (the 10.4.x files are in the tree) |

So the loop closes: a real vendored tree, identified purely from source fingerprints,
yields a real, correctly version-filtered CVE. Four findings came out of making it work
— all of them about the *interface* between the two halves, none about the sources.

### Finding 1 — a version **set** means two different things, and the verdict depends on which

Every detector in this repo emits a *set* of release tags, never a single version. That
set carries two incompatible meanings, and collapsing them would silently convert
"unknown" into a hard yes/no:

- **candidates** (CONFIRMED with content-identical releases, PARTIALLY_MODIFIED) — the
  tree *is one of* these. If only some are affected, the honest verdict is
  **POSSIBLY_AFFECTED**, and the fix is to tighten *detection*, not the advisory query.
- **coexisting** (MIXED) — files from several releases are *simultaneously present*. If
  any one is affected, the tree is affected; there is nothing to narrow, the vulnerable
  file is genuinely there.

The synthetic mixed tree is the proof: it resolves to 10.4.x tags **and** V11.0.0/V11.0.1,
which under "candidates" semantics would read as an unresolvable ambiguity, but under
"coexisting" semantics is a definite AFFECTED. `end_to_end_freertos.py` keeps the two
apart explicitly. **The version-window output shape this repo has produced all along is
not a nuisance for vuln lookup — but it needs its semantics carried alongside it.**

### Finding 2 — version membership is necessary, not sufficient: applicability is prose

CVE-2024-28115's actual scope is *"ARMv7-M MPU ports and ARMv8-M ports with MPU support
enabled"* — a **port + build-config predicate**, stated only in the advisory's prose
summary. Nothing in the machine-readable range expresses it. A version-only verdict
therefore **over-claims**: a 10.4.3 kernel built for a non-MPU port is not actually
vulnerable. The lookup prints the scope line on every AFFECTED verdict rather than
pretending the answer is complete.

This is a direct, independent argument for the already-queued next step —
**consolidating FreeRTOS's port/`mpu_wrappers` layer** — which is exactly where this
CVE lives. Detecting *which port* is present is what would turn an over-broad AFFECTED
into a precise one. (Generalized: an advisory's applicability condition is a third input
next to identity and version, and it is not machine-readable in any source tested.)

> **Resolved 2026-07-28** by the
> [port-layer experiment](../../../components/freertos/experiments/port-layer/README.md).
> `end_to_end_freertos.py` now reports **two** verdicts — version-only, and refined by
> port + build-config evidence — and the refinement changes real answers:
>
> | corpus tree | version only | refined | why |
> |---|---|---|---|
> | `esp-idf-fork` (real vendor fork) | AFFECTED | **NOT_AFFECTED** | Xtensa port; not an ARM MPU port |
> | `armv8m-config-synthetic` | AFFECTED | **NOT_AFFECTED** | ARMv8-M port with `configENABLE_MPU 0` |
> | ↑ same tree, macro flipped to `1` | AFFECTED | AFFECTED *(confirmed)* | condition positively met |
> | `mixed-version-synthetic` | AFFECTED | **POSSIBLY_AFFECTED** | no port files — undecidable |
> | `nxp-mcux-vendored` | NOT_AFFECTED | unchanged | already outside the range |
>
> Three rules make this safe rather than a licence to guess: the refinement **only ever
> narrows** (composition evidence can withdraw or suspend a finding, never create one);
> **absent evidence suspends, it doesn't clear** (no port files ⇒ POSSIBLY_AFFECTED, the
> same discipline as "not covered" ≠ "no vulns"); and the applicability condition itself
> is **curated advisory metadata**, transcribed from the prose with its quote attached,
> not inferred. This is identification work — which port, which build switch — and
> deliberately stops short of reachability analysis (see the scope boundary below).

### Finding 3 — GHSA's `vulnerable_version_range` grammar is not reliably honored

Of the three FreeRTOS-org advisories, only **one** states a range in the documented
comma-separated-comparator grammar (`<=10.6.1`). The others are hand-written:
`202212.01, 202112.00` (an *enumeration* — ANDing it, as the grammar says, is
unsatisfiable and would yield NOT_AFFECTED for both listed versions) and `v5.0.0` (a
bare version, i.e. an implied `=`). `parse_range()` classifies these as
`conjunction` / `enumeration` / `exact` / `unparseable` and flags the non-conforming
ones instead of silently mis-evaluating them. **A consumer that assumes the documented
grammar will get wrong answers on real self-published advisories** — the kernel's range
happens to be the well-formed one, which is luck, not a rule.

### Finding 4 — upstream tag zoo vs. advisory ranges

Real tags in the reference DB don't all compare linearly against a mainline range, so
`parse_version()` classifies rather than forces:

- `V10.4.1-kernel-only` — packaging suffix only; same release content → compares as 10.4.1.
- `V10.4.3-LTS-Patch-3` — an **LTS maintenance branch**. Linearly it lands inside
  `<=10.6.1`, but a mainline range structurally *cannot* express backported fixes, so
  the verdict carries an explicit note to confirm against the LTS changelog. (Here the
  linear answer is right — the LTS patches predate the 2024 CVE — but the general case
  isn't decidable from the range.)
- `V202110.00-SMP` — **date-scheme** (AWS distribution versioning), not comparable to a
  kernel-semver range at all → **UNDETERMINED**, not a guess. This is the FreeRTOS
  version-scheme problem showing up *inside* the source that otherwise sidesteps it.
- `V9.0.0rc1` — prerelease, sorts before its release.

### Finding 5 — "not covered" is a first-class result

The lookup never returns an empty CVE list where it means "this source doesn't cover
this component". `mbedtls` → NOT_COVERED *with the reason and the right alternative*
(`use NVD/CPE cpe:2.3:a:arm:mbed_tls`); `cmsis` → NOT_COVERED (no repo feed); an
unmapped component (`lwip`) → NOT_COVERED (no mapping yet). Likewise a tree whose
version the detector couldn't resolve returns NOT_QUERYABLE — *"a detection gap, not a
clean bill of health"*. This implements sub-task 4 of the paused mapping-layer backlog
for one source, and `COMPONENT_MAP` is the miniature of sub-task 1: identity →
source coordinate, with per-component coverage metadata attached.

### Doing this for the next component (the repeatable part)

This is now **phase 3 of the `research-component` skill** — every component researched
from here on gets an advisory-source mapping, not just FreeRTOS. The skill holds the
authoritative steps (`.claude/skills/research-component/SKILL.md`, "Phase 3"); the
short version:

1. **Map identity → each source's coordinate.** NVD/CPE first (the CPE name rarely
   resembles the purl: `pkg:github/mbed-tls/mbedtls` → `cpe:2.3:a:arm:mbed_tls`); then the
   GHSA repo feed by adding a `COMPONENT_MAP` entry here and running `--refresh`; probe
   OSV only to record the expected miss.
2. **Always include an impossible-version control** (`@99.0.0`). Same CVEs back ⇒ the
   source is version-inert and must not be reported as precise.
3. **Compare version *schemes*, not just versions.** Detector scheme vs. advisory scheme;
   a mismatch is a recorded gap, not something to paper over.
4. **Record coverage with reasons**, including the negatives — "not covered, use X" is
   the required form; a bare empty list is a bug.
5. **Close the loop once** if a scheme-compatible source exists: copy
   `.claude/skills/research-component/templates/end_to_end.py.template`, point it at the
   component's matcher (needs the print-free `scan_tree()` split) and its `COMPONENT_MAP`
   key, run it over the corpus. The **negative** ground truth (post-fix version →
   NOT_AFFECTED) matters as much as the affected one.
6. **Write up the interface findings, not CVE counts** — counts drift; version-set
   semantics, range-grammar deviations, tag-shape handling and applicability conditions
   are the durable results.

`ghsa_vuln_lookup.py` is already component-generic — adding a component is one
`COMPONENT_MAP` entry. Only the end-to-end glue is per-component, because each component
has its own matcher.

### Scope boundary — this is a fitness check, not vulnerability triage

Deliberate, and worth stating because Finding 2 sits right on the line. This experiment
answers *"does our identity+version map to the right CVEs, and can that mapping be
trusted?"*. It does **not** answer *"does this CVE actually impact this project?"* —
whether the vulnerable file is compiled in, the config enabled, the code path reachable.
That is **vulnerability triage**, a project-evaluation activity, and its output is a
**VEX** statement (e.g. `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`), produced by the SBOM's *consumer*, not by the
generator or by this research.

The reason Finding 2 is recorded here anyway is that it isn't triage — it's a
**granularity** signal. "Only ARMv7-M MPU ports are affected" tells us the component we
identify (`FreeRTOS-Kernel`) is coarser than the thing the advisory talks about (a
specific port layer). Making detection finer is squarely our job; deciding whether the
project's build reaches that code is not. Rule of thumb for future components: **an
applicability condition is a prompt to sharpen identification, never a licence to build
a reachability analyzer.** See
[../../sbom-generator-architecture.md](../../sbom-generator-architecture.md) rec. 13.

## lwIP (2026-07-29) — the second loop closed, through NVD/CPE this time

Phase-3 pass for [lwIP](../../../components/lwip/README.md), run over the
[phase-2 corpus](../../../components/lwip/corpus/README.md). Deliberately routed through
a **different source** than the FreeRTOS run: `lwip-tcpip/lwip`'s GHSA per-repo feed
returns **0** advisories (lwIP does not self-publish, like Mbed TLS), so the fit source
here is NVD/CPE — exercising the path that was identified as primary but had never been
run end to end.

New reusable script: **`nvd_vuln_lookup.py`** — the CPE sibling of `ghsa_vuln_lookup.py`,
same `load_cache`/`lookup`/`print_lookup` interface so `end_to_end_*.py` can swap sources.
It caches CVE+constraint data in `nvd_cve_cache.json` (`--refresh` to re-fetch) and carries
a `COMPONENT_MAP` from canonical identity to CPE product, including the *negative* entries
(CMSIS: no CPE; FreeRTOS: marked `blocked` because NVD keys it to AWS-distribution versions
the detector never produces).

### Source coverage for lwIP

| source | coordinate | result |
|---|---|---|
| **NVD/CPE** | `cpe:2.3:a:lwip_project:lwip` | ✓ **fit** — real range matching (@1.4.1 → CVE-2014-4883; @2.1.2 → CVE-2020-22284; @2.2.1 → none; **@99.0.0 impossible → none**) |
| **GHSA per-repo** | `lwip-tcpip/lwip` | **0 advisories** — does not self-publish |
| **OSV** | `pkg:github/lwip-tcpip/lwip` | **0**; bare name `lwip` → 10, all `DEBIAN-*`/`UBUNTU-*`/`OESA-*` distro records |

### Result: all eight corpus ground truths resolve correctly

`end_to_end_lwip.py`, snapshot in `end_to_end_lwip_results.json`:

| corpus tree | detection | verdict |
|---|---|---|
| `upstream-1.4.1` | CONFIRMED 1.4.1 | **AFFECTED** — CVE-2014-4883 (range `<=1.4.1`) |
| `mixed-version-synthetic` | MIXED_VERSION {2.0.2, 2.0.3, 2.1.1, 2.1.2} (**coexisting**) | **AFFECTED** — CVE-2020-22284 pins exactly 2.1.2, which really is present |
| `savannah-zip-2.0.2` | CONFIRMED 2.0.2 | NOT_AFFECTED |
| `st-stm32-mw-2.1.3` | CONFIRMED 2.1.3 | NOT_AFFECTED |
| `esp-lwip-2.2.0-esp` | PARTIALLY_MODIFIED 2.2.0 | NOT_AFFECTED *(but see carrier finding below)* |
| `nxp-mcux-2.16.100` | PARTIALLY_MODIFIED 2.2.1 | NOT_AFFECTED |
| `xilinx-lwip220` | PARTIALLY_MODIFIED 2.2.0 | NOT_AFFECTED |
| `negative-control-cjson` | NOT_THIS_COMPONENT | NOT_QUERYABLE — "no lwIP detected", not "no vulns" |

The version-set semantics rule from the FreeRTOS run held without modification: the mixed
tree's set is **coexisting**, so a CVE hitting one member means the vulnerable code really
is present → AFFECTED.

### Finding A — advisories for a vendored component are often filed against the **carrier**

The headline result, and it is not about lwIP's tooling but about how CVEs are indexed.
Six CVEs in NVD mention lwIP in their description; only **three** are bound to the
`lwip_project:lwip` CPE. The other three:

| CVE | CPE product it is filed under | what it actually is |
|---|---|---|
| CVE-2024-7490 | `microchip:advanced_software_framework` | buffer overflow in the **lwIP example DHCP server** bundled in Microchip ASF |
| CVE-2026-45160 | `espressif:esp-idf` | OOB read in `parse_options()` in **ESP-IDF's own** `components/lwip/apps/dhcpserver/dhcpserver.c` |
| CVE-2026-8836 | *(none — no CPE at all)* | stack overflow in **upstream** `src/apps/snmp/snmp_msg.c`, "lwIP up to 2.2.1" |

So a *correct* upstream identity (`lwip_project:lwip` @2.2.0) is not sufficient: it
returns nothing for the two carrier-indexed CVEs, and nothing for the un-CPE'd one. This
is the inverse of the FreeRTOS scheme mismatch — there NVD used the distribution's
*versions*, here it uses the distribution's *product name*.

Consequence for the mapping layer: identity → CPE is **not 1:1**. When detection
establishes that a tree is a known vendor distribution, the query set must include that
vendor's CPE too. `nvd_vuln_lookup.py` carries this as a per-component
`carrier_products` map and prints it with every lookup. Note the limit, stated honestly:
CVE-2026-45160's file lives in **esp-idf**, not even in Espressif's `esp-lwip` fork — no
amount of lwIP-tree fingerprinting reaches it, only recognizing the *carrier* does.

Cheap carrier discriminators exist and are worth mining: `src/core/ipv4/ip4_napt.c`
(1089 lines) is present in Espressif's fork and in **no upstream release tag**, so a
single file's presence identifies the carrier.

### Finding B — a CPE bound to the literal version `-` is unmatchable, and must not read as "not affected"

CVE-2020-22283 (ICMPv6 buffer overflow, "lwIP version git head") is bound to CPE version
`-`, NVD's "no version information" placeholder. No version can ever match it, so a naive
range evaluation silently returns NOT_AFFECTED for *every* version — a false clean bill of
health. `nvd_vuln_lookup.py` classifies it **UNDETERMINED** with the reason attached, and
every corpus row above carries it. Same class of problem as GHSA's non-conforming range
grammars: classify what the source actually said, never coerce it into a boolean.

### Finding C — the CPE dictionary lags releases, but range bindings still work

The CPE dictionary has entries only up to **2.1.2** — nothing for 2.1.3 / 2.2.0 / 2.2.1,
i.e. every release since 2021. Version *queries* still work (range constraints are
evaluated against any version string), so this is not fatal, but it means a CVE filed
against a modern lwIP has no dictionary name to bind to, and CVE-2026-8836 — a real
upstream flaw in "lwIP up to 2.2.1" — indeed has **no CPE at all**.

Its advisory does name the fix commit (`0c957ec0…`, 2026-05-13), which `git tag --contains`
resolves to **no release tag**: the fix is unreleased, so every released version is
affected. That is a *usable* answer obtained from a commit coordinate where the CPE
coordinate had nothing — a concrete argument for the paused tag→commit resolver sub-task.

### Finding D — the nested component's CVEs are reachable only through the nested identity

Phase 1 established that lwIP vendors a reduced copy of **pppd 2.4.5** and of **PolarSSL
0.10.1-bsd**. OSV's bare-name `lwip` query returns `DEBIAN-CVE-2020-8597` — pppd's
`eap.c` `rhostname` overflow, stated as affecting *ppp 2.4.2 through 2.4.8*, which
brackets the 2.4.5 lwIP vendored. lwIP 2.2.1 still ships `src/netif/ppp/eap.c` with 33
`rhostname` references. Whether lwIP's reduced copy is actually vulnerable is **triage,
and explicitly not this repo's job** — but the *mapping* fact is: that CVE is reachable
only if the nested pppd is emitted with its own identity. An SBOM listing lwIP alone
cannot surface it from any source tested.

## Implications for the generator (feeds the metadata-mapping layer)

1. **SBOM identity ≠ vuln-lookup key.** The canonical upstream purl is right for
   attribution and wrong for OSV. A **mapping layer** from canonical identity to
   each vuln source's coordinate system is mandatory — captured as a new
   recommendation in
   [../../sbom-generator-architecture.md](../../sbom-generator-architecture.md).
2. **Target NVD/CPE first; add the GHSA per-repo feed as a per-component source;
   OSV.dev alone is insufficient for embedded C.**
   Confirmed empirically: **NVD/CPE gives version-accurate matching** (impossible
   version → 0), so the primary vuln-lookup coordinate is **CPE 2.3**. The **GHSA
   per-repository feed** is a real, version-ranged secondary for components whose
   maintainers self-publish (FreeRTOS-Kernel — and there its kernel-semver range is
   *better* than NVD's AWS-distribution versioning), discovered from the canonical
   identity's `{owner}/{repo}`. OSV's GIT-range CVE records are a further
   upstream-accurate secondary (via our tag→commit map); OSV package queries and the
   GHSA *global* feed are coarse or empty.
3. **Never emit version-inert results as if precise.** If only bare-name OSV is
   available for a component, the output is a version-independent CVE pile and
   must be labeled as such (or suppressed) — consistent with the per-finding /
   whole-scan provenance recommendation.
4. **The residual work is mapping, not more sources.** NVD's misses are all
   mapping-layer problems — identity→CPE, kernel-semver→AWS-distribution version,
   and missing CPE names for CMSIS sub-components — which is where the generator's
   effort should go, rather than adding ever more advisory feeds.

## Follow-ups queued (not started)

- ~~**NVD/CPE probe**~~ — **DONE 2026-07-22** (above): CPE version-range matching
  gives the discrimination OSV lacks; NVD/CPE is the fit source.
- **FreeRTOS version-scheme mapping**: work out how the kernel semver we detect
  (10.4.3) maps onto the AWS-FreeRTOS / FreeRTOS+TCP CPE versioning that the NVD
  CVEs actually use — the concrete instance of the component-granularity question
  for FreeRTOS. *Note (2026-07-23): the GHSA per-repo feed sidesteps this for the
  kernel specifically — its CVE-2024-28115 range is already in kernel semver
  (`<=10.6.1`) — so kernel-semver → GHSA-repo may be the shorter path than
  kernel-semver → AWS-distribution CPE. Weigh both.*
- ~~**Per-component vuln-source map incl. the GHSA repo feed**~~ — **DONE 2026-07-28**
  as `COMPONENT_MAP` in `ghsa_vuln_lookup.py` (see "Closing the loop" above): per
  component, its `{owner}/{repo}`, whether that repo self-publishes (FreeRTOS-Kernel yes,
  mbedTLS no), the version scheme, and the coverage note naming the right alternative
  source. Covers the four components researched so far; extend it as components are added.
- **Applicability predicates beyond version** (new, from Finding 2 above): CVE-2024-28115
  applies only to ARMv7-M/ARMv8-M **MPU ports** — a condition stated in prose only, in
  every source tested. Pairs with the FreeRTOS port-layer consolidation step; until then
  version-only verdicts are knowingly over-broad.
- **Tag→commit resolver over OSV GIT ranges**: prototype resolving a detected
  version to its release commit and testing membership in OSV CVE GIT ranges,
  using the tags the reference DBs already mine.
- **Remaining advisory sources**: the untested sources in
  [../../advisory-source-roadmap.md](../../advisory-source-roadmap.md) (distro
  trackers, vendor/upstream advisories, CVE.org/cvelistV5, EUVD, CISA KEV).
- **CVE-dedup cost of the OSSKB attribution gap** (the original framing): quantify
  how many *wrong* CVEs OSSKB's arbitrary-containing-repo attribution would feed
  in vs. our curated purl — now measurable with this harness.
