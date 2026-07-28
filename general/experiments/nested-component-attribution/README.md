# Nested components: what detection actually says about a component inside a component

**Question**: [general/README.md](../../README.md#attribution-vendored-integrations-are-often-multiple-stacked-components)
has asserted since the FreeRTOS pass that a vendored integration is often *several*
stacked components and must be attributed as such. That rule had never been tested
against a real nested case. The lwIP pass produced one, so this experiment asks the two
concrete failure directions:

- does existing detection **over-report** — claim a component that is not independently
  present, with a wrong purl/version/license?
- does it **under-report** — miss legacy third-party code that carries its own CVE
  history?

**Answer: both, in different tiers — and the over-report is worse than expected.** A
309-file lwIP 2.2.1 tree containing *zero* Mbed TLS is reported by this repo's own curated
KB as **"CONSISTENT: mbed-tls 2.28.8/2.28.9/2.28.10, Apache-2.0"**, on the strength of one
file out of 309. The mechanism is not a fingerprint failure; it is a **verdict-logic**
failure plus a **constant-table** artifact, both of which generalize well beyond this case.

## The case

lwIP vendors two other projects inside itself (phase-1 finding,
[components/lwip](../../../components/lwip/README.md#2-component-granularity)), documented
in-tree by upstream:

- `src/netif/ppp/polarssl/` — `md5.c`, `sha1.c`, `des.c`, `arc4.c`, `md4.c`, *"fetched from
  the latest BSD release of the PolarSSL project (**PolarSSL 0.10.1-bsd**) … cleaned to
  contain only the necessary struct fields and functions needed for lwIP"*.
- `src/netif/ppp/` — a heavily reduced fork of **pppd 2.4.5**.

PolarSSL 0.10.1 (2009) is the direct ancestor of Mbed TLS, which this repo has already
researched and mined into the curated KB — so the nested copy sits exactly on the boundary
between "known component" and "not present".

Ground truth for the nested subtree: **PolarSSL 0.10.1-bsd lineage, BSD-3-Clause**
(headers read `Copyright (C) 2009 Paul Bakker`, `Based on XySSL: Copyright (C) 2006-2008
Christophe Devine`), reduced by lwIP, shipped as part of lwIP.

## Test A — the bespoke per-component matcher: silent miss

`components/mbedtls/experiments/version-fingerprint/match_target.py` against the nested
directory:

```
No tracked files (['version.h', 'bignum.c', 'ecp.c', 'aes.c', 'ecdsa.c']) found
```

Blind by construction: the POC matcher tracks five files chosen for version
discrimination, none of which is a crypto primitive. This is the documented
[POC-scope caveat](../../README.md#maturity-caveat-the-fingerprints-here-are-poc-scoped-not-consolidated)
behaving as designed — worth recording because it means **the narrow matchers cannot
produce this class of false positive at all**, and the false positive below is a property
of the broad KB, not of fingerprinting as such.

## Test B — the curated KB export: confident, wrong attribution

`general/experiments/minr-self-mining/validate_export.py` against the **whole lwIP 2.2.1
`src/` tree** (309 files, containing no Mbed TLS whatsoever):

```
=== lwip-full-2.2.1
  des.c    snippet  versions=2.28.10,2.28.8,2.28.9 purl=pkg:github/mbed-tls/mbedtls
           lic=Apache-2.0 (65% of 287 snippets -> library/des.c)
  VERDICT: CONSISTENT - all files coexist in release(s): 2.28.10, 2.28.8, 2.28.9
```

(308 `NO MATCH` lines elided.) Every element of that output is wrong:

| | reported | actual |
|---|---|---|
| component | Mbed TLS | lwIP (which merely contains reduced PolarSSL) |
| version | 2.28.8 – 2.28.10 (2024) | PolarSSL 0.10.1 lineage (2009) |
| license | **Apache-2.0** | **BSD-3-Clause** |
| confidence | **CONSISTENT** | one matched file in 309 |

The license error is the most consequential: Apache-2.0 vs BSD-3-Clause is exactly the
kind of attribution mistake an SBOM exists to prevent, and it is asserted here with the
KB's highest-confidence verdict. Note this is *not* the OSSKB arbitrary-containing-repo
problem the curated KB was built to fix — attribution-by-construction worked perfectly:
the KB faithfully reported the metadata of the release its evidence pointed at. The
evidence just should never have been believed.

## Finding 1 — the tree verdict has no minimum-evidence rule

`validate_export.py` computes the tree verdict by intersecting the release sets of the
files that **matched**, and treats a `NO MATCH` file as *no evidence* rather than as
*counter-evidence*. With exactly one matched file, the intersection is that file's own
release set — so a single weak match yields `CONSISTENT`, the verdict reserved for
coherent verbatim trees.

The validator was never wrong on its own corpus because every tree there was a real
vendored copy where most files matched. A tree where 308 of 309 files say "not this
component" is outside the shape it was written for.

What a fixed rule needs, at minimum: a **match ratio** (matched files / candidate files
of a plausible type), a **floor** below which the verdict is `NO COMPONENT DETECTED`
rather than a version statement, and per-finding confidence that degrades with the ratio
instead of being binary. A single-file match in a large tree is a *snippet* finding
("this file resembles X"), never a *component* finding ("this tree is X"). That maps onto
the evidence-producer/resolver split already recommended in
[sbom-generator-architecture.md](../../sbom-generator-architecture.md) rec. 3–4: the
producer emitted a defensible per-file signal; the resolver over-promoted it.

## Finding 2 — the match is made of constant tables, not code

Why did `des.c` match at all, when lwIP's copy is 15 years diverged and deliberately
reduced? `measure_nesting.py` decomposes the similarity (shared winnowing implementation,
Jaccard on fingerprints):

| lwIP file | vs mbedtls-1.3.22 | vs mbedtls-2.28.8 | **constants only** | **code only (hex stripped)** | file that is hex |
|---|---|---|---|---|---|
| `md5.c` | 0.291 | 0.014 | 0.468 | 0.018 | 12% |
| `sha1.c` | 0.309 | 0.017 | 0.231 | 0.014 | 2% |
| **`des.c`** | 0.460 | **0.322** | **0.794** | **0.071** | **53%** |
| `arc4.c` | 0.114 | 0.037 | 0.000 | 0.043 | 1% |
| `md4.c` | 0.273 | 0.028 | 0.150 | 0.028 | 2% |

`des.c` is **53% hex constants**, and those constants are 0.794 similar to Mbed TLS's
while the surrounding code is 0.071 — i.e. essentially unrelated code around identical
tables. That is not a coincidence of lineage: DES's S-boxes and permutation tables are
**fixed by FIPS 46**. Every DES implementation on earth contains them. The tables identify
*the algorithm*, never *the project*, and never a version.

Direct consequence for the technique roadmap: **constant/data-table fingerprinting**
([fingerprint-detection-roadmap.md](../../fingerprint-detection-roadmap.md)) is currently
logged as an uncovered TODO on the assumption that data tables are a strong signal. They
are — for *component family*. This experiment is the counter-example that must be carried
with it: standard algorithm tables (crypto S-boxes, CRC tables, compression Huffman
tables, Unicode/locale tables) are shared across unrelated projects and must be excluded
or down-weighted; only *distinctive* constants carry provenance. Note also that the
generic winnowing tier already has this problem — it is not specific to a future
table-aware tier.

## Finding 3 — correct attribution was not achievable here anyway

Even with the over-report fixed, the KB could not have answered *correctly*, because the
right answer is not in it:

- The KB's oldest Mbed TLS **source-tier** release is **2.28.8**; its symbol tier reaches
  back to 2.16.0. The nested copy is **0.10.1**, from 2009.
- Mbed TLS's git history does not go back that far either — the earliest release tag in
  `Mbed-TLS/mbedtls` is `mbedtls-1.3.10`. **PolarSSL 0.10.1 was distributed as a tarball
  and exists in no git tag**, so no amount of widening tag coverage reaches it.

This is the [rec. 14](../../sbom-generator-architecture.md) point (mine artifacts, not
just tags) in its sharpest form, and it bounds what a tag-mined KB can ever attribute:
pre-git-era code inside a modern component is *structurally* invisible to it. The honest
output for such a subtree is "known-OSS content, origin not in coverage", which is a
category the current verdict vocabulary does not have.

## Finding 4 — the under-report has a real vulnerability consequence

The nested pppd 2.4.5 is not detected by anything here, and
[the advisory pass](../advisory-fitness/README.md#lwip-2026-07-29--the-second-loop-closed-through-nvdcpe-this-time)
already showed why that matters: `DEBIAN-CVE-2020-8597` (pppd `eap.c` `rhostname`
overflow) states a range of *ppp 2.4.2 through 2.4.8*, which brackets the vendored 2.4.5,
and lwIP 2.2.1 still ships that `eap.c` with 33 `rhostname` references. Whether the
reduced copy is exploitable is **triage, explicitly not this repo's job** — but the
mapping fact stands: an SBOM naming only lwIP cannot surface that CVE from any source
tested, because the advisory is keyed to pppd's identity.

## What this changes

1. **The attribution rule needs an evidence threshold, not just a taxonomy.** "Emit
   stacked components separately" is right but insufficient; the failure here was
   promoting one file's snippet match to a whole-tree component claim.
2. **A `contains` relationship is a distinct output from a `detected` one.** lwIP's
   PolarSSL subtree should surface as *lwIP contains reduced PolarSSL 0.10.1
   (BSD-3-Clause)* — a curated fact about a known component's composition, cheap to record
   once per component and impossible to derive reliably from content alone here.
3. **Curated-KB coverage should include the nested origins of components already
   covered**, or explicitly mark them out of coverage. Mining PolarSSL 0.10.1 requires the
   2009 tarball, not the git repo.
4. **Negative evidence must count.** 308 files saying "not this component" is
   information; the current verdict ignores it entirely.

## Files

- [`measure_nesting.py`](measure_nesting.py) — reproduces the similarity decomposition
  (whole-file vs constants vs code) from an lwIP clone plus 10 fetched Mbed TLS files.
  `python measure_nesting.py --lwip-clone <dir>`.
- The KB run (Test B) uses `../minr-self-mining/validate_export.py` with
  `results/export_with_symbols.json.gz`, which is gitignored/regenerable — reproduce it by
  rebuilding the export per that experiment's README, then running it against any lwIP
  2.2.1 `src/` tree.
