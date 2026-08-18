"""Phase-3 loop-closing check for zlib: vendored tree -> detection -> NVD/CPE -> verdict.

The third end-to-end run in this repo (FreeRTOS closed through GHSA's per-repo feed, lwIP
through NVD/CPE, zlib through NVD/CPE again). Same shape as `end_to_end_lwip.py`, plus one
thing neither earlier run needed:

**Sub-component applicability refinement.** zlib is the first component here where the
*same failure repeats across two independent CVEs*: a flaw in a `contrib/` sub-component is
bound, machine-readably, to the **core zlib CPE**, while the CVE record's own prose says
the core is not affected.

  * `CVE-2023-45853` — MiniZip integer overflow. CPE: `zlib:zlib < 1.3.1`.
    Prose: *"NOTE: MiniZip is not a supported part of the zlib product."*
  * `CVE-2026-22184` — `contrib/untgz` global buffer overflow. CPE: `zlib:zlib <= 1.3.1.2`.
    Prose: *"The vulnerability is limited to the standalone demonstration utility and does
    not affect the core zlib compression library."*

A version-only verdict therefore reports **every** zlib tree below those bounds as
AFFECTED, including the overwhelmingly common case of a core-only vendoring that never
took `contrib/` at all. This is the same shape as FreeRTOS's ARMv7-M-MPU-only
CVE-2024-28115 (`end_to_end_freertos.py`), and it gets the same treatment, with the same
three safety rules from architecture rec. 12:

  1. The refinement **only ever narrows** — it never turns NOT_AFFECTED into AFFECTED.
  2. **Absent evidence suspends, never clears.** If the tree cannot be shown to be a
     complete distribution, sub-component absence is UNKNOWN, not "absent".
  3. The applicability condition is **curated advisory metadata carrying its source
     quote**, never inferred from the CVE text at runtime.

Rule 2 matters more here than it did for FreeRTOS, and the corpus shows why: most trees in
it are *extracts* (only the tracked files were fetched), so "no `unzip.c` found" says
nothing about the real carrier — Chromium's `README.chromium` states it ships minizip, yet
the extract contains none of it. `subcomponent_evidence()` therefore reports ABSENT only
for trees that look like a complete distribution, and UNKNOWN otherwise.

This is identification work — "is this sub-component in the tree?" — not impact analysis.
Whether a present `unzip.c` is ever compiled or reachable is triage, and belongs to the
SBOM consumer's VEX process (rec. 13).

Usage: python end_to_end_zlib.py [tree ...] [--json OUT.json]
"""
import json
import sys
from pathlib import Path

COMPONENT = "pkg:github/madler/zlib"
COMPONENT_DIR = "zlib"
MATCHER_SUBDIR = "experiments/version-fingerprint"
COEXISTING = {"MIXED_VERSION"}
NO_DETECTION = {"NOT_THIS_COMPONENT", "INCOMPLETE"}

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "components" / COMPONENT_DIR / MATCHER_SUBDIR))

from match_target import scan_tree                                    # noqa: E402
from nvd_vuln_lookup import load_cache, lookup                        # noqa: E402

CORPUS = REPO / "components" / COMPONENT_DIR / "corpus"

# Curated applicability conditions, each with the quote from the advisory that states it.
APPLICABILITY = {
    "CVE-2023-45853": {
        "requires": "minizip",
        "quote": "MiniZip is not a supported part of the zlib product.",
    },
    "CVE-2026-22184": {
        "requires": "untgz",
        "quote": "The vulnerability is limited to the standalone demonstration utility "
                 "and does not affect the core zlib compression library.",
    },
}

# Filenames that identify each contrib sub-component. Presence of any is enough.
SUBCOMPONENT_MARKERS = {
    "minizip": {"unzip.c", "zip.c", "ioapi.c", "mztools.c", "unzip.h", "zip.h"},
    "untgz": {"untgz.c"},
}

# A tree can only support an "absent" claim if it looks like a whole distribution rather
# than an extract of tracked files. Core sources plus any build entry point.
COMPLETENESS_CORE = {"inflate.c", "inftrees.c", "inffast.c", "deflate.c", "trees.c",
                     "adler32.c", "crc32.c", "zutil.c", "compress.c", "uncompr.c"}
COMPLETENESS_BUILD = {"Makefile", "Makefile.in", "CMakeLists.txt", "configure",
                      "BUILD.bazel"}


def subcomponent_evidence(tree: Path) -> dict:
    """PRESENT / ABSENT / UNKNOWN per contrib sub-component, with the reason."""
    names = {p.name for p in tree.rglob("*") if p.is_file()}
    complete = COMPLETENESS_CORE <= names and bool(names & COMPLETENESS_BUILD)

    out = {"tree_looks_complete": complete, "subcomponents": {}}
    for sub, markers in SUBCOMPONENT_MARKERS.items():
        hits = sorted(markers & names)
        if hits:
            out["subcomponents"][sub] = {
                "state": "PRESENT", "why": f"found {hits}"}
        elif complete:
            out["subcomponents"][sub] = {
                "state": "ABSENT",
                "why": "tree contains the full core source set and a build entry point "
                       "but none of " + str(sorted(markers))}
        else:
            out["subcomponents"][sub] = {
                "state": "UNKNOWN",
                "why": "no marker found, but this tree is not a complete distribution "
                       "(it may be an extract) — absence cannot be concluded"}
    return out


def refine(verdict: str, cves: list, evidence: dict) -> dict:
    """Narrow a version-only verdict using sub-component composition evidence."""
    if verdict not in ("AFFECTED", "POSSIBLY_AFFECTED"):
        return {"refined_verdict": verdict, "refinement": "not applicable"}

    conditioned = [c for c in cves if c in APPLICABILITY]
    unconditioned = [c for c in cves if c not in APPLICABILITY]
    if not conditioned:
        return {"refined_verdict": verdict,
                "refinement": "no curated applicability condition for the matched "
                              "advisories — version evidence stands alone"}

    ruled_out, suspended, still_in = [], [], []
    for cve in conditioned:
        sub = APPLICABILITY[cve]["requires"]
        state = evidence["subcomponents"][sub]["state"]
        (ruled_out if state == "ABSENT" else
         still_in if state == "PRESENT" else suspended).append((cve, sub))

    notes = []
    if ruled_out:
        notes.append("; ".join(
            f"{cve} ruled out — requires contrib/{sub}, "
            f"{evidence['subcomponents'][sub]['why']} "
            f"(advisory: \"{APPLICABILITY[cve]['quote']}\")" for cve, sub in ruled_out))
    if still_in:
        notes.append("; ".join(f"{cve} stands — contrib/{sub} is present in the tree"
                               for cve, sub in still_in))
    if suspended:
        notes.append("; ".join(
            f"{cve} undecided — requires contrib/{sub}, "
            f"{evidence['subcomponents'][sub]['why']}" for cve, sub in suspended))

    remaining = unconditioned + [c for c, _ in still_in]
    if remaining:
        refined = verdict
    elif suspended:
        # Rule 2: absent evidence suspends, never clears.
        refined = "POSSIBLY_AFFECTED"
    else:
        refined = "NOT_AFFECTED"

    return {"refined_verdict": refined, "refinement": " | ".join(notes),
            "remaining_cves": sorted(remaining),
            "ruled_out": sorted(c for c, _ in ruled_out),
            "suspended": sorted(c for c, _ in suspended)}


def assess(tree: Path, cache: dict) -> list:
    out = []
    for group in scan_tree(tree):
        status, versions = group["status"], group["versions"]
        semantics = "coexisting" if status in COEXISTING else "candidates"
        evidence = subcomponent_evidence(tree)

        if status in NO_DETECTION or not versions:
            out.append({"tree": tree.name, "status": status, "versions": versions,
                        "semantics": semantics, "verdict": "NOT_QUERYABLE",
                        "refined_verdict": "NOT_QUERYABLE", "refinement": "not applicable",
                        "detail": group["detail"], "per_version": {},
                        "evidence": evidence,
                        "note": ("no zlib detected — nothing to look up"
                                 if status == "NOT_THIS_COMPONENT" else
                                 "no version resolved: a detection gap, not a clean "
                                 "bill of health")})
            continue

        per_version = {v: lookup(COMPONENT, v, cache) for v in versions}
        affected = {v: [f["cve_id"] for f in r["findings"] if f["verdict"] == "AFFECTED"]
                    for v, r in per_version.items()}
        context_only = sorted({f["cve_id"] for r in per_version.values()
                               for f in r["findings"] if f["verdict"] == "CONTEXT_ONLY"})
        undetermined = sorted({f["cve_id"] for r in per_version.values()
                               for f in r["findings"] if f["verdict"] == "UNDETERMINED"})
        hit = {v for v, ids in affected.items() if ids}

        if not hit:
            verdict = "NOT_AFFECTED"
        elif semantics == "coexisting" or len(hit) == len(versions):
            verdict = "AFFECTED"
        else:
            verdict = "POSSIBLY_AFFECTED"

        cves = sorted({c for ids in affected.values() for c in ids})
        out.append({"tree": tree.name, "status": status, "versions": versions,
                    "semantics": semantics, "verdict": verdict, "cves": cves,
                    "context_only": context_only, "undetermined": undetermined,
                    "detail": group["detail"], "evidence": evidence,
                    "per_version": {v: affected[v] for v in versions},
                    **refine(verdict, cves, evidence)})
    return out


def main() -> None:
    argv = sys.argv[1:]
    json_out = None
    if "--json" in argv:
        i = argv.index("--json")
        json_out = Path(argv[i + 1])
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    trees = [Path(a) for a in args] or sorted(p for p in CORPUS.iterdir() if p.is_dir())

    cache = load_cache()
    results = []
    for tree in trees:
        for res in assess(tree, cache):
            results.append(res)
            print(f"\n{'=' * 74}\n{res['tree']}\n{'=' * 74}")
            print(f"  detection      : {res['status']} -> {res['versions'] or '(none)'} "
                  f"({res['semantics']})")
            subs = res["evidence"]["subcomponents"]
            print(f"  composition    : complete-distribution="
                  f"{res['evidence']['tree_looks_complete']}, "
                  + ", ".join(f"{k}={v['state']}" for k, v in sorted(subs.items())))
            print(f"  version-only   : {res['verdict']}"
                  + (f"  {res['cves']}" if res.get("cves") else ""))
            print(f"  refined        : {res['refined_verdict']}"
                  + (f"  {res['remaining_cves']}" if res.get("remaining_cves") else ""))
            if res.get("ruled_out"):
                print(f"      ruled out on composition evidence: {res['ruled_out']}")
            if res.get("refinement") and res["refinement"] != "not applicable":
                print(f"      {res['refinement']}")
            if res.get("context_only"):
                print(f"  context-only (another product's flaw, zlib is a precondition): "
                      f"{res['context_only']}")
            if res.get("undetermined"):
                print(f"  undetermined   : {res['undetermined']}")
            if res.get("note"):
                print(f"  note           : {res['note']}")

    print(f"\n\n{'=' * 74}\nSUMMARY\n{'=' * 74}")
    print(f"  {'tree':32} {'detection':20} {'version-only':18} refined")
    for r in results:
        print(f"  {r['tree']:32} {r['status']:20} {r['verdict']:18} "
              f"{r['refined_verdict']}")

    if json_out:
        json_out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {json_out}")


if __name__ == "__main__":
    main()
