"""Phase-3 loop-closing check for lwIP: vendored tree -> detection -> NVD/CPE -> verdict.

The second end-to-end run in this repo, and deliberately over a *different* source than
the first: FreeRTOS closed the loop through GHSA's per-repository feed
(end_to_end_freertos.py), lwIP closes it through **NVD/CPE**, because
`lwip-tcpip/lwip`'s GHSA repo feed returns 0 advisories and NVD is where lwIP's CVEs
actually live. Everything but the lookup module is the same shape.

What this proves: the detector's output (canonical identity + resolved version set), fed
into a real advisory source, produces the right verdict for every corpus ground truth —
including the negatives. It is a *fitness check*, not a vuln scanner: it stops at "which
CVEs map to this identity+version". Whether a CVE actually impacts a build is triage and
belongs to the SBOM consumer's VEX process (general/sbom-generator-architecture.md
rec. 13).

Version-set semantics (architecture rec. 8): a resolved set of releases means one of two
different things, and the verdict differs.
  * candidates  — "it is one of these" (PARTIALLY_MODIFIED pins a base, INCONSISTENT).
                  A CVE hitting only some members is POSSIBLY_AFFECTED: the honest
                  answer is "tighten detection", not yes or no.
  * coexisting  — "all of these are present at once" (MIXED_VERSION: a tree really
                  containing files from several releases). A CVE hitting any member
                  means the vulnerable code is genuinely in the tree: AFFECTED.

Usage: python end_to_end_lwip.py [tree ...] [--json OUT.json]
"""
import json
import sys
from pathlib import Path

COMPONENT = "pkg:github/lwip-tcpip/lwip"
COMPONENT_DIR = "lwip"
MATCHER_SUBDIR = "experiments/version-fingerprint"
COEXISTING = {"MIXED_VERSION"}
# Statuses that mean "don't ask the advisory source at all".
NO_DETECTION = {"NOT_THIS_COMPONENT", "INCOMPLETE"}

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "components" / COMPONENT_DIR / MATCHER_SUBDIR))

from match_target import scan_tree                                    # noqa: E402
from nvd_vuln_lookup import load_cache, lookup, print_lookup          # noqa: E402

CORPUS = REPO / "components" / COMPONENT_DIR / "corpus"


def assess(tree: Path, cache: dict) -> list:
    out = []
    for group in scan_tree(tree):
        status, versions = group["status"], group["versions"]
        semantics = "coexisting" if status in COEXISTING else "candidates"

        if status in NO_DETECTION or not versions:
            out.append({"tree": tree.name, "status": status, "versions": versions,
                        "semantics": semantics, "verdict": "NOT_QUERYABLE",
                        "detail": group["detail"], "per_version": {},
                        "note": ("no lwIP detected — nothing to look up"
                                 if status == "NOT_THIS_COMPONENT" else
                                 "no version resolved: a detection gap, not a clean "
                                 "bill of health")})
            continue

        per_version = {v: lookup(COMPONENT, v, cache) for v in versions}
        affected = {v: [f["cve_id"] for f in r["findings"] if f["verdict"] == "AFFECTED"]
                    for v, r in per_version.items()}
        undetermined = sorted({f["cve_id"] for r in per_version.values()
                               for f in r["findings"] if f["verdict"] == "UNDETERMINED"})
        hit = {v for v, ids in affected.items() if ids}

        if not hit:
            verdict = "NOT_AFFECTED"
        elif semantics == "coexisting" or len(hit) == len(versions):
            verdict = "AFFECTED"
        else:
            verdict = "POSSIBLY_AFFECTED"

        out.append({"tree": tree.name, "status": status, "versions": versions,
                    "semantics": semantics, "verdict": verdict,
                    "cves": sorted({c for ids in affected.values() for c in ids}),
                    "undetermined": undetermined,
                    "detail": group["detail"],
                    "per_version": {v: affected[v] for v in versions}})
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
            print(f"  detection : {res['status']} -> {res['versions'] or '(none)'} "
                  f"({res['semantics']})")
            print(f"  verdict   : {res['verdict']}"
                  + (f"  {res['cves']}" if res.get("cves") else ""))
            if res.get("undetermined"):
                print(f"  undetermined (source can't be version-matched): "
                      f"{res['undetermined']}")
            if res.get("note"):
                print(f"  note      : {res['note']}")

    print(f"\n\n{'=' * 74}\nSUMMARY\n{'=' * 74}")
    for r in results:
        print(f"  {r['tree']:26} {r['status']:20} {str(r['versions']):34} "
              f"{r['verdict']}")

    if json_out:
        json_out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {json_out}")


if __name__ == "__main__":
    main()
