"""End-to-end spike: vendored source tree -> detected version -> applicable CVE.

The first full SBOM-to-vuln result in this repo. It chains two pieces that already
existed but had never been connected:

  components/freertos/experiments/version-fingerprint/match_target.py  (detection)
      -> canonical identity + version(s)
  ghsa_vuln_lookup.py                                                  (advisory)
      -> CVE verdict from GHSA's per-repository advisory feed

Run against the FreeRTOS corpus by default (the three known-ground-truth trees), or
point it at any directory.

The interesting part is not the plumbing but what the *shape* of the detector's output
does to the verdict. Detection emits a **set** of release tags, and that set means two
different things:

  - "candidates" — the tree is one of these releases, we can't narrow further
    (CONFIRMED with several tags sharing identical content, PARTIALLY_MODIFIED).
    If only some candidates are affected, the honest verdict is POSSIBLY_AFFECTED:
    the *detection* must be tightened before the vuln answer is decidable.
  - "coexisting" — files from several releases are genuinely present at once
    (MIXED). If any of them is affected, the tree is affected; there is nothing to
    narrow, the vulnerable file is really in the tree.

Conflating the two would silently turn "we don't know which release" into a hard
yes/no, so the aggregation below keeps them apart.

Usage:
  python end_to_end_freertos.py [tree-or-corpus-dir ...] [--json OUT.json]
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "components" / "freertos" / "experiments" / "version-fingerprint"))

from match_target import scan_tree  # noqa: E402

from ghsa_vuln_lookup import load_cache, lookup  # noqa: E402

COMPONENT = "pkg:github/freertos/freertos-kernel"
CORPUS = REPO / "components" / "freertos" / "corpus"
# Which detector statuses mean "several releases are simultaneously present" rather than
# "we narrowed the release down to this many candidates".
COEXISTING = {"MIXED"}


def assess(tree: Path, cache: dict) -> list:
    out = []
    for group in scan_tree(tree):
        semantics = "coexisting" if group["status"] in COEXISTING else "candidates"
        entry = {"directory": str(group["directory"]), "status": group["status"],
                 "versions": group["versions"], "version_set_semantics": semantics,
                 "lookups": []}
        if not group["versions"]:
            entry["tree_verdict"] = "NOT_QUERYABLE"
            entry["reason"] = ("detection did not resolve a version — nothing to look up "
                               "(this is a detection gap, not a clean bill of health)")
            out.append(entry)
            continue

        verdicts = []
        for version in group["versions"]:
            res = lookup(COMPONENT, version, cache)
            entry["lookups"].append(res)
            if res["coverage"] != "COVERED":
                verdicts.append("UNDETERMINED")
                continue
            vs = {f["verdict"] for f in res["findings"]}
            verdicts.append("AFFECTED" if "AFFECTED" in vs
                            else "UNDETERMINED" if "UNDETERMINED" in vs else "NOT_AFFECTED")

        if "AFFECTED" in verdicts:
            if semantics == "coexisting" or all(v == "AFFECTED" for v in verdicts):
                entry["tree_verdict"] = "AFFECTED"
            else:
                entry["tree_verdict"] = "POSSIBLY_AFFECTED"
                entry["reason"] = ("only some of the candidate releases are affected — "
                                   "narrow the detection to decide")
        elif "UNDETERMINED" in verdicts:
            entry["tree_verdict"] = "UNDETERMINED"
        else:
            entry["tree_verdict"] = "NOT_AFFECTED"
        out.append(entry)
    return out


def print_entry(entry: dict) -> None:
    print(f"\n{'=' * 74}")
    print(f"{entry['directory']}")
    print(f"{'=' * 74}")
    print(f"  detection: {entry['status']} -> {entry['versions'] or '(no version resolved)'}"
          f"  [{entry['version_set_semantics']}]")
    for res in entry["lookups"]:
        print()
        from ghsa_vuln_lookup import print_lookup
        print_lookup(res, indent="    ")
    print(f"\n  TREE VERDICT: {entry['tree_verdict']}")
    if entry.get("reason"):
        print(f"    {entry['reason']}")


def main() -> None:
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = Path(args[i + 1])
        args = args[:i] + args[i + 2:]

    if args:
        trees = [Path(a) for a in args]
    else:
        trees = sorted(p for p in CORPUS.iterdir() if p.is_dir())

    cache = load_cache()
    entries = []
    for tree in trees:
        found = assess(tree, cache)
        if not found:
            print(f"\n{tree}: no FreeRTOS-Kernel core files found")
            continue
        for entry in found:
            print_entry(entry)
            entries.append(entry)

    if out_json:
        out_json.write_text(json.dumps(
            {"component": COMPONENT, "advisory_source": "GHSA per-repository feed",
             "advisory_cache_generated": cache["generated"], "trees": entries},
            indent=2) + "\n", encoding="utf-8")
        print(f"\nresults -> {out_json}")


if __name__ == "__main__":
    main()
