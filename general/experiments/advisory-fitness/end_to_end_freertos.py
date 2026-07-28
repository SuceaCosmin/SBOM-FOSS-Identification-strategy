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

**Applicability refinement (added 2026-07-28)**: a version-only verdict over-claims,
because CVE-2024-28115 applies only to ARMv7-M MPU ports and ARMv8-M ports built with
MPU support — a condition stated in the advisory's prose and in no machine-readable
field. The port-layer detector
(components/freertos/experiments/port-layer) supplies exactly that missing fact, so this
script now reports **both** verdicts: the version-only one, and the one refined by port
evidence. The refinement only ever *narrows* — it never turns a NOT_AFFECTED into an
AFFECTED.

Note the scope line (general/sbom-generator-architecture.md rec. 12–13): the applicability
condition below is **curated advisory metadata** (someone read the advisory text and
recorded "requires MPU"), combined with **composition evidence** detected from the tree
(which port, what `configENABLE_MPU` says). That is identification work. It is *not*
reachability analysis, and the tool stops short of deciding anything the evidence doesn't
state — an unknown MPU status stays UNDETERMINED rather than resolving either way.

Usage:
  python end_to_end_freertos.py [tree-or-corpus-dir ...] [--json OUT.json]
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "components" / "freertos" / "experiments" / "version-fingerprint"))
sys.path.insert(0, str(REPO / "components" / "freertos" / "experiments" / "port-layer"))

from match_target import scan_tree  # noqa: E402
from match_port import scan_ports  # noqa: E402

from ghsa_vuln_lookup import load_cache, lookup  # noqa: E402

COMPONENT = "pkg:github/freertos/freertos-kernel"
CORPUS = REPO / "components" / "freertos" / "corpus"
# Which detector statuses mean "several releases are simultaneously present" rather than
# "we narrowed the release down to this many candidates".
COEXISTING = {"MIXED"}

# Curated applicability conditions: what the advisory's *prose* says about when it
# applies, transcribed into something checkable. No source publishes this
# machine-readably (see the advisory-fitness README, Finding 2), so it is curated
# per-advisory with the quote it came from.
APPLICABILITY = {
    "CVE-2024-28115": {
        "requires": "mpu",
        "quote": "ARMv7-M MPU ports and ARMv8-M ports with MPU support enabled",
    },
}


def port_evidence(tree: Path) -> dict:
    """Summarize the tree's port layer into the one fact advisory applicability needs."""
    ports = scan_ports(tree)
    if not ports:
        return {"ports": [], "mpu": "UNKNOWN",
                "why": "no port-layer files found in this tree — the port cannot be "
                       "determined, so MPU-scoped conditions stay undecided"}
    summary = [{"directory": str(p["directory"]), "status": p["status"],
                "port": p.get("port"), "versions": p.get("versions", []),
                "mpu_status": p["mpu_status"],
                "config_evidence": p["mpu_config_evidence"]} for p in ports]
    states = {p["mpu_status"]["mpu"] for p in ports}
    # Any MPU-enabled port in the tree means the condition can be met somewhere.
    if "ENABLED" in states:
        mpu, why = "ENABLED", next(p["mpu_status"]["why"] for p in ports
                                   if p["mpu_status"]["mpu"] == "ENABLED")
    elif "UNKNOWN" in states:
        mpu, why = "UNKNOWN", next(p["mpu_status"]["why"] for p in ports
                                   if p["mpu_status"]["mpu"] == "UNKNOWN")
    elif states == {"DISABLED"}:
        mpu, why = "DISABLED", "every port found is MPU-capable but built with the MPU off"
    else:
        mpu, why = "NOT_SUPPORTED", "; ".join(sorted({p["mpu_status"]["why"] for p in ports}))
    return {"ports": summary, "mpu": mpu, "why": why}


def refine(verdict: str, findings: list, ports: dict) -> dict:
    """Narrow a version-only verdict using the tree's port/build evidence.

    Only ever narrows: AFFECTED may become NOT_AFFECTED (condition provably unmet) or
    POSSIBLY_AFFECTED (condition undecidable). Nothing else is touched.
    """
    if verdict not in ("AFFECTED", "POSSIBLY_AFFECTED"):
        return {"refined_verdict": verdict, "refinement": "not applicable"}

    conditioned = [f for f in findings
                   if f["verdict"] == "AFFECTED" and f.get("cve_id") in APPLICABILITY]
    if not conditioned:
        return {"refined_verdict": verdict,
                "refinement": "no curated applicability condition for the matched advisory "
                              "— version evidence stands alone"}

    cves = ", ".join(sorted({f["cve_id"] for f in conditioned}))
    quote = APPLICABILITY[conditioned[0]["cve_id"]]["quote"]
    if ports["mpu"] in ("NOT_SUPPORTED", "DISABLED"):
        return {"refined_verdict": "NOT_AFFECTED",
                "refinement": f"{cves} applies only to \"{quote}\"; this tree's port "
                              f"evidence says MPU {ports['mpu']} ({ports['why']})"}
    if ports["mpu"] == "ENABLED":
        return {"refined_verdict": "AFFECTED",
                "refinement": f"{cves} applies to \"{quote}\" and this tree's port "
                              f"evidence confirms it: {ports['why']}"}
    return {"refined_verdict": "POSSIBLY_AFFECTED",
            "refinement": f"{cves} applies only to \"{quote}\", and the port evidence is "
                          f"inconclusive ({ports['why']}) — undecidable from this tree"}


def assess(tree: Path, cache: dict) -> list:
    ports = port_evidence(tree)
    out = []
    for group in scan_tree(tree):
        semantics = "coexisting" if group["status"] in COEXISTING else "candidates"
        entry = {"directory": str(group["directory"]), "status": group["status"],
                 "versions": group["versions"], "version_set_semantics": semantics,
                 "lookups": []}
        entry["port_evidence"] = ports
        if not group["versions"]:
            entry["tree_verdict"] = "NOT_QUERYABLE"
            entry["reason"] = ("detection did not resolve a version — nothing to look up "
                               "(this is a detection gap, not a clean bill of health)")
            entry["refined_verdict"] = "NOT_QUERYABLE"
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

        all_findings = [f for res in entry["lookups"] for f in res.get("findings", [])]
        entry.update(refine(entry["tree_verdict"], all_findings, ports))
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
    ports = entry.get("port_evidence") or {}
    if ports:
        print(f"\n  port evidence: MPU {ports['mpu']} — {ports['why']}")
        for p in ports["ports"]:
            port = p["port"]
            ident = (f"{port['compiler']}/{port['arch']}"
                     f"{'/' + port['security'] if port['security'] else ''} ({port['family']})"
                     if port else p["status"])
            print(f"    {p['directory']}: {ident} -> MPU {p['mpu_status']['mpu']}")

    print(f"\n  TREE VERDICT (version only): {entry['tree_verdict']}")
    if entry.get("reason"):
        print(f"    {entry['reason']}")
    if entry.get("refined_verdict") and entry["refined_verdict"] != entry["tree_verdict"]:
        print(f"  TREE VERDICT (with port evidence): {entry['refined_verdict']}")
        print(f"    {entry['refinement']}")
    elif entry.get("refinement"):
        print(f"    refinement: {entry['refinement']}")


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
