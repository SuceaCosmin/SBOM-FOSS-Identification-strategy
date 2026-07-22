#!/usr/bin/env python3
"""De-risking sweep (b): batch-scan a tree of static libs against reference DBs.

False-positive stress test + hidden-OSS hunt: run every *.a under a root
(e.g. the TI SDK's source/ti — 588 TI-authored libs) against each mined
symbol reference DB. Proprietary libs should overwhelmingly report NO MATCH;
any hit is either a false positive (bad) or an undeclared embedded OSS copy
(the nanopb precedent — exactly what an SBOM scanner exists to find).

Match semantics are those of match_symbols.py: observed = prefix-filtered
defined globals; a lib "hits" a DB when observed symbols overlap the DB
universe; presence-consistent releases form the version window.

Usage:
  python batch_scan.py ROOT REF.json [REF2.json ...] [--json OUT.json]

Console output: one line per hit, then a summary. --json writes the full
per-lib result list (pretty-printed).
"""

import json
import re
import sys
from pathlib import Path

from extract_symbols import extract


def load_ref(path):
    with open(path, encoding="utf-8") as f:
        ref = json.load(f)
    releases = {tag: set(s) for tag, s in ref["releases"].items()}
    return {
        "component": ref["component"],
        "prefix_re": re.compile(r"^(?:" + ref["prefix"] + r")"),
        "releases": releases,
        "universe": set().union(*releases.values()),
    }


def match(ref, all_defined):
    observed = {s for s in all_defined if ref["prefix_re"].match(s)}
    known = observed & ref["universe"]
    if not known:
        return None
    consistent = [tag for tag, rset in ref["releases"].items()
                  if not (known - rset)]
    return {
        "component": ref["component"],
        "observed_prefix_symbols": len(observed),
        "known_to_db": len(known),
        "unknown_to_db": len(observed - known),
        "known_symbols_sample": sorted(known)[:10],
        "presence_consistent_window": consistent,
    }


def main():
    args = [a for a in sys.argv[1:]]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i : i + 2]
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)
    root, refs = Path(args[0]), [load_ref(p) for p in args[1:]]

    libs = sorted(root.rglob("*.a")) + sorted(root.rglob("*.lib"))
    results, errors, hits = [], [], 0
    for lib in libs:
        try:
            res = extract(str(lib))
        except Exception as e:                      # malformed/non-ar files
            errors.append({"library": str(lib), "error": str(e)})
            continue
        defined = set(res["defined_globals"])
        lib_hits = [m for ref in refs if (m := match(ref, defined))]
        results.append({
            "library": str(lib),
            "elf_members": res["member_count"],
            "defined_globals": len(defined),
            "matches": lib_hits,
        })
        if lib_hits:
            hits += 1
            for m in lib_hits:
                win = m["presence_consistent_window"]
                wintxt = (f"{win[0]} ... {win[-1]} ({len(win)} releases)"
                          if win else "NONE consistent")
                print(f"HIT  {lib.relative_to(root)}")
                print(f"     {m['component']}: {m['known_to_db']} known symbols, "
                      f"window {wintxt}")
                print(f"     e.g. {', '.join(m['known_symbols_sample'][:5])}")

    print(f"\nscanned {len(results)} libs under {root} "
          f"against {len(refs)} reference DBs "
          f"({', '.join(r['component'] for r in refs)})")
    print(f"NO MATCH: {len(results) - hits}   HITS: {hits}   "
          f"unreadable: {len(errors)}")
    for e in errors:
        print(f"  unreadable: {e['library']}: {e['error']}")

    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"root": str(root), "libs_scanned": len(results),
                       "hits": hits, "errors": errors,
                       "results": results}, f, indent=2)
            f.write("\n")
        print(f"full results -> {out_json}")


if __name__ == "__main__":
    main()
