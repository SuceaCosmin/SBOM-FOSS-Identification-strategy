#!/usr/bin/env python3
"""Match a static library's defined symbols against a mined reference DB.

Ports the source experiments' tag-set/window logic to the symbol domain:
- observed = defined globals of the .a, filtered to the component's prefix
- presence-consistent releases: every observed symbol exists in that
  release's reference set (observed may be a SUBSET — vendor configs
  compile the component partially, so absence of a reference symbol is
  only soft evidence, never disqualifying)
- the reported window = presence-consistent releases, ranked by fewest
  unexplained reference symbols (soft absences); discriminating symbols
  (present in only part of the release range) are listed as evidence.

Usage:
  python match_symbols.py REF.json LIB.a
"""

import json
import re
import sys

from extract_symbols import extract


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    ref_path, lib_path = sys.argv[1], sys.argv[2]
    with open(ref_path, encoding="utf-8") as f:
        ref = json.load(f)
    prefix_re = re.compile(r"^(?:" + ref["prefix"] + r")")
    releases = {tag: set(syms) for tag, syms in ref["releases"].items()}
    universe = set().union(*releases.values())

    lib = extract(lib_path)
    all_defined = set(lib["defined_globals"])
    observed = {s for s in all_defined if prefix_re.match(s)}
    known = observed & universe
    unknown = observed - universe

    print(f"component:  {ref['component']}")
    print(f"library:    {lib_path}")
    print(f"observed {len(observed)} '{ref['prefix']}' symbols "
          f"({len(known)} known to reference DB, {len(unknown)} unknown)")
    if unknown:
        print(f"  unknown to DB: {', '.join(sorted(unknown)[:8])}"
              f"{'...' if len(unknown) > 8 else ''}")
    if not known:
        print("NO MATCH: no overlap with reference DB")
        return

    rows = []
    for tag, rset in releases.items():
        missing_obs = known - rset          # observed but not in this release
        soft_absent = rset - all_defined    # expected but not defined anywhere
        rows.append((tag, len(missing_obs), len(soft_absent), missing_obs))

    consistent = [r for r in rows if r[1] == 0]
    if consistent:
        best_soft = min(r[2] for r in consistent)
        window = [r[0] for r in consistent]
        top = [r[0] for r in consistent if r[2] == best_soft]
        print(f"presence-consistent releases ({len(window)}): "
              f"{window[0]} ... {window[-1]}" if len(window) > 4
              else f"presence-consistent releases: {', '.join(window)}")
        print(f"best window (fewest soft absences = {best_soft}): "
              f"{', '.join(top)}")
    else:
        print("no fully presence-consistent release; closest:")
        for tag, nmiss, nsoft, missing in sorted(rows, key=lambda r: r[1])[:5]:
            print(f"  {tag}: {nmiss} observed symbols unexplained "
                  f"({', '.join(sorted(missing)[:5])})")

    # discriminating evidence: observed symbols not present in all releases
    partial = sorted(s for s in known
                     if 0 < sum(s in r for r in releases.values()) < len(releases))
    if partial:
        print("discriminating observed symbols (not in every release):")
        for s in partial[:12]:
            tags_with = [t for t, r in releases.items() if s in r]
            print(f"  {s}: {tags_with[0]} ... {tags_with[-1]}")


if __name__ == "__main__":
    main()
