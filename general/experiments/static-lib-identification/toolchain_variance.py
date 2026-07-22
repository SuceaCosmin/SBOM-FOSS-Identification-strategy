#!/usr/bin/env python3
"""De-risking sweep (a): is the defined-symbol set toolchain-independent?

The symbol-set fingerprint tier rests on the claim that a library's defined
global symbols depend only on the source version (and build config), not on
which compiler produced the binary. The TI SDK ships the *same* lib version
built by gcc, IAR, and ticlang side by side — so the claim is directly
testable: extract the defined-globals set from every flavor of the same lib
and diff across toolchains (and, as a bonus, across CPU cores).

Usage:
  python toolchain_variance.py SDK_ROOT

Output: per lib group (e.g. fatfs/m4f), whether the three toolchains'
symbol sets are identical; any differences listed symbol-by-symbol.
"""

import sys
from collections import defaultdict
from pathlib import Path

from extract_symbols import extract

# lib groups: relative glob roots under the SDK -> (component, path pattern)
# Path layout is <root>\lib\<toolchain>\<core>\<name>.a
GROUP_ROOTS = [
    "source/third_party/fatfs/lib",
    "source/third_party/spiffs/lib",
    "source/third_party/ecc/lib",
    "source/third_party/psa_crypto/library/lib",
]


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sdk = Path(sys.argv[1])

    # groups[(root, libname, core)][toolchain] = set(symbols)
    groups = defaultdict(dict)
    for root in GROUP_ROOTS:
        for lib in sorted((sdk / root).rglob("*.a")):
            toolchain, core = lib.parent.parent.name, lib.parent.name
            res = extract(str(lib))
            groups[(root, lib.name, core)][toolchain] = set(res["defined_globals"])

    print(f"{len(groups)} (lib, core) groups collected\n")
    identical = mismatched = 0
    for (root, name, core), flavors in sorted(groups.items()):
        if len(flavors) < 2:
            continue
        sets = list(flavors.values())
        if all(s == sets[0] for s in sets[1:]):
            identical += 1
            print(f"IDENTICAL  {name} [{core}] across {sorted(flavors)} "
                  f"({len(sets[0])} symbols)")
        else:
            mismatched += 1
            print(f"DIFFERS    {name} [{core}]:")
            universe = set().union(*sets)
            for sym in sorted(universe):
                have = [tc for tc, s in sorted(flavors.items()) if sym in s]
                if len(have) != len(flavors):
                    print(f"    {sym}: only in {have}")

    # bonus: cross-core variance within one toolchain (expect identical too,
    # since symbol names don't depend on the target core)
    print("\ncross-core check (per toolchain):")
    bycore = defaultdict(dict)
    for (root, name, core), flavors in groups.items():
        for tc, syms in flavors.items():
            bycore[(name, tc)][core] = syms
    for (name, tc), cores in sorted(bycore.items()):
        if len(cores) < 2:
            continue
        sets = list(cores.values())
        verdict = ("identical" if all(s == sets[0] for s in sets[1:])
                   else "DIFFERS")
        print(f"  {name} [{tc}] across cores {sorted(cores)}: {verdict}")

    print(f"\nsummary: {identical} identical, {mismatched} differing "
          f"toolchain groups")


if __name__ == "__main__":
    main()
