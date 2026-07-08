"""Match a candidate source tree against the local CMSIS-Core reference fingerprint
database (see build_reference_db.py).

Four files are tracked, all normally living together in one CMSIS/Core/Include/
directory in a real vendored copy (confirmed this session: STM32CubeF4 ships all four,
not just the core_cm*.h variant matching its own chip - see ../../README.md section 3),
so - like the FreeRTOS-Kernel matcher and unlike the multi-directory Mbed TLS one -
candidates are grouped by their literal parent directory.

For each such group:
  1. Every present file is matched independently: exact normalized-content hash first,
     falling back to winnowing-fingerprint Jaccard similarity against every known
     release.
  2. If not all four tracked files are found, the group is reported INCOMPLETE - a
     weak, unconfirmed signal, not a positive detection. (Four tracked files is this
     experiment's deliberately narrow research scope - see ../../README.md section 7 -
     not a claim that these are "the" minimal CMSIS-Core signature; a real vendored copy
     ships ~30 core_c{a,m,r}*.h files total, of which this experiment tracks three plus
     the version-macro file.)
  3. If all four are present, their resolved versions are cross-checked for agreement,
     using the same CONFIRMED / MIXED VERSION / PARTIALLY MODIFIED / INCONSISTENT /
     LIKELY CONSISTENT / NOT THIS COMPONENT categories as the FreeRTOS-Kernel and
     Mbed TLS matchers (including the NO_SIMILARITY_FLOOR fix the Mbed TLS negative
     control surfaced - see ../mbedtls/experiments/version-fingerprint/README.md).

Usage: python match_target.py <directory>
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

from cmsis_fingerprint import fingerprint_source

DB_PATH = Path(__file__).parent / "reference" / "cmsis_fingerprints.json"
TOP_N = 5
NO_SIMILARITY_FLOOR = 0.05


def load_db() -> dict:
    """Loads the DB and re-keys db["content"]/db["files"] from full repo-relative
    paths (e.g. "CMSIS/Core/Include/core_cm4.h") to plain basenames, since a target
    tree being scanned may not preserve the same subdirectory layout as upstream."""
    db = json.loads(DB_PATH.read_text(encoding="utf-8"))
    db["content"] = {Path(f).name: bucket for f, bucket in db["content"].items()}
    db["files"] = [Path(f).name for f in db["files"]]
    return db


def find_groups(target: Path, filenames: list) -> dict:
    """parent directory -> {filename: path}, for every directory under target that
    contains at least one tracked filename."""
    groups: dict = defaultdict(dict)
    if target.is_file():
        if target.name in filenames:
            groups[target.parent][target.name] = target
        return groups

    for path in sorted(target.rglob("*")):
        if path.is_file() and path.name in filenames:
            groups[path.parent][path.name] = path
    return groups


def evaluate_file(path: Path, filename: str, db: dict) -> dict:
    fp = fingerprint_source(path.read_text(encoding="utf-8", errors="replace"))
    target_winnow = set(fp["winnow"])
    bucket = db["content"].get(filename, {})

    exact_entry = bucket.get(fp["sha256"])
    exact_matches = sorted(exact_entry["tags"]) if exact_entry else []

    scored = []
    for entry in bucket.values():
        ref_winnow = set(entry["winnow"])
        if not target_winnow and not ref_winnow:
            continue
        intersection = len(target_winnow & ref_winnow)
        union = len(target_winnow | ref_winnow) or 1
        score = intersection / union
        for tag in entry["tags"]:
            scored.append((score, tag))
    scored.sort(reverse=True)

    return {"path": path, "filename": filename, "exact_matches": exact_matches,
            "top_candidates": scored[:TOP_N]}


def print_file_result(result: dict) -> None:
    print(f"\n  {result['filename']}  ({result['path']})")
    if result["exact_matches"]:
        print(f"    EXACT match -> {', '.join(result['exact_matches'])}")
    elif result["top_candidates"]:
        print("    No exact match. Closest known releases by fingerprint similarity:")
        for score, tag in result["top_candidates"]:
            print(f"      {score:.3f}  {tag}")
    else:
        print(f"    No reference data for {result['filename']} - can't compare.")


def analyze_group(location: Path, files_present: dict, required: list, db: dict) -> None:
    print(f"\n{'=' * 70}\nCandidate CMSIS-Core location: {location}\n{'=' * 70}")

    missing = [f for f in required if f not in files_present]
    results = {}
    for filename in required:
        if filename not in files_present:
            continue
        results[filename] = evaluate_file(files_present[filename], filename, db)
        print_file_result(results[filename])

    if missing:
        print(f"\n  INCOMPLETE - missing {missing}. Presence of CMSIS-Core can't be "
              f"confirmed from this tree alone (this experiment tracks {required} "
              f"together); the matches above are a weak, unconfirmed signal only.")
        return

    exact_sets = {f: set(r["exact_matches"]) for f, r in results.items()}
    files_with_exact = {f for f, tags in exact_sets.items() if tags}
    files_without_exact = set(required) - files_with_exact

    if not files_without_exact:
        common = set.intersection(*exact_sets.values())
        if common:
            print(f"\n  CONFIRMED: all files exact-match a common release -> {sorted(common)}")
        else:
            print("\n  MIXED VERSION WARNING: every file has an exact match, but they don't "
                  "agree on a common release:")
            for f, tags in sorted(exact_sets.items()):
                print(f"    {f}: {sorted(tags)}")
            print("  This looks like a CMSIS-Core integration assembled from files pulled "
                  "from different releases.")
        return

    if files_with_exact:
        print("\n  PARTIALLY MODIFIED: some files exact-match a known release, others don't:")
        for f in sorted(files_with_exact):
            print(f"    {f}: EXACT -> {sorted(exact_sets[f])}")
        for f in sorted(files_without_exact):
            top = results[f]["top_candidates"]
            closest = top[0][1] if top else "unknown (no reference data)"
            print(f"    {f}: no exact match, closest -> {closest}")

        exact_union = set.union(*(exact_sets[f] for f in files_with_exact))
        fuzzy_top_tags = {results[f]["top_candidates"][0][1] for f in files_without_exact
                           if results[f]["top_candidates"]}
        overlap = exact_union & fuzzy_top_tags
        if overlap:
            print(f"  Consistent with a single base release that was partially modified - "
                  f"the unmodified file(s) pin the base to {sorted(overlap)}.")
        else:
            print("  The exact-matched release(s) and the modified files' closest release(s) "
                  "don't overlap - worth a closer look, this may span more than one base version.")
        return

    # A completely unrelated file still gets a "top" candidate (score 0.0, picked by
    # tie-breaking on tag name alone) - without this floor, every file in a negative
    # control can spuriously tie on the same tag and get reported as LIKELY CONSISTENT
    # (this exact bug was found and fixed during the Mbed TLS experiment - see its README).
    top1 = {f: (r["top_candidates"][0] if r["top_candidates"] else None)
            for f, r in results.items()}
    if any(top is not None and top[0] < NO_SIMILARITY_FLOOR for top in top1.values()):
        print(f"\n  NOT THIS COMPONENT: no file has meaningful fingerprint similarity "
              f"(best score(s): {sorted(t[0] for t in top1.values() if t)}) to any known "
              f"release - this doesn't look like a modified copy of this component at all.")
        return

    top1_tags = {f: (t[1] if t else None) for f, t in top1.items()}
    if None in top1_tags.values():
        print("\n  INCONCLUSIVE - at least one file has no reference data to compare against.")
    elif len(set(top1_tags.values())) == 1:
        print(f"\n  LIKELY CONSISTENT: best-match version agrees across all files -> "
              f"{next(iter(top1_tags.values()))} (at least one file differs from an exact "
              f"release copy, so treat this as a modified base rather than a confirmed exact version).")
    else:
        print("\n  INCONSISTENT best-match versions across files - possible mixed-version "
              "or independently-modified integration:")
        for f, tag in sorted(top1_tags.items()):
            print(f"    {f}: closest -> {tag}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        sys.exit(1)

    db = load_db()
    groups = find_groups(target, db["files"])
    if not groups:
        print(f"No tracked files ({db['files']}) found under {target}")
        return

    for location, files_present in groups.items():
        analyze_group(location, files_present, db["files"], db)


if __name__ == "__main__":
    main()
