"""Match a candidate source tree against the local Mbed-TLS reference fingerprint
database (see build_reference_db.py).

Unlike the FreeRTOS-Kernel experiment (three files that sit flat in the same
directory), the five files tracked here span two subdirectories of a real Mbed TLS
checkout (include/mbedtls/version.h vs. library/*.c) - so candidates are treated as a
single group per target path (the root of one vendored copy), not grouped by their
literal parent directory.

For the target as a whole:
  1. Every present file is matched independently: exact normalized-content hash first,
     falling back to winnowing-fingerprint Jaccard similarity against every known
     release.
  2. If not all five tracked files are found, the group is reported INCOMPLETE - a
     weak, unconfirmed signal, not a positive detection. (Five tracked files is this
     experiment's deliberately narrow research scope - see ../../README.md section 7 -
     not a claim that these are "the" minimal Mbed TLS signature the way
     tasks.c/queue.c/list.c are for FreeRTOS-Kernel.)
  3. If all five are present, their resolved versions are cross-checked for agreement,
     using the same CONFIRMED / MIXED VERSION / PARTIALLY MODIFIED / INCONSISTENT
     categories as the FreeRTOS-Kernel matcher.

Usage: python match_target.py <directory>
"""

import json
import sys
from pathlib import Path

from mbedtls_fingerprint import fingerprint_source

DB_PATH = Path(__file__).parent / "reference" / "mbedtls_fingerprints.json"
TOP_N = 5


def load_db() -> dict:
    """Loads the DB and re-keys db["content"]/db["files"] from full repo-relative
    paths (e.g. "library/bignum.c") to plain basenames, since a target tree being
    scanned may not preserve the same subdirectory layout as the upstream repo."""
    db = json.loads(DB_PATH.read_text(encoding="utf-8"))
    db["content"] = {Path(f).name: bucket for f, bucket in db["content"].items()}
    db["files"] = [Path(f).name for f in db["files"]]
    return db


def find_files_present(target: Path, filenames: list) -> dict:
    """filename -> path, for the first match of each tracked filename anywhere under
    target. Warns on stderr if a filename appears more than once (unexpected for a
    single vendored copy)."""
    if target.is_file():
        return {target.name: target} if target.name in filenames else {}

    found: dict = {}
    for path in sorted(target.rglob("*")):
        if path.is_file() and path.name in filenames:
            if path.name in found:
                print(f"  (note: multiple {path.name} found under {target}; "
                      f"using {found[path.name]}, ignoring {path})", file=sys.stderr)
                continue
            found[path.name] = path
    return found


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


def analyze_target(target: Path, files_present: dict, required: list, db: dict) -> None:
    print(f"\n{'=' * 70}\nCandidate Mbed TLS location: {target}\n{'=' * 70}")

    missing = [f for f in required if f not in files_present]
    results = {}
    for filename in required:
        if filename not in files_present:
            continue
        results[filename] = evaluate_file(files_present[filename], filename, db)
        print_file_result(results[filename])

    if missing:
        print(f"\n  INCOMPLETE - missing {missing}. Presence of Mbed TLS can't be "
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
            print("  This looks like a Mbed TLS integration assembled from files pulled "
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
    # control can spuriously tie on the same tag and get reported as LIKELY CONSISTENT.
    NO_SIMILARITY_FLOOR = 0.05
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
    files_present = find_files_present(target, db["files"])
    if not files_present:
        print(f"No tracked files ({db['files']}) found under {target}")
        return

    analyze_target(target, files_present, db["files"], db)


if __name__ == "__main__":
    main()
