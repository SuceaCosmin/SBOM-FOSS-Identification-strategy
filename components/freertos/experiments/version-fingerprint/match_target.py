"""Match a candidate source tree against the local FreeRTOS-Kernel reference
fingerprint database (see build_reference_db.py).

Core kernel `.c` files (tasks/queue/list/timers/event_groups/stream_buffer/croutine)
are grouped by the directory they were found in (a real vendored copy keeps them
together), since presence of the kernel can't be confirmed from a single file alone.
For each such group:
  1. Every present file is matched independently: exact normalized-content hash first,
     falling back to winnowing-fingerprint Jaccard similarity against every known
     release tag.
  2. The kernel is confirmed present only if the *anchor* files (db["anchors"] —
     tasks.c/queue.c/list.c, which essentially always ship) are all present; otherwise
     the group is reported as an INCOMPLETE / unconfirmed signal. The remaining core
     files are optional (croutine is legacy, others are feature-gated) and are not
     required — but any that ARE present are folded into the cross-file consistency
     check, tightening the version resolution.
  3. Once presence is confirmed, the resolved versions of every present file are
     cross-checked for agreement. Files that exact-match releases that don't share a
     common tag are flagged as a MIXED VERSION integration — e.g. a partial upgrade
     where only some kernel files were replaced, leaving others on an older release.

Usage: python match_target.py <file-or-directory>
"""

import json
import sys
from pathlib import Path

from freertos_fingerprint import fingerprint_source

DB_PATH = Path(__file__).parent / "reference" / "kernel_fingerprints.json"
TOP_N = 5


def load_db() -> dict:
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def find_candidates(target: Path, filenames: list) -> list:
    if target.is_file():
        return [target] if target.name in filenames else []
    return [p for p in target.rglob("*.c") if p.name in filenames]


def group_by_directory(candidates: list) -> dict:
    groups: dict = {}
    for path in candidates:
        groups.setdefault(path.parent, {})[path.name] = path
    return groups


def evaluate_file(path: Path, db: dict) -> dict:
    filename = path.name
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
        # one content hash can correspond to several tags (patch releases that left
        # this file untouched) — surface each as its own scored row.
        for tag in entry["tags"]:
            scored.append((score, tag))
    scored.sort(reverse=True)

    return {"path": path, "filename": filename, "exact_matches": exact_matches,
            "top_candidates": scored[:TOP_N]}


def print_file_result(result: dict) -> None:
    print(f"\n  {result['path']}")
    if result["exact_matches"]:
        print(f"    EXACT match -> {', '.join(result['exact_matches'])}")
    elif result["top_candidates"]:
        print("    No exact match. Closest known releases by fingerprint similarity:")
        for score, tag in result["top_candidates"]:
            print(f"      {score:.3f}  {tag}")
    else:
        print(f"    No reference data for {result['filename']} — can't compare.")


def analyze_group(directory: Path, files_present: dict, anchors: list, db: dict) -> None:
    print(f"\n{'=' * 70}\nCandidate FreeRTOS-Kernel location: {directory}\n{'=' * 70}")

    missing_anchors = [f for f in anchors if f not in files_present]
    results = {}
    for filename, path in sorted(files_present.items()):
        results[filename] = evaluate_file(path, db)
        print_file_result(results[filename])

    if missing_anchors:
        print(f"\n  INCOMPLETE — missing anchor file(s) {missing_anchors}. Presence of "
              f"FreeRTOS-Kernel can't be confirmed from this directory alone (need "
              f"{anchors} together); the matches above are a weak, unconfirmed signal only.")
        return

    # Consistency runs over every present core file, not just the anchors: any of the
    # optional files (timers/event_groups/stream_buffer/croutine) that happen to be
    # present tighten the version intersection.
    exact_sets = {f: set(r["exact_matches"]) for f, r in results.items()}
    files_with_exact = {f for f, tags in exact_sets.items() if tags}
    files_without_exact = set(results) - files_with_exact

    if not files_without_exact:
        # Every file exact-matches at least one release.
        common = set.intersection(*exact_sets.values())
        if common:
            print(f"\n  CONFIRMED: all files exact-match a common release -> {sorted(common)}")
        else:
            print("\n  MIXED VERSION WARNING: every file has an exact match, but they don't "
                  "agree on a common release:")
            for f, tags in sorted(exact_sets.items()):
                print(f"    {f}: {sorted(tags)}")
            print("  This looks like a FreeRTOS-Kernel integration assembled from files "
                  "pulled from different releases (e.g. a partial upgrade that only "
                  "replaced some kernel files).")
        return

    if files_with_exact:
        # Some files exact-match, others don't — a real fork often leaves some files
        # (e.g. list.c) untouched while heavily modifying others (e.g. tasks.c).
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
            print(f"  Consistent with a single base release that was partially modified — "
                  f"the unmodified file(s) pin the base to {sorted(overlap)}.")
        else:
            print("  The exact-matched release(s) and the modified files' closest release(s) "
                  "don't overlap — worth a closer look, this may span more than one base version.")
        return

    top1_tags = {f: (r["top_candidates"][0][1] if r["top_candidates"] else None)
                 for f, r in results.items()}
    if None in top1_tags.values():
        print("\n  INCONCLUSIVE — at least one file has no reference data to compare against.")
    elif len(set(top1_tags.values())) == 1:
        print(f"\n  LIKELY CONSISTENT: best-match version agrees across all files -> "
              f"{next(iter(top1_tags.values()))} (at least one file differs from an exact "
              f"release copy, so treat this as a modified base rather than a confirmed exact version).")
    else:
        print("\n  INCONSISTENT best-match versions across files — possible mixed-version "
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
    anchors = db.get("anchors", db["files"])
    candidates = find_candidates(target, db["files"])
    if not candidates:
        print(f"No files named {db['files']} found under {target}")
        return

    for directory, files_present in sorted(group_by_directory(candidates).items()):
        analyze_group(directory, files_present, anchors, db)


if __name__ == "__main__":
    main()
