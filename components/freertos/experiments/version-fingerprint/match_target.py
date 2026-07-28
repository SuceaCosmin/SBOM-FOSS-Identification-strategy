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


def resolve_group(directory: Path, files_present: dict, anchors: list, db: dict) -> dict:
    """Resolve one candidate kernel directory to a structured verdict.

    Returns {"directory", "files" (per-file evaluate_file results), "status",
    "versions", "detail"}. `versions` is the set of release tags the tree is pinned
    to — the handoff point for downstream consumers (e.g. the advisory lookup in
    general/experiments/advisory-fitness/ghsa_vuln_lookup.py). It is empty whenever
    presence or version could not be established.

    Statuses: CONFIRMED / MIXED / PARTIALLY_MODIFIED / LIKELY_CONSISTENT /
    INCOMPLETE / INCONSISTENT / INCONCLUSIVE.
    """
    missing_anchors = [f for f in anchors if f not in files_present]
    results = {filename: evaluate_file(path, db)
               for filename, path in sorted(files_present.items())}
    out = {"directory": directory, "files": results, "versions": [], "detail": {}}

    if missing_anchors:
        out["status"] = "INCOMPLETE"
        out["detail"] = {"missing_anchors": missing_anchors}
        return out

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
            out["status"] = "CONFIRMED"
            out["versions"] = sorted(common)
        else:
            out["status"] = "MIXED"
            # Every distinct per-file release matters downstream: a mixed tree can be
            # simultaneously affected and not affected by the same advisory.
            out["versions"] = sorted(set.union(*exact_sets.values()))
            out["detail"] = {"per_file": {f: sorted(t) for f, t in exact_sets.items()}}
        return out

    if files_with_exact:
        # Some files exact-match, others don't — a real fork often leaves some files
        # (e.g. list.c) untouched while heavily modifying others (e.g. tasks.c).
        exact_union = set.union(*(exact_sets[f] for f in files_with_exact))
        fuzzy_top_tags = {results[f]["top_candidates"][0][1] for f in files_without_exact
                          if results[f]["top_candidates"]}
        overlap = exact_union & fuzzy_top_tags
        out["status"] = "PARTIALLY_MODIFIED"
        out["versions"] = sorted(overlap) if overlap else sorted(exact_union)
        out["detail"] = {"exact": {f: sorted(exact_sets[f]) for f in files_with_exact},
                         "fuzzy_closest": {f: (results[f]["top_candidates"][0][1]
                                               if results[f]["top_candidates"] else None)
                                           for f in files_without_exact},
                         "base_pinned_by_unmodified_files": bool(overlap)}
        return out

    top1_tags = {f: (r["top_candidates"][0][1] if r["top_candidates"] else None)
                 for f, r in results.items()}
    out["detail"] = {"fuzzy_closest": top1_tags}
    if None in top1_tags.values():
        out["status"] = "INCONCLUSIVE"
    elif len(set(top1_tags.values())) == 1:
        out["status"] = "LIKELY_CONSISTENT"
        out["versions"] = [next(iter(top1_tags.values()))]
    else:
        out["status"] = "INCONSISTENT"
    return out


def analyze_group(directory: Path, files_present: dict, anchors: list, db: dict) -> dict:
    print(f"\n{'=' * 70}\nCandidate FreeRTOS-Kernel location: {directory}\n{'=' * 70}")

    resolved = resolve_group(directory, files_present, anchors, db)
    for filename in sorted(resolved["files"]):
        print_file_result(resolved["files"][filename])

    status, detail = resolved["status"], resolved["detail"]
    if status == "INCOMPLETE":
        print(f"\n  INCOMPLETE — missing anchor file(s) {detail['missing_anchors']}. Presence "
              f"of FreeRTOS-Kernel can't be confirmed from this directory alone (need "
              f"{anchors} together); the matches above are a weak, unconfirmed signal only.")
    elif status == "CONFIRMED":
        print(f"\n  CONFIRMED: all files exact-match a common release -> {resolved['versions']}")
    elif status == "MIXED":
        print("\n  MIXED VERSION WARNING: every file has an exact match, but they don't "
              "agree on a common release:")
        for f, tags in sorted(detail["per_file"].items()):
            print(f"    {f}: {tags}")
        print("  This looks like a FreeRTOS-Kernel integration assembled from files "
              "pulled from different releases (e.g. a partial upgrade that only "
              "replaced some kernel files).")
    elif status == "PARTIALLY_MODIFIED":
        print("\n  PARTIALLY MODIFIED: some files exact-match a known release, others don't:")
        for f, tags in sorted(detail["exact"].items()):
            print(f"    {f}: EXACT -> {tags}")
        for f, closest in sorted(detail["fuzzy_closest"].items()):
            print(f"    {f}: no exact match, closest -> {closest or 'unknown (no reference data)'}")
        if detail["base_pinned_by_unmodified_files"]:
            print(f"  Consistent with a single base release that was partially modified — "
                  f"the unmodified file(s) pin the base to {resolved['versions']}.")
        else:
            print("  The exact-matched release(s) and the modified files' closest release(s) "
                  "don't overlap — worth a closer look, this may span more than one base version.")
    elif status == "INCONCLUSIVE":
        print("\n  INCONCLUSIVE — at least one file has no reference data to compare against.")
    elif status == "LIKELY_CONSISTENT":
        print(f"\n  LIKELY CONSISTENT: best-match version agrees across all files -> "
              f"{resolved['versions'][0]} (at least one file differs from an exact "
              f"release copy, so treat this as a modified base rather than a confirmed exact version).")
    else:
        print("\n  INCONSISTENT best-match versions across files — possible mixed-version "
              "or independently-modified integration:")
        for f, tag in sorted(detail["fuzzy_closest"].items()):
            print(f"    {f}: closest -> {tag}")
    return resolved


def scan_tree(target: Path, db: dict = None) -> list:
    """Programmatic entry point: resolve every candidate kernel directory under
    `target` and return the structured verdicts, printing nothing."""
    db = db or load_db()
    anchors = db.get("anchors", db["files"])
    candidates = find_candidates(target, db["files"])
    return [resolve_group(directory, files_present, anchors, db)
            for directory, files_present in sorted(group_by_directory(candidates).items())]


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
