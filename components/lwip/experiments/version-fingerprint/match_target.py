"""Match a candidate source tree against the local lwIP reference fingerprint database
(see build_reference_db.py).

Two things differ from the plain skill template, both forced by phase-1 evidence:

**1. Files are located by path suffix, not basename.** ST's shipped lwIP middleware
contains `system/arch/init.h` (ST's own port header) alongside upstream's
`src/include/lwip/init.h`, and upstream itself has both `lwip/init.h` and `core/init.c`.
A basename-keyed scan picks whichever it walks into first and then scores a
vendor-authored port header against upstream release fingerprints. Matching
`lwip/init.h` / `core/init.c` as *path suffixes* resolves all three cases.

**2. Anchor quorum instead of all-or-nothing.** Requiring all 7 tracked files present
reports INCOMPLETE for legitimately partial vendoring (lwIP is routinely vendored without
`src/api/` when only the raw API is used). Instead: at least 2 of the 3 anchors
(`lwip/init.h`, `core/tcp.c`, `core/pbuf.c` — present in every lwIP tree since 1.3) must
be found to claim lwIP is present at all; every *other* tracked file that is present then
tightens the version intersection. Same design as the FreeRTOS 7-file DB.

Per-file matching is unchanged: exact normalized-content hash first, winnowing-fingerprint
Jaccard similarity as the fallback.

Verdicts (the `status` field of `resolve_group()`):
  CONFIRMED            every present file exact-matches, and they share a common release
  MIXED_VERSION        every present file exact-matches, but no common release
  PARTIALLY_MODIFIED   some exact-match, others don't (the classic vendor-patched tree)
  LIKELY_CONSISTENT    none exact-match, fuzzy best-matches agree
  INCONSISTENT         none exact-match, fuzzy best-matches disagree
  INCOMPLETE           anchor quorum not met — a weak, unconfirmed signal
  NOT_THIS_COMPONENT   no meaningful similarity to any known release

`resolve_group()` / `scan_tree()` are print-free and return dicts, so the phase-3
advisory loop-closing script can consume them; `analyze_group()` is the thin printer used
by the CLI.

Usage: python match_target.py <directory>
"""

import json
import re
import sys
from pathlib import Path

from lwip_fingerprint import fingerprint_source

DB_PATH = Path(__file__).parent / "reference" / "lwip_fingerprints.json"
TOP_N = 5

# Present in every lwIP release in scope; at least ANCHOR_QUORUM of them must be found.
ANCHORS = ["src/include/lwip/init.h", "src/core/tcp.c", "src/core/pbuf.c"]
ANCHOR_QUORUM = 2

# A completely unrelated file still gets a "top" candidate (score ~0.0, picked by
# tie-breaking on tag name alone) - without this floor, every file in a negative control
# can spuriously tie on the same tag and be reported as LIKELY_CONSISTENT. (Found the
# hard way in the Mbed TLS pass - don't remove.)
NO_SIMILARITY_FLOOR = 0.05

_TAG_RE = re.compile(r"^STABLE-(\d+)_(\d+)_(\d+)(?:_RELEASE(?:_VER)?)?$")


def tag_to_version(tag: str) -> str:
    """`STABLE-2_1_3_RELEASE` -> `2.1.3`. Both spellings of the 2.0.2 tag map to 2.0.2;
    see the README - `STABLE-2_0_2_RELEASE` is a phantom (its `init.h` still declares
    2.0.1) and only `STABLE-2_0_2_RELEASE_VER` matches the released zip."""
    m = _TAG_RE.match(tag)
    return ".".join(m.groups()) if m else tag


def load_db() -> dict:
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def find_files_present(target: Path, db: dict) -> dict:
    """tracked repo-path -> filesystem path, located by matching the tracked file's
    path *suffix* (e.g. `lwip/init.h`) against each candidate's posix path."""
    suffix = db["suffix"]
    candidates = [target] if target.is_file() else sorted(
        p for p in target.rglob("*") if p.is_file())

    found: dict = {}
    for tracked, suf in suffix.items():
        for path in candidates:
            if path.as_posix().endswith("/" + suf) or path.as_posix().endswith(suf):
                if tracked in found:
                    continue
                found[tracked] = path
    return found


def evaluate_file(path: Path, tracked: str, db: dict) -> dict:
    fp = fingerprint_source(path.read_text(encoding="utf-8", errors="replace"))
    target_winnow = set(fp["winnow"])
    bucket = db["content"].get(tracked, {})

    exact_entry = bucket.get(fp["sha256"])
    exact_matches = sorted(exact_entry["tags"]) if exact_entry else []

    scored = []
    for entry in bucket.values():
        ref_winnow = set(entry["winnow"])
        if not target_winnow and not ref_winnow:
            continue
        score = len(target_winnow & ref_winnow) / (len(target_winnow | ref_winnow) or 1)
        for tag in entry["tags"]:
            scored.append((score, tag))
    scored.sort(reverse=True)

    return {"path": str(path), "tracked": tracked, "exact_matches": exact_matches,
            "top_candidates": scored[:TOP_N]}


def resolve_group(target: Path, db: dict) -> dict:
    """Print-free resolution of one candidate location.

    Returns {"target", "status", "versions", "tags", "detail", "files"} where `versions`
    is the resolved release set (empty when unresolved) as plain version strings, and
    `files` maps each present tracked file to its evaluation."""
    files_present = find_files_present(target, db)
    anchors_found = [a for a in ANCHORS if a in files_present]

    results = {t: evaluate_file(p, t, db) for t, p in files_present.items()}
    out = {"target": str(target), "files": results,
           "anchors_found": anchors_found, "versions": [], "tags": []}

    if len(anchors_found) < ANCHOR_QUORUM:
        out["status"] = "INCOMPLETE"
        out["detail"] = (f"anchor quorum not met: found {anchors_found}, need "
                         f"{ANCHOR_QUORUM} of {ANCHORS}. lwIP presence can't be confirmed "
                         f"from this tree alone.")
        return out

    def finish(status, tags, detail):
        out["status"] = status
        out["tags"] = sorted(tags)
        out["versions"] = sorted({tag_to_version(t) for t in tags})
        out["detail"] = detail
        return out

    exact_sets = {t: set(r["exact_matches"]) for t, r in results.items()}
    with_exact = {t for t, tags in exact_sets.items() if tags}
    without_exact = set(results) - with_exact

    if not without_exact:
        common = set.intersection(*exact_sets.values())
        if common:
            return finish("CONFIRMED", common,
                          "all present tracked files exact-match a common release")
        return finish("MIXED_VERSION", set.union(*exact_sets.values()),
                      "every file exact-matches, but no single release is common to all: "
                      + "; ".join(f"{Path(t).name}={sorted(v)}"
                                  for t, v in sorted(exact_sets.items())))

    if with_exact:
        exact_union = set.union(*(exact_sets[t] for t in with_exact))
        exact_common = set.intersection(*(exact_sets[t] for t in with_exact))
        fuzzy_top = {results[t]["top_candidates"][0][1] for t in without_exact
                     if results[t]["top_candidates"]}
        pinned = (exact_common or exact_union)
        overlap = pinned & fuzzy_top
        detail = ("unmodified file(s) pin the base release; "
                  + ", ".join(f"{Path(t).name}=EXACT {sorted(exact_sets[t])}"
                              for t in sorted(with_exact))
                  + "; modified: "
                  + ", ".join(f"{Path(t).name}~{results[t]['top_candidates'][0][1]}"
                              f"@{results[t]['top_candidates'][0][0]:.2f}"
                              for t in sorted(without_exact)
                              if results[t]["top_candidates"]))
        if not overlap:
            detail += ("; NOTE exact-matched release(s) and the modified files' closest "
                       "release(s) don't overlap - may span more than one base version")
        return finish("PARTIALLY_MODIFIED", pinned, detail)

    top1 = {t: (r["top_candidates"][0] if r["top_candidates"] else None)
            for t, r in results.items()}
    if any(v is not None and v[0] < NO_SIMILARITY_FLOOR for v in top1.values()):
        out["status"] = "NOT_THIS_COMPONENT"
        out["detail"] = ("no file has meaningful fingerprint similarity to any known "
                         "release (best scores: "
                         + ", ".join(f"{Path(t).name}={v[0]:.3f}"
                                     for t, v in sorted(top1.items()) if v) + ")")
        return out

    tags = {v[1] for v in top1.values() if v}
    if len(tags) == 1:
        return finish("LIKELY_CONSISTENT", tags,
                      "no file exact-matches, but every file's closest release agrees - "
                      "treat as a modified copy of that base, not a confirmed version")
    return finish("INCONSISTENT", tags,
                  "no file exact-matches and closest releases disagree: "
                  + ", ".join(f"{Path(t).name}~{v[1]}@{v[0]:.2f}"
                              for t, v in sorted(top1.items()) if v))


def scan_tree(path: Path, db: dict | None = None) -> list:
    """One resolved group per candidate location. lwIP's tracked files span src/core,
    src/api and src/include, so a tree is treated as a single vendored copy (the
    template's default) rather than grouped per directory."""
    db = db or load_db()
    return [resolve_group(path, db)]


def analyze_group(res: dict) -> None:
    print(f"\n{'=' * 74}\nCandidate location: {res['target']}\n{'=' * 74}")
    for tracked in sorted(res["files"]):
        r = res["files"][tracked]
        print(f"\n  {tracked}  ({r['path']})")
        if r["exact_matches"]:
            print(f"    EXACT match -> {', '.join(r['exact_matches'])}")
        elif r["top_candidates"]:
            print("    No exact match. Closest known releases by fingerprint similarity:")
            for score, tag in r["top_candidates"]:
                print(f"      {score:.3f}  {tag}")
        else:
            print(f"    No reference data for {tracked} - can't compare.")

    missing = [t for t in load_db()["files"] if t not in res["files"]]
    if missing:
        print(f"\n  (not present in this tree: {[Path(m).name for m in missing]})")
    print(f"\n  {res['status']}"
          + (f" -> {res['versions']}" if res["versions"] else ""))
    print(f"    {res['detail']}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    target = Path(sys.argv[1])
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        sys.exit(1)

    db = load_db()
    for res in scan_tree(target, db):
        if not res["files"]:
            print(f"No tracked lwIP files found under {target}")
            continue
        analyze_group(res)


if __name__ == "__main__":
    main()
