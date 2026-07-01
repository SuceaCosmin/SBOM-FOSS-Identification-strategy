"""Match a candidate source tree against the local FreeRTOS-Kernel reference
fingerprint database (see build_reference_db.py).

For each of tasks.c / queue.c / list.c found under the target path:
  1. Try an exact normalized-content hash match against every known release tag.
  2. If no exact match, fall back to winnowing-fingerprint Jaccard similarity and
     report the closest tags, to approximate "which version was this modified from,
     and how much".

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


def match_file(path: Path, db: dict) -> None:
    filename = path.name
    fp = fingerprint_source(path.read_text(encoding="utf-8", errors="replace"))
    target_winnow = set(fp["winnow"])

    exact_matches = [
        tag for tag, files in db["tags"].items()
        if filename in files and files[filename]["sha256"] == fp["sha256"]
    ]

    print(f"\n{path}")
    if exact_matches:
        print(f"  EXACT match ({filename} unmodified) -> {', '.join(sorted(exact_matches))}")
        return

    scored = []
    for tag, files in db["tags"].items():
        if filename not in files:
            continue
        ref_winnow = set(files[filename]["winnow"])
        if not target_winnow and not ref_winnow:
            continue
        intersection = len(target_winnow & ref_winnow)
        union = len(target_winnow | ref_winnow) or 1
        scored.append((intersection / union, tag))
    scored.sort(reverse=True)

    if not scored:
        print(f"  No reference data for {filename} — can't compare.")
        return

    print(f"  No exact match. Closest known releases by fingerprint similarity:")
    for score, tag in scored[:TOP_N]:
        print(f"    {score:.3f}  {tag}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    target = Path(sys.argv[1])
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        sys.exit(1)

    db = load_db()
    candidates = find_candidates(target, db["files"])
    if not candidates:
        print(f"No files named {db['files']} found under {target}")
        return

    for path in candidates:
        match_file(path, db)


if __name__ == "__main__":
    main()
