"""Build a local reference fingerprint database for every tagged release of
FreeRTOS/FreeRTOS-Kernel, covering the three files that "contain the kernel"
(tasks.c, queue.c, list.c). Fetches file content over HTTPS from raw.githubusercontent.com
per tag — no full git clone needed.

Usage: python build_reference_db.py
Output: reference/kernel_fingerprints.json
"""

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from freertos_fingerprint import fingerprint_source

REPO = "FreeRTOS/FreeRTOS-Kernel"
FILES = ["tasks.c", "queue.c", "list.c"]
OUT_PATH = Path(__file__).parent / "reference" / "kernel_fingerprints.json"


def list_tags() -> list:
    result = subprocess.run(
        ["git", "ls-remote", "--tags", f"https://github.com/{REPO}.git"],
        capture_output=True, text=True, check=True,
    )
    tags = []
    for line in result.stdout.splitlines():
        ref = line.split("refs/tags/", 1)[1]
        if ref.endswith("^{}"):
            continue
        tags.append(ref)
    return sorted(set(tags))


# Repo layout changed over time: post-"kernel-only" tags (~V10.3.0 onward) have the
# kernel files at the repo root; older tags predate the kernel-only extraction and
# still carry the full old "FreeRTOS/Source/..." distribution layout.
CANDIDATE_PATH_TEMPLATES = ["{filename}", "FreeRTOS/Source/{filename}"]


def fetch_file(tag: str, filename: str) -> str | None:
    for template in CANDIDATE_PATH_TEMPLATES:
        path = template.format(filename=filename)
        url = f"https://raw.githubusercontent.com/{REPO}/{tag}/{path}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
    return None


def main() -> None:
    tags = list_tags()
    print(f"Found {len(tags)} tags on {REPO}", file=sys.stderr)

    # content[filename][sha256] = {"winnow": [...], "tags": [...]} — deduplicated:
    # many patch/rc releases leave a given file byte-identical to a prior release, so
    # storing fingerprints once per unique content (not once per tag) cuts storage
    # roughly in half for a project like FreeRTOS-Kernel. tag_index maps each tag back
    # to which content hash it had, per file.
    content: dict = {f: {} for f in FILES}
    tag_index: dict = {}

    for i, tag in enumerate(tags, 1):
        entry = {}
        for filename in FILES:
            text = fetch_file(tag, filename)
            if text is None:
                continue
            fp = fingerprint_source(text)
            sha = fp["sha256"]
            bucket = content[filename]
            if sha in bucket:
                bucket[sha]["tags"].append(tag)
            else:
                bucket[sha] = {"winnow": fp["winnow"], "tags": [tag]}
            entry[filename] = sha
        if entry:
            tag_index[tag] = entry
        print(f"[{i}/{len(tags)}] {tag}: {sorted(entry.keys())}", file=sys.stderr)

    db = {"repo": REPO, "files": FILES, "content": content, "tags": tag_index}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(db, separators=(",", ":")), encoding="utf-8")
    unique_count = sum(len(bucket) for bucket in content.values())
    print(f"Wrote {OUT_PATH} ({len(tag_index)} tags, {unique_count} unique file-contents)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
