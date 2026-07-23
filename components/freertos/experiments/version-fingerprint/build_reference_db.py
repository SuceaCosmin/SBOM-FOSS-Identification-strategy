"""Build a local reference fingerprint database for every tagged release of
FreeRTOS/FreeRTOS-Kernel, covering all seven core kernel `.c` files at the repo root.
Fetches file content over HTTPS from raw.githubusercontent.com per tag — no full git
clone needed.

`FILES` are every core source file we fingerprint. `ANCHORS` is the subset that
essentially always ships in any real kernel integration (tasks/queue/list); the matcher
uses the anchors to confirm the kernel is present, and folds every *other* present file
into the cross-file version-consistency check. The non-anchor files (timers,
event_groups, stream_buffer, croutine) are optional/feature-gated — croutine in
particular is legacy and frequently omitted — so they must not be treated as required.

Note: this file set is still source-level only. It does **not** cover the
`portable/<compiler>/<arch>/port.c` + `mpu_wrappers` layer, which is where
architecture/MPU vulnerabilities (e.g. CVE-2024-28115) actually live; see the README's
"minimal for POC" note.

Usage: python build_reference_db.py
Output: reference/kernel_fingerprints.json
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from freertos_fingerprint import fingerprint_source

REPO = "FreeRTOS/FreeRTOS-Kernel"
FILES = ["tasks.c", "queue.c", "list.c", "timers.c", "event_groups.c",
         "stream_buffer.c", "croutine.c"]
ANCHORS = ["tasks.c", "queue.c", "list.c"]
OUT_PATH = Path(__file__).parent / "reference" / "kernel_fingerprints.json"


def pretty_json(obj, indent: int = 2, level: int = 0) -> str:
    """Pretty-print JSON with the structure indented (one field per line) but *leaf
    arrays* — lists containing no nested objects/arrays, i.e. the winnow-hash integer
    lists and tag-name string lists — kept inline on a single line. Plain
    `json.dumps(indent=2)` would put every winnowing hash on its own line, exploding the
    file to hundreds of thousands of lines and making it *less* readable, not more. This
    keeps the browsable structure while leaving the opaque hash arrays as one line each.
    """
    pad, pad_in = " " * (indent * level), " " * (indent * (level + 1))
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        body = ",\n".join(f"{pad_in}{json.dumps(k)}: {pretty_json(v, indent, level + 1)}"
                          for k, v in obj.items())
        return "{\n" + body + "\n" + pad + "}"
    if isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):   # leaf array → inline
            return json.dumps(obj)
        body = ",\n".join(f"{pad_in}{pretty_json(x, indent, level + 1)}" for x in obj)
        return "[\n" + body + "\n" + pad + "]"
    return json.dumps(obj)


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


def fetch_file(tag: str, filename: str, retries: int = 4) -> str | None:
    for template in CANDIDATE_PATH_TEMPLATES:
        path = template.format(filename=filename)
        url = f"https://raw.githubusercontent.com/{REPO}/{tag}/{path}"
        # 404 → this file isn't at this path for this tag: try the next template.
        # Transient network errors (read timeout, connection reset, 5xx) → retry with
        # backoff. With ~400 fetches, a hard-fail on the first blip would waste the
        # whole run, so tolerate blips but still surface a persistent failure.
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    break            # not at this path — next template
                if e.code < 500 or attempt == retries - 1:
                    raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == retries - 1:
                    raise
            time.sleep(2 * (attempt + 1))
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

    db = {"repo": REPO, "files": FILES, "anchors": ANCHORS,
          "content": content, "tags": tag_index}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(pretty_json(db) + "\n", encoding="utf-8")
    unique_count = sum(len(bucket) for bucket in content.values())
    print(f"Wrote {OUT_PATH} ({len(tag_index)} tags, {unique_count} unique file-contents)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
