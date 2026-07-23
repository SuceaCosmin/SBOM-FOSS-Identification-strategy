"""Build a local reference fingerprint database for CMSIS-Core, covering four files
from CMSIS/Core/Include/ (see ../../README.md sections 3 and 7):
cmsis_version.h (the version-macro anchor - confirmed byte-identical to upstream in
both real vendor forks diffed this session, ST and NXP), and three core_cm*.h variants
spanning the Cortex-M profile's age range: core_cm0.h (Armv6-M baseline), core_cm4.h
(the mainstream Armv7-M core, the one actually diffed against a real ST fork in Phase 1),
and core_cm33.h (Armv8-M mainline/TrustZone, the newer profile used by e.g. Renesas RA).

CMSIS-Core's history is split across two repos with a real governance break, not just a
rename (see ../../README.md section 1):
- ARM-software/CMSIS_5 - archived, last tag 5.9.0. Covers the whole CMSIS v5 era.
- ARM-software/CMSIS_6 - active, tags start at v6.0.0. CMSIS v6 era.
Both keep files at the identical repo-relative path (CMSIS/Core/Include/<file>),
confirmed directly this session at every tag fetched below, so this script queries both
repos and merges their release tags into one reference DB.

Scope: "clean" release tags only, anchored full-string match so pre-release / dev /
rc / beta suffixes are automatically excluded (e.g. "5.8.0-rc", "5.2.1-dev3",
"v6.3.0-dev", "v6.3.1-dev" are NOT in scope) - along with one stray non-release tag
found on CMSIS_5 ("NN/2.0.0", an artifact of CMSIS-NN's pre-split history living inside
this repo's tag namespace before CMSIS-NN moved to its own repo in 2022 - see
../../README.md section 2). cmsis_version.h does not exist before CMSIS_5 tag 5.1.0
(confirmed this session - 5.0.0/5.0.1 predate it), so those two releases will have no
cmsis_version.h entry; this is a real, small scope boundary, not a bug.

Total in-scope releases: 13 on CMSIS_5 (5.0.0 through 5.9.0) + 4 on CMSIS_6 (v6.0.0
through v6.3.0) = 17 releases, ~64 fetches (some skipped for the cmsis_version.h gap
above) - far smaller than FreeRTOS-Kernel's 58 tags or Mbed TLS's 116 unique commits,
since CMSIS_6 is young and CMSIS_5's own tag history (unlike mbedTLS's 500+ tags) was
never double-tagged under two naming schemes.

Usage: python build_reference_db.py
Output: reference/cmsis_fingerprints.json
"""

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cmsis_fingerprint import fingerprint_source


def pretty_json(obj, indent: int = 2, level: int = 0) -> str:
    """Pretty-print JSON with the structure indented (one field per line) but *leaf
    arrays* (the winnow-hash integer lists, tag-name string lists) kept inline on one
    line each. Plain `json.dumps(indent=2)` would put every winnowing hash on its own
    line — hundreds of thousands of lines, less readable, not more. Keeps the browsable
    structure while leaving opaque hash arrays as one line each."""
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


REPOS = [
    {"repo": "ARM-software/CMSIS_5", "tag_re": re.compile(r"^(\d+)\.(\d+)\.(\d+)$")},
    {"repo": "ARM-software/CMSIS_6", "tag_re": re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")},
]
FILES = [
    "CMSIS/Core/Include/cmsis_version.h",
    "CMSIS/Core/Include/core_cm0.h",
    "CMSIS/Core/Include/core_cm4.h",
    "CMSIS/Core/Include/core_cm33.h",
]
OUT_PATH = Path(__file__).parent / "reference" / "cmsis_fingerprints.json"

REQUEST_DELAY_SECONDS = 0.3  # raw.githubusercontent.com rate-limits unauthenticated
                              # bursts (HTTP 429) - see general/README.md pitfalls.


def list_tags_with_commits(repo: str) -> dict:
    """Tag name -> commit SHA, using the peeled (^{}) SHA for annotated tags so two
    tag names pointing at the same commit are recognized as duplicates before any
    file is fetched (not currently observed on either CMSIS repo, unlike mbedTLS's
    mbedtls-X.Y.Z/vX.Y.Z double-tagging, but kept for consistency with the other two
    experiments and as a safety net if it starts happening)."""
    result = subprocess.run(
        ["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"],
        capture_output=True, text=True, check=True,
    )
    sha_by_tag: dict = {}
    peeled: set = set()
    for line in result.stdout.splitlines():
        sha, ref = line.split("\t")
        name = ref.split("refs/tags/", 1)[1]
        if name.endswith("^{}"):
            base = name[:-3]
            sha_by_tag[base] = sha
            peeled.add(base)
        elif name not in peeled:
            sha_by_tag[name] = sha
    return sha_by_tag


def fetch_file(repo: str, commit: str, filename: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{filename}"
    for attempt in range(6):
        try:
            time.sleep(REQUEST_DELAY_SECONDS)
            with urllib.request.urlopen(url, timeout=15) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429 and attempt < 5:
                backoff = 5 * (attempt + 1)
                print(f"  429 rate-limited, backing off {backoff}s...", file=sys.stderr)
                time.sleep(backoff)
                continue
            raise
    raise RuntimeError(f"Exceeded retries fetching {url}")


def main() -> None:
    # content[filename][sha256] = {"winnow": [...], "tags": [...]} - dedup by content,
    # since a patch release can leave a file byte-identical to a prior release.
    content: dict = {f: {} for f in FILES}
    tag_index: dict = {}
    all_groups = []

    for repo_cfg in REPOS:
        repo = repo_cfg["repo"]
        tag_re = repo_cfg["tag_re"]
        sha_by_tag = list_tags_with_commits(repo)
        groups: dict = {}
        for tag, sha in sha_by_tag.items():
            if tag_re.match(tag):
                groups.setdefault(sha, []).append(tag)
        in_scope_tags = sum(len(v) for v in groups.values())
        print(f"{repo}: {len(sha_by_tag)} tags total, {in_scope_tags} in-scope release "
              f"tags, {len(groups)} unique commits", file=sys.stderr)
        all_groups.append((repo, groups))

    total_commits = sum(len(g) for _, g in all_groups)
    done = 0
    for repo, groups in all_groups:
        for commit, tags in sorted(groups.items(), key=lambda kv: sorted(kv[1])[0]):
            done += 1
            entry = {}
            for filename in FILES:
                text = fetch_file(repo, commit, filename)
                if text is None:
                    continue
                fp = fingerprint_source(text)
                sha = fp["sha256"]
                bucket = content[filename]
                if sha in bucket:
                    for t in tags:
                        if t not in bucket[sha]["tags"]:
                            bucket[sha]["tags"].append(t)
                else:
                    bucket[sha] = {"winnow": fp["winnow"], "tags": list(tags)}
                entry[filename] = sha
            if entry:
                for t in tags:
                    tag_index[t] = {"repo": repo, "files": entry}
            rep_tag = sorted(tags)[0]
            print(f"[{done}/{total_commits}] {repo}@{rep_tag}: {sorted(entry.keys())}",
                  file=sys.stderr)

    db = {"repos": [r["repo"] for r in REPOS], "files": FILES, "content": content,
          "tags": tag_index}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(pretty_json(db) + "\n", encoding="utf-8")
    unique_count = sum(len(bucket) for bucket in content.values())
    print(f"Wrote {OUT_PATH} ({len(tag_index)} tags, {unique_count} unique file-contents)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
