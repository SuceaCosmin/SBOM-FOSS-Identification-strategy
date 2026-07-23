"""Build a local reference fingerprint database for Mbed-TLS/mbedtls releases,
covering five files chosen from real vendor diffs (see ../../README.md section 3):
include/mbedtls/version.h (untouched by every vendor checked - the version anchor),
library/bignum.c and library/ecp.c (patched in place by Espressif's ESP-IDF fork and
NXP's fork for hardware-accelerated bignum/ECC), and library/aes.c and library/ecdsa.c
(patched in place by NXP for hardware AES, and by STMicroelectronics for a
double-signature-check feature and a license-header-only edit respectively).

Scope: tags matching mbedtls-X.Y.Z or vX.Y.Z with major version 2 or 3 only.
- 1.3.x (PolarSSL-era, pre-Apache/GPL dual license, pre-rebrand) is a different era -
  see README.md section 1 - and out of scope for this pass.
- 4.0+ moves bignum.c/ecp.c/aes.c/ecdsa.c out of this repo into the separate
  TF-PSA-Crypto repo (README.md section 2) - tracking that split needs its own
  reference DB and is deferred, not done here.
Many releases are tagged twice (an old "mbedtls-X.Y.Z" name and a newer "vX.Y.Z" name
pointing at the identical commit) - these are deduplicated by commit SHA (from
`git ls-remote`, before any HTTP fetch) rather than relying on content-hash dedup after
the fact, since fetching the same commit's files twice would be pure waste at this
tag count (500+ total tags on this repo, vs. FreeRTOS-Kernel's 58).

Usage: python build_reference_db.py
Output: reference/mbedtls_fingerprints.json
"""

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from mbedtls_fingerprint import fingerprint_source


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


REPO = "Mbed-TLS/mbedtls"
FILES = [
    "include/mbedtls/version.h",
    "library/bignum.c",
    "library/ecp.c",
    "library/aes.c",
    "library/ecdsa.c",
]
OUT_PATH = Path(__file__).parent / "reference" / "mbedtls_fingerprints.json"

TAG_RE = re.compile(r"^(?:mbedtls-)?v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$")


def list_tags_with_commits() -> dict:
    """Tag name -> commit SHA, using the peeled (^{}) SHA for annotated tags so two
    tag names pointing at the same commit are recognized as duplicates before any
    file is fetched."""
    result = subprocess.run(
        ["git", "ls-remote", "--tags", f"https://github.com/{REPO}.git"],
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


def in_scope(tag: str) -> bool:
    m = TAG_RE.match(tag)
    return bool(m) and int(m.group(1)) in (2, 3)


def group_by_commit(sha_by_tag: dict) -> dict:
    groups: dict = {}
    for tag, sha in sha_by_tag.items():
        if in_scope(tag):
            groups.setdefault(sha, []).append(tag)
    return groups


REQUEST_DELAY_SECONDS = 0.3  # raw.githubusercontent.com rate-limits unauthenticated
                              # bursts (HTTP 429) well under this repo's ~580-request
                              # fetch volume (116 commits x 5 files) without pacing.


def fetch_file(commit: str, filename: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{REPO}/{commit}/{filename}"
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
    sha_by_tag = list_tags_with_commits()
    groups = group_by_commit(sha_by_tag)
    print(f"Found {len(sha_by_tag)} tags total on {REPO}, "
          f"{sum(len(v) for v in groups.values())} in-scope (2.x/3.x), "
          f"{len(groups)} unique commits after dedup", file=sys.stderr)

    # content[filename][sha256] = {"winnow": [...], "tags": [...]} - dedup by content
    # in addition to the by-commit dedup above, since a patch/rc release can still
    # leave a given file byte-identical to a prior release even on a different commit.
    content: dict = {f: {} for f in FILES}
    tag_index: dict = {}

    for i, (commit, tags) in enumerate(sorted(groups.items(), key=lambda kv: sorted(kv[1])[0]), 1):
        entry = {}
        for filename in FILES:
            text = fetch_file(commit, filename)
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
                tag_index[t] = entry
        rep_tag = sorted(tags)[0]
        print(f"[{i}/{len(groups)}] {rep_tag} ({len(tags)} alias(es)): "
              f"{sorted(entry.keys())}", file=sys.stderr)

    db = {"repo": REPO, "files": FILES, "content": content, "tags": tag_index}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(pretty_json(db) + "\n", encoding="utf-8")
    unique_count = sum(len(bucket) for bucket in content.values())
    print(f"Wrote {OUT_PATH} ({len(tag_index)} tags, {unique_count} unique file-contents)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
