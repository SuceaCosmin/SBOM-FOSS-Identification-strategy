"""Build a local reference fingerprint database for lwIP releases.

Tracked files were picked from evidence, not guesswork — two inputs:

  1. **Measured discrimination.** For every candidate core file, the number of distinct
     normalized contents across the 11 tracked releases was counted first (see the
     experiment README's "Picking the tracked files" table). `lwip/init.h` and
     `core/tcp.c` separate 10 of 11 releases; the rest of the set separates 8–9.
  2. **Phase-1 fork diffs.** `lwip/init.h` is the version-macro carrier (and is the file
     Espressif edits — one line, `LWIP_VERSION_RC` → `LWIP_RC_DEVELOPMENT`), so it anchors
     the declared base version even when it no longer exact-matches. `core/pbuf.c` is in
     the set as a file none of the four real forks patched.

This is a deliberately narrow research scope — 7 files out of ~90 `.c`/`.h` files in
`src/` — not a claim that these are *the* minimal signature files for lwIP.

**Tracked files are matched by path suffix, not basename** (see `TRACKED` below). lwIP is
the first component researched here where bare-basename matching is actively wrong: ST's
vendored tree ships its own `system/arch/init.h` port header next to upstream's
`src/include/lwip/init.h`, and upstream itself has both `lwip/init.h` and `core/init.c`.
The suffix keys disambiguate all three.

Mines from a **local git clone** rather than raw.githubusercontent fetches: 7 files ×
~15 release commits is small enough either way, but the clone is ~23 MB and removes the
rate-limit pacing entirely. Same approach as the FreeRTOS port-layer DB.

Usage:
  python build_reference_db.py [--clone <dir>]     # clones if <dir> doesn't exist
Output: reference/lwip_fingerprints.json
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from lwip_fingerprint import fingerprint_source

REPO = "lwip-tcpip/lwip"          # the official GitHub *mirror* of git.savannah.gnu.org
REPO_URL = f"https://github.com/{REPO}.git"
OUT_PATH = Path(__file__).parent / "reference" / "lwip_fingerprints.json"
DEFAULT_CLONE = Path(tempfile.gettempdir()) / "lwip-refdb-clone"

TRACKED = [
    "src/include/lwip/init.h",   # version-macro carrier; top discriminator (10/11)
    "src/core/tcp.c",            # 10/11
    "src/core/tcp_in.c",         # 9/11
    "src/core/init.c",           # 9/11
    "src/api/sockets.c",         # 9/11
    "src/core/pbuf.c",           # 8/11; untouched by all four real forks
    "src/core/udp.c",            # 8/11
]

# The suffix used to locate each tracked file in a target tree. Long enough to be
# unambiguous against vendor port layers that reuse upstream basenames.
SUFFIX = {
    "src/include/lwip/init.h": "lwip/init.h",
    "src/core/tcp.c": "core/tcp.c",
    "src/core/tcp_in.c": "core/tcp_in.c",
    "src/core/init.c": "core/init.c",
    "src/api/sockets.c": "api/sockets.c",
    "src/core/pbuf.c": "core/pbuf.c",
    "src/core/udp.c": "core/udp.c",
}

# Release tags only. lwIP's tag zoo (see the component README) also contains
# release-candidate tags (`..._RC1`), workflow markers (`PRE_ARCH_MOVE`,
# `merged_from_main_to_STABLE`, `start`, `cvs-repository-moved-to-git`) and
# double-tagged releases (`STABLE-2_0_1` *and* `STABLE-2_0_1_RELEASE` on the same commit;
# `STABLE-2_0_2_RELEASE_VER` likewise). The suffix group below accepts the three release
# spellings and rejects the RCs; the by-commit dedup collapses the double tags.
TAG_RE = re.compile(r"^STABLE-(\d+)_(\d+)_(\d+)(?:_RELEASE(?:_VER)?)?$")
# Scope: 1.3.0 and later. Earlier (0.x–1.1.x) predates the current src/ layout and is
# not plausibly in a live firmware tree; excluded rather than silently half-covered.
MIN_VERSION = (1, 3, 0)


def sh(clone: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(clone), *args],
                          capture_output=True, text=True, check=True).stdout


def ensure_clone(clone: Path) -> None:
    if (clone / ".git").exists():
        print(f"Using existing clone at {clone}", file=sys.stderr)
        return
    print(f"Cloning {REPO_URL} (full) -> {clone} …", file=sys.stderr)
    subprocess.run(["git", "clone", "--quiet", REPO_URL, str(clone)], check=True)


def version_of(tag: str):
    m = TAG_RE.match(tag)
    return tuple(int(g) for g in m.groups()[:3]) if m else None


def release_tags(clone: Path) -> dict:
    """tag -> commit SHA, release tags in scope only, deduped by commit."""
    out = {}
    for line in sh(clone, "for-each-ref", "--format=%(refname:short) %(objectname)",
                   "refs/tags").splitlines():
        tag, sha = line.split()
        v = version_of(tag)
        if v and v >= MIN_VERSION:
            # peel annotated tags so double-tagged releases collapse to one commit
            out[tag] = sh(clone, "rev-list", "-n", "1", tag).strip()
    return out


def group_by_commit(sha_by_tag: dict) -> dict:
    groups: dict = {}
    for tag, sha in sha_by_tag.items():
        groups.setdefault(sha, []).append(tag)
    return groups


def read_at(clone: Path, commit: str, path: str):
    r = subprocess.run(["git", "-C", str(clone), "show", f"{commit}:{path}"],
                       capture_output=True, check=False)
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", errors="replace")


def pretty_json(obj, indent: int = 2, level: int = 0) -> str:
    """Pretty-print JSON with the structure indented (one field per line) but *leaf
    arrays* — the winnow-hash integer lists and tag-name string lists — kept inline on a
    single line. Plain `json.dumps(indent=2)` would put every winnowing hash on its own
    line, exploding the file to hundreds of thousands of lines and making it *less*
    readable. Same formatter as the FreeRTOS/Mbed TLS/CMSIS DBs (repo convention: JSON
    checked in here is browsable by humans).
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


def main() -> None:
    clone = DEFAULT_CLONE
    if "--clone" in sys.argv:
        clone = Path(sys.argv[sys.argv.index("--clone") + 1])
    ensure_clone(clone)

    sha_by_tag = release_tags(clone)
    groups = group_by_commit(sha_by_tag)
    print(f"{len(sha_by_tag)} in-scope release tags -> {len(groups)} unique commits "
          f"after dedup", file=sys.stderr)

    content: dict = {f: {} for f in TRACKED}
    tag_index: dict = {}

    for i, (commit, tags) in enumerate(
            sorted(groups.items(), key=lambda kv: version_of(sorted(kv[1])[0])), 1):
        entry = {}
        for path in TRACKED:
            text = read_at(clone, commit, path)
            if text is None:
                continue
            fp = fingerprint_source(text)
            sha = fp["sha256"]
            bucket = content[path]
            if sha in bucket:
                for t in tags:
                    if t not in bucket[sha]["tags"]:
                        bucket[sha]["tags"].append(t)
            else:
                bucket[sha] = {"winnow": fp["winnow"], "tags": list(tags)}
            entry[path] = sha
        if entry:
            for t in tags:
                tag_index[t] = entry
        print(f"[{i}/{len(groups)}] {sorted(tags)}: {len(entry)}/{len(TRACKED)} files",
              file=sys.stderr)

    db = {"repo": REPO, "files": TRACKED, "suffix": SUFFIX,
          "content": content, "tags": tag_index}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(pretty_json(db) + "\n", encoding="utf-8")
    unique = sum(len(b) for b in content.values())
    print(f"Wrote {OUT_PATH} ({len(tag_index)} tags, {unique} unique file-contents, "
          f"{OUT_PATH.stat().st_size / 1024:.0f} KiB)", file=sys.stderr)


if __name__ == "__main__":
    main()
