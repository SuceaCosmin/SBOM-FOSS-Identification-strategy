"""Build a local reference fingerprint database for zlib releases.

Tracked files were picked from **measured** discrimination plus phase-1 fork evidence,
not guesswork. The measurement (distinct normalized contents across the 55 in-scope
release tags) is in the experiment README's "Picking the tracked files" table. The short
version:

  * `inftrees.c` and `deflate.c` separate **all 55** releases, because each carries a
    version **string literal** (`inflate_copyright` / `deflate_copyright`, e.g.
    `" inflate 1.3.2 Copyright 1995-2026 Mark Adler "`). These are string constants, not
    comments, so they survive `normalize()`'s comment stripping. This is the in-source
    version anchor phase 1 concluded zlib did not have — it does, just not in the header
    the carriers delete.
  * `inftrees.c` is additionally the file real forks barely touch (Chromium: 4 changed
    lines against v1.3.2), so it is both the top discriminator *and* the modification-
    survivor. zlib's equivalent of lwIP's `pbuf.c`, only better.
  * The set is split deliberately across zlib's two halves, because **subset vendoring is
    the normal case** (see the component README §6): `inftrees.c`/`inflate.c`/`inffast.c`/
    `zutil.c` are present even in decompression-only copies, while `deflate.c`/`trees.c`/
    `crc32.c` appear only in fuller ones. A tree matching only the first group is a
    legitimate subset integration, not a weak match.
  * `zlib.h` is tracked to *observe* the declared version, never to rely on it — U-Boot
    and the Linux kernel both ship a zlib without it, and zlib-ng ships a non-zlib with it.

Deliberately narrow research scope — 8 files out of ~30 root sources — not a claim that
these are *the* minimal signature files for zlib.

**Locating tracked files in a target tree.** Unlike lwIP, zlib's upstream layout is
**flat** (every tracked file sits in the repo root), so a path suffix degenerates to a
bare basename and provides no disambiguation at all. U-Boot proves this matters: it ships
two files named `zlib.h` — a 17-line glue shim in `lib/zlib/` and the real merged header
in `include/u-boot/`. The matcher therefore collects **every** candidate per tracked name
and keeps the best-scoring one, rather than trusting a path. See `match_target.py`.

**Tag scope**: `v1.1.3` … `v1.3.2`, 55 tags. zlib's four-component tags (`v1.2.3.4`,
`v1.3.1.2`, …) are *not* junk refs — every one has a dated `ChangeLog` entry, i.e. they
are real development releases, so they are all in scope. `-pre`/`v1.0-pre` style tags are
excluded. 1.1.3 is the floor because the Linux kernel's deflate side declares that base.

Mines from a **local git clone** (~10 MB) rather than raw.githubusercontent fetches —
same approach as the lwIP and FreeRTOS port-layer DBs; removes rate-limit pacing.

Usage:
  python build_reference_db.py [--clone <dir>]     # clones if <dir> doesn't exist
Output: reference/zlib_fingerprints.json
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from zlib_fingerprint import fingerprint_source

REPO = "madler/zlib"
REPO_URL = f"https://github.com/{REPO}.git"
OUT_PATH = Path(__file__).parent / "reference" / "zlib_fingerprints.json"
DEFAULT_CLONE = Path(tempfile.gettempdir()) / "zlib-refdb-clone"

# distinct-contents / 55 tags, measured — see the README table.
TRACKED = [
    "inftrees.c",   # 55/55; carries `inflate_copyright` version string; Chromium touches 4 lines
    "deflate.c",    # 55/55; carries `deflate_copyright` version string; full copies only
    "zlib.h",       # 55/55; declared-version carrier — observed, never relied on
    "inflate.c",    # 27/55; present in every copy including subsets
    "trees.c",      # 21/55; deflate side
    "crc32.c",      # 20/55; gzip/crc side, rewritten at 1.2.12
    "zutil.c",      # 20/55; present in every subset; Chromium touches 1 line
    "inffast.c",    # 15/55; present in every subset
]

# Which half of zlib each tracked file belongs to. A decompression-only integration
# legitimately ships only the `inflate` group; the matcher uses this to distinguish
# "subset integration" from "weak match" instead of applying a flat file-count ratio.
GROUP = {
    "inftrees.c": "inflate",
    "inflate.c": "inflate",
    "inffast.c": "inflate",
    "zutil.c": "inflate",      # shared, but always present in inflate-only copies
    "deflate.c": "deflate",
    "trees.c": "deflate",
    "crc32.c": "optional",     # absent from both U-Boot's and the kernel's inflate-only trees
    "zlib.h": "header",
}

# Real releases only. Accepts v1.1.3 .. v1.3.2 including the four-component development
# releases (each has a dated ChangeLog entry); rejects `-pre`/`-rc` style tags.
TAG_RE = re.compile(r"^v(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?$")
MIN_VERSION = (1, 1, 3, 0)


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
    return tuple(int(g or 0) for g in m.groups()) if m else None


def release_tags(clone: Path) -> dict:
    """tag -> commit SHA, in-scope release tags only (peeled)."""
    out = {}
    for line in sh(clone, "for-each-ref", "--format=%(refname:short)",
                   "refs/tags").splitlines():
        tag = line.strip()
        v = version_of(tag)
        if v and v >= MIN_VERSION:
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
    return None if r.returncode != 0 else r.stdout.decode("utf-8", errors="replace")


def pretty_json(obj, indent: int = 2, level: int = 0) -> str:
    """Structure indented one field per line, but *leaf arrays* (winnow-hash integer
    lists, tag-name lists) kept inline. Plain json.dumps(indent=2) would put every
    winnowing hash on its own line and make the file less readable, not more. Same
    formatter as the FreeRTOS/Mbed TLS/CMSIS/lwIP DBs (repo convention: checked-in JSON
    is browsable by humans).
    """
    pad, pad_in = " " * (indent * level), " " * (indent * (level + 1))
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        body = ",\n".join(f"{pad_in}{json.dumps(k)}: {pretty_json(v, indent, level + 1)}"
                          for k, v in obj.items())
        return "{\n" + body + "\n" + pad + "}"
    if isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
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

    db = {"repo": REPO, "files": TRACKED, "group": GROUP,
          "content": content, "tags": tag_index}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(pretty_json(db) + "\n", encoding="utf-8")
    unique = sum(len(b) for b in content.values())
    print(f"Wrote {OUT_PATH} ({len(tag_index)} tags, {unique} unique file-contents, "
          f"{OUT_PATH.stat().st_size / 1024:.0f} KiB)", file=sys.stderr)


if __name__ == "__main__":
    main()
