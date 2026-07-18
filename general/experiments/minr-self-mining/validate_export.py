"""Validate the lightweight export: reproduce the baseline corpus results with
ONLY the export artifact (export.json.gz) — no LDB, no engine, no GPL code.

Tiers per target file:
  1. exact:   raw MD5 -> export.files -> full containing-release set
  2. snippet: scanoss-py-generated winnowing hashes -> export.wfp voting ->
              top candidate file md5 -> its containing-release set

Tree verdict (ports the bespoke matchers' cross-file consistency check):
  intersect the release sets of all matched files ->
    non-empty  -> CONSISTENT with the common release(s) (verbatim or coherent tree)
    empty      -> MIXED VERSION WARNING with per-file version evidence

Usage:
  python validate_export.py <export.json.gz> <target-dir> [<target-dir> ...]
(scanoss-py must be on PATH; it generates the .wfp fingerprints per tree.)
"""
import gzip
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


def load_export(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def parse_multi_wfp(text):
    """scanoss-py .wfp -> {path: (md5_hex, {hash_hex: [line, ...]})}"""
    out, path, md5, hashes = {}, None, None, None
    for line in text.splitlines():
        if line.startswith("file="):
            if path is not None:
                out[path] = (md5, hashes)
            md5, _size, path = line[5:].split(",", 2)
            hashes = {}
        elif "=" in line and hashes is not None:
            lineno, hs = line.split("=", 1)
            if lineno.isdigit():
                for h in hs.split(","):
                    hashes.setdefault(h.zfill(8), []).append(int(lineno))
    if path is not None:
        out[path] = (md5, hashes)
    return out


def wfp_for_dir(target_dir):
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "t.wfp"
        subprocess.run(["scanoss-py", "wfp", str(target_dir), "-o", str(out)],
                       check=True, capture_output=True)
        return parse_multi_wfp(out.read_text(encoding="utf-8"))


def match_file(export, path, md5, snippet_hashes):
    """Returns (tier, release_ids, detail) or (None, [], reason)."""
    entry = export["files"].get(md5)
    if entry:
        return "exact", entry["releases"], "100%"
    votes, usable = Counter(), 0
    for h in snippet_hashes:
        recs = export["wfp"].get(h)
        if not recs:
            continue
        usable += 1
        for m in {r[0] for r in recs}:
            votes[m] += 1
    if not votes or usable < 5:
        return None, [], f"no match ({usable} usable snippet hashes)"
    top_md5, top_votes = votes.most_common(1)[0]
    ratio = top_votes / len(snippet_hashes)
    if ratio < 0.5:
        return None, [], f"best candidate only {ratio:.0%} of snippets"
    entry = export["files"].get(top_md5)
    rel = entry["releases"] if entry else []
    return "snippet", rel, f"{ratio:.0%} of {len(snippet_hashes)} snippets -> {entry['path'] if entry else top_md5}"


def versions_of(export, release_ids):
    return sorted({export["releases"][r]["version"]
                   for r in release_ids if r in export["releases"]})


def scan_tree(export, target_dir):
    print(f"\n=== {target_dir}")
    wfps = wfp_for_dir(target_dir)
    per_file, release_sets = [], []
    for path, (md5, hashes) in sorted(wfps.items()):
        tier, rel, detail = match_file(export, path, md5, hashes)
        name = Path(path).name
        if tier is None:
            print(f"  {name:18} NO MATCH   {detail}")
            continue
        vers = versions_of(export, rel)
        purls = sorted({export["releases"][r]["purl"] for r in rel})
        lics = sorted({export["releases"][r]["license"] for r in rel})
        print(f"  {name:18} {tier:8} versions={','.join(vers)} "
              f"purl={','.join(purls)} lic={','.join(lics)} ({detail})")
        per_file.append((name, vers))
        release_sets.append(set(rel))
    if not release_sets:
        print("  VERDICT: NOT IDENTIFIED (no component evidence)")
        return
    common = set.intersection(*release_sets)
    if common:
        vers = versions_of(export, common)
        print(f"  VERDICT: CONSISTENT — all files coexist in release(s): {', '.join(vers)}")
    else:
        print("  VERDICT: MIXED VERSION WARNING — no single release contains all files:")
        for name, vers in per_file:
            print(f"    {name}: {','.join(vers)}")


def main():
    export = load_export(sys.argv[1])
    for target in sys.argv[2:]:
        scan_tree(export, target)


if __name__ == "__main__":
    main()
