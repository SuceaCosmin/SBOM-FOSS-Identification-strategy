"""Lightweight-export prototype: walk a self-mined SCANOSS LDB KB and emit a
compact, scanner-embeddable identification artifact (gzipped JSON).

Clean-room LDB traversal (same on-disk format knowledge as
general/experiments/osskb-open-dataset/{ldb_lookup,wfp_lookup}.py — no LDB code
reused, so no GPL entanglement in the export path or the artifact).

Exported per KB:
  releases: url-id -> declared -d metadata (vendor, component, version, date,
            license, purl, source URL)          [url table]
  files:    file-md5 -> {release url-ids, exemplar path}   [file table]
  wfp:      32-bit winnowing hash -> [[file-md5, line], ...]  [wfp table]

Deliberately NOT exported: sources (evidence tier stays in the full KB),
license/copyright/quality detections (available on demand from the full KB).

Usage (host, docker volume mounted):
  docker run --rm -v scanoss-ldb:/var/lib/ldb:ro -v <repo>:/repo python:3.12-slim \
      python /repo/general/experiments/minr-self-mining/export_lightweight.py \
      /var/lib/ldb/oss /repo/general/experiments/minr-self-mining/results/export.json.gz
"""
import gzip
import json
import re
import sys
import time
from pathlib import Path

PTR = 5
MAP_SLOTS = 256 * 256 * 256
NONZERO = re.compile(rb"[^\x00]")


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def u40(b, o=0):
    return int.from_bytes(b[o:o + 5], "little")


def occupied_slots(map_bytes):
    """Slot indices with a nonzero 5-byte pointer. The maps are ~99.97% zeros,
    so scan for nonzero bytes (C-speed) and dedupe to slots instead of
    iterating 16.7M slots in Python."""
    return sorted({m.start() // PTR for m in NONZERO.finditer(map_bytes)})


def walk_shard(path, fixed_rec_len=None):
    """Yield (map_index, node_data_groups) for every occupied slot of one shard.

    For variable tables (16-byte keys) yields (idx, [(subkey12, [record, ...])]).
    For fixed tables (4-byte keys, e.g. wfp) yields (idx, [(None, [record, ...])]).
    """
    with open(path, "rb") as f:
        map_bytes = f.read(MAP_SLOTS * PTR)
        for idx in occupied_slots(map_bytes):
            list_ptr = u40(map_bytes, idx * PTR)
            if list_ptr == 0:
                continue
            groups = {}
            node_ptr = list_ptr + PTR  # skip LN (ptr to last node)
            while node_ptr:
                f.seek(node_ptr)
                hdr = f.read(PTR + 2)
                next_node = u40(hdr)
                if fixed_rec_len:
                    n = u16(hdr, PTR)  # record COUNT for fixed-length tables
                    data = f.read(n * fixed_rec_len)
                    recs = groups.setdefault(None, [])
                    for r in range(0, len(data), fixed_rec_len):
                        recs.append(bytes(data[r:r + fixed_rec_len]))
                else:
                    node_len = u16(hdr, PTR)  # byte size for variable tables
                    data = f.read(node_len)
                    p = 0
                    while p + 14 <= len(data):
                        sk = bytes(data[p:p + 12])
                        gs = u16(data, p + 12)
                        p += 14
                        end = p + gs
                        recs = groups.setdefault(sk, [])
                        while p < end and p + 2 <= len(data):
                            rs = u16(data, p)
                            p += 2
                            recs.append(bytes(data[p:p + rs]))
                            p += rs
                        p = end
                node_ptr = next_node
            yield idx, groups


def walk_table(table_dir, fixed_rec_len=None):
    """Yield (key_hex, [record, ...]) across all shard files of a table."""
    for shard_path in sorted(Path(table_dir).glob("*.ldb")):
        shard_byte = int(shard_path.stem, 16)
        for idx, groups in walk_shard(shard_path, fixed_rec_len):
            prefix = bytes([shard_byte, idx >> 16, (idx >> 8) & 0xFF, idx & 0xFF])
            for subkey, recs in groups.items():
                key = prefix + (subkey or b"")
                yield key.hex(), recs


def main():
    kb_dir, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    t0 = time.time()

    releases = {}
    for key, recs in walk_table(kb_dir / "url"):
        # record: vendor,component,version,date,license,purl,url (CSV text)
        fields = recs[0].decode("utf-8", errors="replace").split(",")
        releases[key] = dict(zip(
            ["vendor", "component", "version", "date", "license", "purl", "url"],
            fields))

    files = {}
    for key, recs in walk_table(kb_dir / "file"):
        rel_ids, path = [], None
        for r in recs:
            rel_ids.append(r[:16].hex())
            path = path or r[16:].decode("utf-8", errors="replace")
        files[key] = {"releases": sorted(set(rel_ids)), "path": path}

    wfp = {}
    for key, recs in walk_table(kb_dir / "wfp", fixed_rec_len=18):
        wfp[key] = [[r[:16].hex(), u16(r, 16)] for r in recs]

    artifact = {
        "generated": time.strftime("%Y-%m-%d"),
        "source_kb": str(kb_dir),
        "releases": releases,
        "files": files,
        "wfp": wfp,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8") as f:
        json.dump(artifact, f, separators=(",", ":"))

    print(f"releases: {len(releases)}  files: {len(files)}  wfp keys: {len(wfp)}")
    print(f"artifact: {out_path} ({out_path.stat().st_size / 1e6:.1f} MB gz)")
    print(f"elapsed: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
