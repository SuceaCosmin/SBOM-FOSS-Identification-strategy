"""Clean-room reader for the osskb-core `wfp` LDB table (winnowing fingerprints).

wfp.cfg = 4,18,1,0 -> 4-byte keys (32-bit winnowing snippet hash),
fixed 18-byte records. Key byte 0 selects the shard file; key bytes 1-3 form
the header-map index, so the whole key is consumed by (shard, map slot):
every map slot holds records for exactly one key, and node data carries no
subkey. Record layout is verified empirically by the `check` mode below
(hypothesis: 16-byte file MD5 + 2-byte little-endian line number).

Usage:
  python wfp_lookup.py lookup <shard.ldb> <hash-8hex>       one key, dump records
  python wfp_lookup.py check  <shard.ldb> <file.wfp> [max]  cross-check a local
        scanoss-py .wfp fingerprint file against the shard: for every snippet
        hash whose first byte matches the shard, report whether the expected
        file MD5 appears among the returned records and at which line.
"""
import os
import re
import sys

PTR = 5


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def u40(b, o=0):
    return int.from_bytes(b[o:o + 5], "little")


def lookup(f, key):
    """key: 4 bytes. Returns list of raw 18-byte records (may be huge)."""
    records = []
    map_pos = ((key[1] << 16) | (key[2] << 8) | key[3]) * PTR
    f.seek(map_pos)
    list_ptr = u40(f.read(PTR))
    if list_ptr == 0:
        return records
    node_ptr = list_ptr + PTR  # skip LN (ptr to last node)
    while node_ptr:
        f.seek(node_ptr)
        hdr = f.read(PTR + 2)
        next_node = u40(hdr)
        # fixed-length-record table: the 2-byte node size field counts
        # RECORDS (not bytes); data is raw concatenated 18-byte records,
        # no subkey (key_ln == 4 is fully consumed by shard + map index),
        # no group headers, no per-record size prefixes.
        n_recs = u16(hdr, PTR)
        data = f.read(n_recs * 18)
        for r in range(0, len(data), 18):
            records.append(bytes(data[r:r + 18]))
        node_ptr = next_node
    return records


def parse_wfp(path):
    """Parse a scanoss-py .wfp file -> (file_md5_hex, {hash_hex: [line, ...]})."""
    md5 = None
    hashes = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("file="):
                md5 = line.split("=", 1)[1].split(",")[0]
            elif "=" in line and line[0].isdigit():
                lineno, rest = line.split("=", 1)
                for h in rest.split(","):
                    hashes.setdefault(h.lower(), []).append(int(lineno))
    return md5, hashes


def cmd_lookup(shard, hash_hex, limit=20):
    with open(shard, "rb") as f:
        recs = lookup(f, bytes.fromhex(hash_hex))
    print(f"hash {hash_hex}: {len(recs)} record(s)")
    for r in recs[:limit]:
        md5, tail = r[:16].hex(), r[16:]
        print(f"  md5={md5} tail_le={u16(tail, 0)} tail_hex={tail.hex()}")
    if len(recs) > limit:
        print(f"  ... {len(recs) - limit} more")


def cmd_check(shard, wfp_path, max_keys=None):
    file_md5, hashes = parse_wfp(wfp_path)
    shard_byte = int(re.search(r"([0-9a-fA-F]{2})\.ldb$",
                               os.path.basename(shard)).group(1), 16)
    mine = {h: ln for h, ln in hashes.items() if int(h[:2], 16) == shard_byte}
    print(f"{wfp_path}: file md5 {file_md5}, {len(hashes)} distinct hashes, "
          f"{len(mine)} in shard {shard_byte:02x}")
    found = miss = md5hit = 0
    line_le = line_be = 0
    rec_counts = []
    with open(shard, "rb") as f:
        for i, (h, lines) in enumerate(sorted(mine.items())):
            if max_keys and i >= max_keys:
                break
            recs = lookup(f, bytes.fromhex(h))
            if not recs:
                miss += 1
                continue
            found += 1
            rec_counts.append(len(recs))
            hit = [r for r in recs if r[:16].hex() == file_md5]
            if hit:
                md5hit += 1
                if any(u16(r[16:], 0) in lines for r in hit):
                    line_le += 1
                if any((r[16] << 8 | r[17]) in lines for r in hit):
                    line_be += 1
    checked = found + miss
    print(f"checked {checked} keys: {found} present in shard, {miss} absent")
    if rec_counts:
        rec_counts.sort()
        n = len(rec_counts)
        print(f"records per present key: min={rec_counts[0]} "
              f"p50={rec_counts[n // 2]} p90={rec_counts[int(n * .9)]} "
              f"max={rec_counts[-1]}")
    print(f"keys whose records include this exact file's md5: {md5hit}")
    print(f"  ...of those, tail == a .wfp line number: LE {line_le}, BE {line_be}")


if __name__ == "__main__":
    if sys.argv[1] == "lookup":
        cmd_lookup(sys.argv[2], sys.argv[3])
    else:
        cmd_check(sys.argv[2], sys.argv[3],
                  int(sys.argv[4]) if len(sys.argv) > 4 else None)
