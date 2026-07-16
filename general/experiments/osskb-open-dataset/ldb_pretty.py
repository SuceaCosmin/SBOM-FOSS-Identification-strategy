"""Pretty-print a handful of entries from an osskb-core file-url LDB shard.

Two modes:
  - random N entries (reconstructing the full MD5 key each record is filed under)
  - prefix search: find keys whose hex MD5 starts with a given prefix (>= 6 hex chars)

Usage:
  python ldb_pretty.py random <shard.ldb> <n> <seed>
  python ldb_pretty.py prefix <shard.ldb> <md5-hex-prefix, >= 6 hex chars>

Uses the clean-room format reader in this folder (ldb_lookup.py).
"""
import os
import random
import sys

from ldb_lookup import PTR, u16, u40


def walk_slot(f, shard_byte, idx):
    """Yield (full_md5_hex, record_bytes) for every record in one map slot."""
    f.seek(idx * PTR)
    list_ptr = u40(f.read(PTR))
    if not list_ptr:
        return
    key_prefix = bytes([shard_byte, (idx >> 16) & 0xFF, (idx >> 8) & 0xFF, idx & 0xFF])
    node_ptr = list_ptr + PTR
    hops = 0
    while node_ptr and hops < 50:
        hops += 1
        f.seek(node_ptr)
        hdr = f.read(PTR + 2)
        next_node = u40(hdr)
        node_len = u16(hdr, PTR)
        data = f.read(node_len)
        p = 0
        while p + 14 <= len(data):
            subkey = data[p:p + 12]
            gs = u16(data, p + 12)
            p += 14
            end = p + gs
            while p < end and p + 2 <= len(data):
                rs = u16(data, p)
                p += 2
                yield (key_prefix + subkey).hex(), bytes(data[p:p + rs])
                p += rs
            p = end
        node_ptr = next_node


def pretty(md5, rec):
    try:
        txt = rec.decode("utf-8")
    except UnicodeDecodeError:
        print(f"MD5 {md5}: <non-utf8 record, {len(rec)} bytes> {rec[:60].hex()}")
        return
    path, url, count = txt.rsplit(",", 2)
    print(f"file MD5 : {md5}")
    print(f"  path   : {path}")
    print(f"  url    : {url}")
    print(f"  count  : {count} (number of URLs in the full KB containing this file)")
    print()


def random_entries(shard_path, n, seed):
    shard_byte = int(os.path.basename(shard_path)[:2], 16)
    rng = random.Random(seed)
    shown = 0
    with open(shard_path, "rb") as f:
        while shown < n:
            for md5, rec in walk_slot(f, shard_byte, rng.randrange(256 ** 3)):
                pretty(md5, rec)
                shown += 1
                if shown >= n:
                    break


def prefix_search(shard_path, prefix_hex):
    shard_byte = int(prefix_hex[:2], 16)
    b1, b2 = int(prefix_hex[2:4], 16), int(prefix_hex[4:6], 16)
    with open(shard_path, "rb") as f:
        for b3 in range(256):
            idx = (b1 << 16) | (b2 << 8) | b3
            for md5, rec in walk_slot(f, shard_byte, idx):
                if md5.startswith(prefix_hex.lower()):
                    pretty(md5, rec)


if __name__ == "__main__":
    if sys.argv[1] == "random":
        random_entries(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:  # prefix <shard> <hexprefix>
        prefix_search(sys.argv[2], sys.argv[3])
