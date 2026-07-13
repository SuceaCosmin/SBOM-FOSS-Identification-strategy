"""Minimal read-only LDB shard lookup (SCANOSS osskb-core file-url table).

Format (derived from scanoss/ldb src, GPL-2.0 — this is a clean-room reader of
the on-disk format, no LDB code reused):
  - shard file <XX>.ldb holds all keys whose first byte is 0xXX
  - header map: 256^3 entries of 5-byte little-endian pointers,
    index = key[1]<<16 | key[2]<<8 | key[3], position = index*5
  - map pointer -> list: [LN(5) ptr to last node][node...] ; first node at +5
  - node: [NN(5) next-node ptr, 0=last][TS(2 LE) node data bytes][data]
  - node data (16-byte-key, variable-rec table): repeated groups of
    [subkey(12) = key bytes 4..15][GS(2 LE) group byte size]
    [records: REC_SIZE(2 LE) + payload, GS bytes total incl. size prefixes]
"""
import sys

LDB_MAP_SIZE = 256 * 256 * 256 * 5
PTR = 5


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def u40(b, o=0):
    return int.from_bytes(b[o:o + 5], "little")


def lookup(shard_path, md5hex):
    key = bytes.fromhex(md5hex)
    subkey = key[4:]
    records = []
    with open(shard_path, "rb") as f:
        map_pos = ((key[1] << 16) | (key[2] << 8) | key[3]) * PTR
        f.seek(map_pos)
        list_ptr = u40(f.read(PTR))
        if list_ptr == 0:
            return records
        node_ptr = list_ptr + PTR  # skip LN
        while node_ptr:
            f.seek(node_ptr)
            hdr = f.read(PTR + 2)
            next_node = u40(hdr)
            node_len = u16(hdr, PTR)
            data = f.read(node_len)
            p = 0
            while p + 14 <= len(data):
                sk = data[p:p + 12]
                gs = u16(data, p + 12)
                p += 14
                group_end = p + gs
                if sk == subkey:
                    while p < group_end and p + 2 <= len(data):
                        rs = u16(data, p)
                        p += 2
                        records.append(bytes(data[p:p + rs]))
                        p += rs
                p = group_end
            node_ptr = next_node
    return records


if __name__ == "__main__":
    shard, md5 = sys.argv[1], sys.argv[2]
    recs = lookup(shard, md5)
    print(f"{md5}: {len(recs)} record(s)")
    for i, r in enumerate(recs):
        try:
            txt = r.decode("utf-8")
            print(f"  [{i}] len={len(r)} text: {txt}")
        except UnicodeDecodeError:
            # likely binary prefix (e.g. url md5) + text
            head = r[:16].hex()
            tail = r[16:].decode("utf-8", errors="replace")
            print(f"  [{i}] len={len(r)} bin16={head} text: {tail}")
