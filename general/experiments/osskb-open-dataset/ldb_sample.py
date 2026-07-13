"""Random-sample records from a file-url LDB shard and report schema stats."""
import random
import re
import sys
from collections import Counter

from ldb_lookup import PTR, u16, u40

LDB_MAP_SIZE = 256 * 256 * 256 * 5


def sample(shard_path, n_slots=200000, seed=42):
    rng = random.Random(seed)
    recs = []
    keys_with_data = 0
    with open(shard_path, "rb") as f:
        for _ in range(n_slots):
            idx = rng.randrange(256 ** 3)
            f.seek(idx * PTR)
            list_ptr = u40(f.read(PTR))
            if not list_ptr:
                continue
            keys_with_data += 1
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
                    gs = u16(data, p + 12)
                    p += 14
                    end = p + gs
                    while p < end and p + 2 <= len(data):
                        rs = u16(data, p)
                        p += 2
                        recs.append(bytes(data[p:p + rs]))
                        p += rs
                    p = end
                node_ptr = next_node
    return keys_with_data, recs


def main():
    shard = sys.argv[1]
    keys, recs = sample(shard)
    print(f"map slots with lists sampled: {keys}, records collected: {len(recs)}")
    fields_hist = Counter()
    host_hist = Counter()
    counts = []
    multi_url_keys = 0
    non_text = 0
    for r in recs:
        try:
            t = r.decode("utf-8")
        except UnicodeDecodeError:
            non_text += 1
            continue
        parts = t.rsplit(",", 2)  # path may contain commas; url,count are last two
        fields_hist[len(parts)] += 1
        if len(parts) == 3:
            m = re.match(r"https?://([^/]+)/", parts[1])
            host_hist[m.group(1) if m else parts[1][:40]] += 1
            if parts[2].isdigit():
                counts.append(int(parts[2]))
    print(f"non-utf8 records: {non_text}")
    print(f"field-count histogram (rsplit ',' -> path,url,count): {dict(fields_hist)}")
    print("top url hosts:", host_hist.most_common(10))
    if counts:
        counts.sort()
        n = len(counts)
        print(f"count field: n={n} min={counts[0]} p50={counts[n//2]} "
              f"p90={counts[int(n*0.9)]} p99={counts[int(n*0.99)]} max={counts[-1]}")
        ones = sum(1 for c in counts if c == 1)
        print(f"records with count==1: {ones} ({100*ones/n:.1f}%)")


if __name__ == "__main__":
    main()
