"""End-to-end offline snippet-match demo:
  modified file -> local winnowing hashes (scanoss-py .wfp)
  -> wfp shard lookup (hash -> [file md5, line] records)
  -> vote: which file md5s co-occur across the most snippet hashes
  -> resolve votable md5s via downloaded file-url shards (path, url, count)

Usage:
  python wfp_pipeline.py <wfp-shard.ldb> <file.wfp> <file-url-shard-dir>

The wfp shard filename must end in <XX>.ldb (its shard byte); the file-url
directory is scanned for <XX>.ldb shards. Only snippet hashes whose first
byte matches the wfp shard can be looked up, and only md5s whose first byte
matches a present file-url shard can be resolved -- a full deployment would
have all 256 of each (97 GiB file-url + 1.14 TiB wfp).
"""
import os
import re
import sys
from collections import Counter

import ldb_lookup as fileurl
from wfp_lookup import lookup as wfp_lookup, parse_wfp


def main(wfp_shard, wfp_file, fileurl_dir, top_n=12):
    shard_byte = int(re.search(r"([0-9a-fA-F]{2})\.ldb$",
                               os.path.basename(wfp_shard)).group(1), 16)
    fileurl_shards = {
        int(m.group(1), 16): os.path.join(fileurl_dir, fn)
        for fn in os.listdir(fileurl_dir)
        if (m := re.fullmatch(r"([0-9a-fA-F]{2})\.ldb", fn))
    }
    file_md5, hashes = parse_wfp(wfp_file)
    mine = sorted(h for h in hashes if int(h[:2], 16) == shard_byte)
    print(f"{wfp_file}\n  md5 {file_md5}, {len(hashes)} snippet hashes, "
          f"{len(mine)} usable with wfp shard {shard_byte:02x}\n")
    votes = Counter()   # md5 -> number of distinct snippet hashes containing it
    with open(wfp_shard, "rb") as f:
        for h in mine:
            recs = wfp_lookup(f, bytes.fromhex(h))
            for m in {r[:16].hex() for r in recs}:
                votes[m] += 1
    print(f"distinct candidate file md5s: {len(votes)}")
    print(f"vote distribution: {Counter(votes.values())}\n")
    print(f"top {top_n} candidates by vote (votes/{len(mine)} possible):")
    for m, v in votes.most_common(top_n):
        line = f"  {v:2d}  {m}"
        b0 = int(m[:2], 16)
        if b0 in fileurl_shards:
            recs = fileurl.lookup(fileurl_shards[b0], m)
            if recs:
                path, url, count = recs[0].decode("utf-8", "replace").rsplit(",", 2)
                line += f"\n      -> {path}\n         {url} (count {count})"
            else:
                line += "\n      -> (not in file-url snapshot)"
        else:
            line += "   (no file-url shard for this byte downloaded)"
        print(line)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
