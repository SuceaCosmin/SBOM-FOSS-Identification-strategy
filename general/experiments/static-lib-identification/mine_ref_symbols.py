#!/usr/bin/env python3
"""Mine per-release reference symbol sets for a component from its source repo.

For each git tag, checks out the tag and extracts candidate external function
names from the component's public/internal headers by prototype-pattern
matching (comment- and preprocessor-stripped). No compilation involved — the
point of the experiment is that reference sets can be mined from source the
same way the minr pipeline mines file hashes.

Usage example:
  python mine_ref_symbols.py --repo /path/to/nanopb \\
      --tags 0.3.9.3 0.4.0 ... \\
      --headers "pb.h" "pb_encode.h" "pb_decode.h" "pb_common.h" \\
      --prefix "pb_" --out nanopb_ref_symbols.json

Output JSON: {component_meta, releases: {tag: sorted symbol list}}.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys


def strip_comments_and_directives(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    # drop preprocessor lines (incl. line continuations) so macro definitions
    # and macro bodies don't contribute candidate names
    text = re.sub(r"(?m)^[ \t]*#(?:[^\n\\]|\\\n)*(?:\\\n(?:[^\n\\]|\\\n)*)*", " ", text)
    return text


def extract_prototypes(text, prefix_re):
    """Names that appear in function-prototype position: a type-ish token
    sequence followed by <prefix><name>( — filters out plain call sites by
    requiring the preceding token not to be ( , = or an operator."""
    names = set()
    pat = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*[\s\*]+((?:" + prefix_re + r")[A-Za-z0-9_]*)\s*\(")
    for m in pat.finditer(text):
        names.add(m.group(1))
    return names


def mine_tag(repo, tag, header_globs, prefix_re):
    subprocess.run(["git", "-C", repo, "checkout", "-q", "--force", tag],
                   check=True)
    syms = set()
    seen_files = []
    for hg in header_globs:
        for path in glob.glob(os.path.join(repo, hg), recursive=True):
            seen_files.append(os.path.relpath(path, repo))
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = strip_comments_and_directives(f.read())
            syms |= extract_prototypes(text, prefix_re)
    return syms, seen_files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--tags", nargs="+", required=True)
    ap.add_argument("--headers", nargs="+", required=True,
                    help="header globs relative to repo root")
    ap.add_argument("--prefix", required=True,
                    help="regex alternation of symbol prefixes, e.g. 'pb_' "
                         "or 'mbedtls_|psa_'")
    ap.add_argument("--component", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    releases = {}
    for tag in args.tags:
        syms, files = mine_tag(args.repo, tag, args.headers, args.prefix)
        releases[tag] = sorted(syms)
        print(f"{tag}: {len(syms)} candidate symbols "
              f"from {len(files)} headers", file=sys.stderr)

    out = {
        "component": args.component or os.path.basename(args.repo.rstrip("/\\")),
        "mined_from": "header prototype patterns (no compilation)",
        "prefix": args.prefix,
        "header_globs": args.headers,
        "releases": releases,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
