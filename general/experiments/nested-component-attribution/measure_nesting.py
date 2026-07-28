"""Measure what a content matcher actually sees when a component vendors *another*
component inside itself.

Case under test: lwIP's `src/netif/ppp/polarssl/` — five crypto files that upstream lwIP
documents as "fetched from the latest BSD release of the PolarSSL project (PolarSSL
0.10.1-bsd) … cleaned to contain only the necessary struct fields and functions". PolarSSL
is Mbed TLS's ancestor, and this repo already has Mbed TLS detection, so the question is
what that detection says about code it half-recognizes.

The script answers three things without needing the 48 MB KB artifact (which is
gitignored/regenerable — the KB run is documented in README.md instead):

  1. how similar the nested copy is to real Mbed TLS releases, by release era;
  2. whether that similarity lives in the *code* or in the *constant tables*;
  3. what share of each file is constant-table bytes in the first place.

Result (see README.md): the similarity is almost entirely tables. lwIP's `des.c` scores
0.79 against Mbed TLS 2.28.8 on constants alone but 0.07 on code with the constants
stripped — DES's S-boxes are fixed by FIPS 46 and are identical in every implementation
of the algorithm, so they identify "this is DES", never "this is Mbed TLS 2.28.8".

Usage:
  python measure_nesting.py --lwip-clone <dir> [--refresh]

Fetches the Mbed TLS comparison files over raw.githubusercontent (5 files × 2 tags) into
a local cache dir; needs a local lwIP clone for the nested files.
"""
import argparse
import re
import sys
import time
import urllib.request
from pathlib import Path

# The shared normalize/winnow implementation used by every component experiment here.
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "components" / "lwip" / "experiments" / "version-fingerprint"))
from lwip_fingerprint import fingerprint_source, jaccard, normalize   # noqa: E402

LWIP_TAG = "STABLE-2_2_1_RELEASE"
NESTED = ["md5.c", "sha1.c", "des.c", "arc4.c", "md4.c"]
# Oldest and newest Mbed TLS eras that still ship these files at all. arc4.c/md4.c were
# removed in 3.0, so the 3.x era is not comparable for the full set.
MBEDTLS_TAGS = ["mbedtls-1.3.22", "mbedtls-2.28.8"]
CACHE = Path(__file__).parent / ".cache"

HEX_RE = re.compile(r"0x[0-9A-Fa-f]{2,8}")


def git_show(clone: Path, ref: str, path: str) -> str:
    import subprocess
    r = subprocess.run(["git", "-C", str(clone), "show", f"{ref}:{path}"],
                       capture_output=True, check=True)
    return r.stdout.decode("utf-8", errors="replace")


def fetch_mbedtls(refresh: bool = False) -> None:
    CACHE.mkdir(exist_ok=True)
    for tag in MBEDTLS_TAGS:
        for name in NESTED:
            out = CACHE / f"{tag}__{name}"
            if out.exists() and not refresh:
                continue
            url = f"https://raw.githubusercontent.com/Mbed-TLS/mbedtls/{tag}/library/{name}"
            with urllib.request.urlopen(url, timeout=30) as r:
                out.write_bytes(r.read())
            time.sleep(0.3)


def constants_only(text: str) -> str:
    return " ".join(HEX_RE.findall(text))


def code_only(text: str) -> str:
    return HEX_RE.sub("", normalize(text))


def sim(a: str, b: str) -> float:
    return jaccard(set(fingerprint_source(a)["winnow"]),
                   set(fingerprint_source(b)["winnow"]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lwip-clone", required=True, type=Path)
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()

    fetch_mbedtls(args.refresh)
    nested = {n: git_show(args.lwip_clone, LWIP_TAG, f"src/netif/ppp/polarssl/{n}")
              for n in NESTED}

    print(f"lwIP {LWIP_TAG} src/netif/ppp/polarssl/* vs real Mbed TLS releases")
    print(f"\n{'file':10} {'bytes':>7} " + " ".join(f"{t.split('-')[1]:>14}" for t in MBEDTLS_TAGS)
          + "   (whole-file similarity)")
    for name, text in nested.items():
        scores = [sim(text, (CACHE / f"{tag}__{name}").read_text(encoding="utf-8",
                                                                 errors="replace"))
                  for tag in MBEDTLS_TAGS]
        print(f"{name:10} {len(text):>7} " + " ".join(f"{s:>14.3f}" for s in scores))

    newest = MBEDTLS_TAGS[-1]
    print(f"\nWhere does the similarity live? (vs {newest})")
    print(f"\n{'file':10} {'constants':>10} {'code':>8} {'whole':>8} {'% of file that is hex':>22}")
    for name, text in nested.items():
        ref = (CACHE / f"{newest}__{name}").read_text(encoding="utf-8", errors="replace")
        pct = 100 * sum(len(x) for x in HEX_RE.findall(text)) / max(len(normalize(text)), 1)
        print(f"{name:10} {sim(constants_only(text), constants_only(ref)):>10.3f} "
              f"{sim(code_only(text), code_only(ref)):>8.3f} "
              f"{sim(text, ref):>8.3f} {pct:>21.0f}%")

    print("\nReading: high 'constants' with low 'code' means the files share a standard "
          "algorithm's fixed tables, not a common provenance.")


if __name__ == "__main__":
    main()
