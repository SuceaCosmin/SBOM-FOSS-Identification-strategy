"""Fold symbol-set reference DBs into the lightweight-export artifact as a
first-class, tier-labeled evidence type (step 2 of the static-lib roadmap).

The lightweight export (export_lightweight.py) is the source-side backbone:
`releases` (canonical attribution) + `files` (exact-hash tier) + `wfp`
(winnowing tier). This script adds the **symbol tier** (roadmap technique #4:
defined-globals of a `.a`, mineable from headers) to the same artifact, so the
static-library signal becomes part of the curated-KB backbone rather than a
side experiment.

Design — tier-labeled schema 2 (see minr-self-mining/README.md "Tier-labeled
artifact"):

  {
    "schema": 2,
    "releases": {release-id: {vendor,component,version,date,license,purl,url,
                              source_tier}},          # shared, canonical
    "tiers": {
      "exact":     {"technique": 1, "unit": "file-md5",        "files": {...}},
      "winnowing": {"technique": 2, "unit": "winnowing-hash",  "wfp":   {...}},
      "symbol":    {"technique": 4, "unit": "defined-globals",
                    "components": {name: {prefix, releases: {release-id: [sym]}}}}
    }
  }

Every tier declares its roadmap technique number, so a scan *profile*
(architecture doc rec. 4) selects tiers by loading a subset of `tiers`, and
every symbol match resolves through the same `releases` table as a file/wfp
match — canonical attribution by construction (rec. 7), not "containing repo".

Reconciliation: a mined tag (e.g. mbedtls `v3.5.0`) whose (component, version)
already exists via the file/wfp tiers **reuses that release-id** — the symbol
tier and the source tiers point at one canonical release. A version present
only in the symbol DB (nanopb entirely; pre-2.28 mbedTLS) mints a new release
record tagged `source_tier: "symbol"` (rec. 5 provenance; rec. 10 "built into
artifact"). Coverage grows without duplicating identity.

Subcommands:
  build  REF.json [REF2 ...] -o TIER.json [--base EXPORT.json.gz]
      Convert mined symbol ref DB(s) into a symbol-tier fragment
      {"releases": {...minted...}, "symbol": {...}}. --base reconciles
      release-ids against an existing export's releases.

  merge  BASE.json.gz TIER.json [TIER2 ...] -o MERGED.json.gz
      Upgrade BASE to schema 2 if needed and inject the symbol tier +
      minted releases. This is the actual "fold into the artifact" step.

  match  ARTIFACT(.json|.json.gz) LIB.a [LIB2.a ...]
      Run the symbol tier of a merged artifact against static libraries;
      print the canonical purl/version window per component. Proves the
      folded tier is self-contained (needs only the artifact, no ref DBs).
"""
import argparse
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "static-lib-identification"))
from extract_symbols import extract  # noqa: E402  (clean-room ar+ELF reader)


# ----------------------------------------------------------------------------
# artifact I/O + schema normalization
# ----------------------------------------------------------------------------
def load_artifact(path):
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def to_schema2(art):
    """Return art as schema 2 (idempotent). Wraps a legacy schema-1 export
    ({releases, files, wfp}) into the tier-labeled shape without data loss."""
    if art.get("schema") == 2:
        return art
    return {
        "schema": 2,
        "generated": art.get("generated"),
        "source_kb": art.get("source_kb"),
        "releases": {rid: {**r, "source_tier": r.get("source_tier", "file")}
                     for rid, r in art["releases"].items()},
        "tiers": {
            "exact": {"technique": 1, "unit": "file-md5",
                      "files": art.get("files", {})},
            "winnowing": {"technique": 2, "unit": "winnowing-hash",
                          "wfp": art.get("wfp", {})},
        },
    }


def release_index(releases):
    """(component-lower, version) -> release-id, for reconciliation."""
    idx = {}
    for rid, r in releases.items():
        idx[(r["component"].lower(), r["version"])] = rid
    return idx


def mint_id(purl, version):
    return hashlib.md5(f"{purl}@{version}".encode()).hexdigest()


# ----------------------------------------------------------------------------
# build: ref DBs -> symbol-tier fragment (+ minted releases)
# ----------------------------------------------------------------------------
def build_fragment(ref_paths, base_releases):
    idx = release_index(base_releases)
    minted, components = {}, {}
    for rp in ref_paths:
        ref = json.load(open(rp, encoding="utf-8"))
        comp = ref["component"]
        purl = ref.get("purl") or f"pkg:generic/{comp}"
        license_ = ref.get("license") or "NOASSERTION"
        vendor = ref.get("vendor") or comp
        tag_re = re.compile(ref.get("tag_version_re", r"^(?:v)?(.+)$"))
        rel_syms = {}
        for tag, syms in ref["releases"].items():
            m = tag_re.match(tag)
            version = m.group(1) if m else tag
            key = (comp.lower(), version)
            if key in idx:                 # reuse canonical file/wfp release
                rid = idx[key]
            else:                          # symbol-only version -> mint
                rid = mint_id(purl, version)
                minted[rid] = {
                    "vendor": vendor, "component": comp, "version": version,
                    "date": "", "license": license_, "purl": purl,
                    "url": "", "source_tier": "symbol",
                }
                idx[key] = rid
            rel_syms[rid] = sorted(syms)
        components[comp] = {"prefix": ref["prefix"], "releases": rel_syms}
        print(f"  {comp}: {len(rel_syms)} releases "
              f"({sum(1 for k in rel_syms if k in minted)} minted, "
              f"{sum(1 for k in rel_syms if k not in minted)} reconciled)",
              file=sys.stderr)
    return {"releases": minted,
            "symbol": {"technique": 4, "unit": "defined-globals",
                       "components": components}}


# ----------------------------------------------------------------------------
# merge: inject symbol tier + minted releases into an export
# ----------------------------------------------------------------------------
def merge(base, fragments):
    art = to_schema2(base)
    sym = {"technique": 4, "unit": "defined-globals", "components": {}}
    for frag in fragments:
        art["releases"].update(frag["releases"])
        sym["components"].update(frag["symbol"]["components"])
    art["tiers"]["symbol"] = sym
    return art


# ----------------------------------------------------------------------------
# match: run the symbol tier of an artifact against static libraries
# ----------------------------------------------------------------------------
def match_symbol_tier(art, defined):
    """Yield a result dict per component whose symbol universe overlaps the
    library. Ports match_symbols.py's full logic to the folded tier:

    - strict window = releases where every observed known symbol is present
      (observed may be a SUBSET — partial configs — so absence of a *reference*
      symbol is soft, never disqualifying);
    - if no release is strictly consistent (a single un-header-declared internal
      global, e.g. mbedTLS's `psa_get_and_lock_key_slot_with_policy`, breaks
      strict consistency), fall back to the CLOSEST releases (fewest observed
      symbols unexplained) — the same graceful degrade the bespoke tool does;
    - narrow the window by soft absences (expected symbols not defined anywhere
      in the lib) as a secondary tie-break.
    """
    sym = art["tiers"]["symbol"]["components"]
    for comp, cdef in sym.items():
        prefix_re = re.compile(r"^(?:" + cdef["prefix"] + r")")
        releases = {rid: set(s) for rid, s in cdef["releases"].items()}
        universe = set().union(*releases.values()) if releases else set()
        observed = {s for s in defined if prefix_re.match(s)}
        known = observed & universe
        if not known:
            continue
        unexplained = {rid: len(known - rset) for rid, rset in releases.items()}
        strict = [rid for rid, n in unexplained.items() if n == 0]
        if strict:
            window, kind = strict, "consistent"
        else:
            best = min(unexplained.values())
            window = [rid for rid, n in unexplained.items() if n == best]
            kind = f"closest (+{best} unexplained)"
        # soft-absence tie-break within the window
        soft = {rid: len(releases[rid] - defined) for rid in window}
        best_soft = min(soft.values())
        narrowed = [rid for rid in window if soft[rid] == best_soft]
        yield {"component": comp, "window": window, "narrowed": narrowed,
               "kind": kind, "known": known, "observed": observed}


def resolve(art, release_ids):
    rels = art["releases"]
    vers = sorted({rels[r]["version"] for r in release_ids if r in rels})
    purls = sorted({rels[r]["purl"] for r in release_ids if r in rels})
    lics = sorted({rels[r]["license"] for r in release_ids if r in rels})
    return vers, purls, lics


def cmd_match(art, lib_paths):
    for lib in lib_paths:
        res = extract(lib)
        defined = set(res["defined_globals"])
        print(f"\n=== {lib}  ({res['member_count']} members, "
              f"{len(defined)} defined globals)")
        any_hit = False
        for r in match_symbol_tier(art, defined):
            any_hit = True
            vers, purls, lics = resolve(art, r["window"])
            nvers, _, _ = resolve(art, r["narrowed"])
            win = f"{vers[0]} ... {vers[-1]}" if len(vers) > 4 else ", ".join(vers)
            print(f"  {r['component']}: {len(r['known'])}/{len(r['observed'])} "
                  f"prefix symbols known ({r['kind']})")
            print(f"    purl={','.join(purls)}  license={','.join(lics)}")
            print(f"    version window ({len(vers)}): {win or 'none'}")
            if nvers != vers:
                print(f"    best (fewest soft absences): {', '.join(nvers)}")
        if not any_hit:
            print("  NO MATCH (no component's symbol universe overlapped)")


# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build")
    b.add_argument("refs", nargs="+")
    b.add_argument("-o", "--out", required=True)
    b.add_argument("--base", help="export.json[.gz] to reconcile release-ids against")

    m = sub.add_parser("merge")
    m.add_argument("base")
    m.add_argument("tiers", nargs="+")
    m.add_argument("-o", "--out", required=True)

    x = sub.add_parser("match")
    x.add_argument("artifact")
    x.add_argument("libs", nargs="+")

    args = ap.parse_args()

    if args.cmd == "build":
        base_releases = load_artifact(args.base)["releases"] if args.base else {}
        frag = build_fragment(args.refs, base_releases)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(frag, f, indent=2)
            f.write("\n")
        print(f"fragment -> {args.out}: {len(frag['releases'])} minted releases, "
              f"components {', '.join(frag['symbol']['components'])}")

    elif args.cmd == "merge":
        base = load_artifact(args.base)
        frags = [json.load(open(t, encoding="utf-8")) for t in args.tiers]
        art = merge(base, frags)
        out = Path(args.out)
        opener = gzip.open if out.suffix == ".gz" else open
        with opener(out, "wt", encoding="utf-8") as f:
            json.dump(art, f, separators=(",", ":"))
        nrel = len(art["releases"])
        ncomp = len(art["tiers"]["symbol"]["components"])
        print(f"merged -> {out} ({out.stat().st_size / 1e6:.1f} MB): "
              f"{nrel} releases, symbol tier over {ncomp} components")

    elif args.cmd == "match":
        cmd_match(load_artifact(args.artifact), args.libs)


if __name__ == "__main__":
    main()
