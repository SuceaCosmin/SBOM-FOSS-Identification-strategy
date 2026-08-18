"""Match a candidate source tree against the local zlib reference fingerprint database
(see build_reference_db.py).

Three things differ from the plain skill template and from the lwIP instance, each forced
by phase-1/phase-2 evidence:

**1. Flat upstream layout → no path disambiguation; resolve duplicates by score.**
lwIP's lesson was "locate tracked files by path suffix, not basename". zlib's upstream
tree is **flat** — every tracked file sits in the repo root — so a path suffix *is* the
basename and disambiguates nothing. U-Boot proves this is not academic: it ships two files
named `zlib.h`, a 17-line glue shim in `lib/zlib/` and the real merged header in
`include/u-boot/`. So this matcher collects **every** candidate for each tracked name,
scores them all, and keeps the highest-scoring one, reporting how many it had to choose
between. Path position is never used as evidence.

**2. Group-aware quorum instead of a flat file count.** Subset vendoring is zlib's normal
case (component README §6): decompression-only copies legitimately ship ~4 of the 8
tracked files. A flat matched/expected ratio would score such a tree ~0.5 and risk
rejecting a true positive. Instead the DB labels each tracked file `inflate`/`deflate`/
`optional`/`header`, and a tree is reported with its **integration shape** (inflate-only,
full, …) rather than being penalised for the files a subset copy is *supposed* to lack.

**3. Declared-version extraction, reported but never trusted.** zlib declares its version
in three independent places, and phase 1 found all three can disagree or vanish:
  * `ZLIB_VERSION` in `zlib.h` — deleted outright by U-Boot and the Linux kernel, and
    **faked** by zlib-ng's compat mode (`"1.3.1.zlib-ng"` on code that is not zlib).
  * `inflate_copyright[]` in `inftrees.c` and `deflate_copyright[]` in `deflate.c` —
    string *literals*, so they survive comment-stripped normalization. These are why
    those two files discriminate all 55 releases.
  * A prose provenance comment ("derived from ... zlib-1.2.3").
`declared_versions()` extracts the first two and the verdict reports them **next to** the
content-derived answer, flagging disagreement rather than resolving it. The content
answer always wins; this is the confirm-only metadata tier, kept visibly separate.

Per-file matching is otherwise unchanged: exact normalized-content hash first, winnowing
Jaccard similarity as the fallback.

Verdicts (the `status` field of `resolve_group()`):
  CONFIRMED            every present file exact-matches, and they share a common release
  MIXED_VERSION        every present file exact-matches, but no common release
  PARTIALLY_MODIFIED   some exact-match, others don't (the classic vendor-patched tree)
  LIKELY_CONSISTENT    none exact-match, fuzzy best-matches agree
  INCONSISTENT         none exact-match, fuzzy best-matches disagree
  INCOMPLETE           anchor quorum not met — a weak, unconfirmed signal
  NOT_THIS_COMPONENT   no meaningful similarity to any known release

`resolve_group()` / `scan_tree()` are print-free and return dicts so the phase-3 advisory
loop-closing script can consume them; `analyze_group()` is the thin printer used by the CLI.

Usage: python match_target.py <directory>
"""

import json
import re
import sys
from pathlib import Path

from zlib_fingerprint import fingerprint_source

DB_PATH = Path(__file__).parent / "reference" / "zlib_fingerprints.json"
TOP_N = 5

# Present in every zlib copy in scope, including decompression-only subsets.
ANCHORS = ["inftrees.c", "inflate.c", "inffast.c"]
ANCHOR_QUORUM = 2

# --- Rejecting "this isn't the component at all" -------------------------------------
#
# The skill template (and every earlier component here) used a per-file *veto*: if ANY
# tracked file scored below a floor of 0.05, the whole tree was declared
# NOT_THIS_COMPONENT. That rule is the wrong shape, and this corpus is what shows it —
# measured tree-by-tree per-file bests:
#
#   uboot-lib-zlib      (genuine) 0.09, 0.21, 0.57, 0.68, 0.72, 0.90, 0.92
#   linux-kernel-zlib   (genuine) 0.12, 0.28, 0.35, 0.35, 0.81
#   zlib-ng-adversarial (NOT zlib) 0.00, 0.10, 0.12, 0.14, 0.19, 0.23, 0.25
#
# Per-file scores of a genuine but heavily-rewritten fork and of an unrelated
# API-compatible reimplementation **overlap** across 0.00–0.25, so no per-file threshold
# separates them. U-Boot only survived the old veto because its worst file (`zutil.c`,
# 0.094) happened to land 0.04 above the floor — a real vendor fork within a rounding
# error of being reported as "not zlib".
#
# What *does* separate them is the tree **maximum**: 0.92 / 0.81 for the genuine forks
# against 0.25 for the reimplementation. So the rule here is positive evidence, not a
# negative veto — at least one tracked file must actually look like zlib. A rewritten or
# absent file is then simply weak evidence, never a veto.
#
# 0.40 sits in the middle of the measured 0.25 → 0.81 gap. See the experiment README,
# "Calibrating the reject rule"; this is the zlib data point for the resolver
# evidence-rule work in CLAUDE.md.
POSITIVE_EVIDENCE_CEILING = 0.40

_TAG_RE = re.compile(r"^v(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)$")

# `const char inflate_copyright[] = " inflate 1.3.2 Copyright 1995-2026 Mark Adler ";`
_COPYRIGHT_STR_RE = re.compile(
    r"\b(inflate|deflate)_copyright\s*\[\s*\]\s*=\s*\"?\s*\"?\s*"
    r"\s*\"\s*(?:inflate|deflate)\s+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)", re.DOTALL)
_ZLIB_VERSION_RE = re.compile(r'#\s*define\s+ZLIB_VERSION\s+"([^"]+)"')


def tag_to_version(tag: str) -> str:
    """`v1.2.13` -> `1.2.13`."""
    m = _TAG_RE.match(tag)
    return m.group(1) if m else tag


def load_db() -> dict:
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def declared_versions(files_present: dict) -> dict:
    """Version strings the tree *declares* about itself. Confirm-only — never used to
    resolve the verdict, only reported beside it. Returns {source: version}."""
    out: dict = {}
    for tracked, path in sorted(files_present.items()):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _COPYRIGHT_STR_RE.finditer(text):
            out[f"{m.group(1)}_copyright[] in {path.name}"] = m.group(2)
        m = _ZLIB_VERSION_RE.search(text)
        if m:
            out[f"ZLIB_VERSION in {path.name}"] = m.group(1)
    return out


def find_files_present(target: Path, db: dict) -> tuple:
    """tracked name -> best-scoring filesystem path.

    zlib's flat upstream layout means the tracked key *is* a basename, so a tree can
    legitimately contain several files with the same name (U-Boot: two `zlib.h`). Every
    candidate is scored and the best kept; `ambiguous` records where a choice was made.
    """
    candidates = [target] if target.is_file() else sorted(
        p for p in target.rglob("*") if p.is_file())

    by_name: dict = {}
    for tracked in db["files"]:
        hits = [p for p in candidates if p.name == tracked]
        if hits:
            by_name[tracked] = hits

    found, ambiguous = {}, {}
    for tracked, hits in by_name.items():
        if len(hits) == 1:
            found[tracked] = hits[0]
            continue
        best, best_score = None, -1.0
        for p in hits:
            ev = evaluate_file(p, tracked, db)
            score = 1.0 if ev["exact_matches"] else (
                ev["top_candidates"][0][0] if ev["top_candidates"] else 0.0)
            if score > best_score:
                best, best_score = p, score
        found[tracked] = best
        ambiguous[tracked] = {"chosen": str(best), "score": round(best_score, 3),
                              "rejected": [str(p) for p in hits if p != best]}
    return found, ambiguous


def evaluate_file(path: Path, tracked: str, db: dict) -> dict:
    fp = fingerprint_source(path.read_text(encoding="utf-8", errors="replace"))
    target_winnow = set(fp["winnow"])
    bucket = db["content"].get(tracked, {})

    exact_entry = bucket.get(fp["sha256"])
    exact_matches = sorted(exact_entry["tags"]) if exact_entry else []

    scored = []
    for entry in bucket.values():
        ref_winnow = set(entry["winnow"])
        if not target_winnow and not ref_winnow:
            continue
        score = len(target_winnow & ref_winnow) / (len(target_winnow | ref_winnow) or 1)
        for tag in entry["tags"]:
            scored.append((score, tag))
    scored.sort(reverse=True)

    return {"path": str(path), "tracked": tracked, "exact_matches": exact_matches,
            "top_candidates": scored[:TOP_N]}


def group_consensus(results: dict, db: dict) -> dict:
    """Per-half (inflate / deflate) best-matching release.

    Added because *both* real forks in the corpus turned out to be **two-era trees**: the
    Linux kernel documents it (`deflate based on ZLIB_VERSION "1.1.3"` / `inflate based on
    ZLIB_VERSION "1.2.3"`), and U-Boot does not — its prose claims a 1.2.3 base while its
    deflate side fingerprints to ~1.2.5 at 0.90+. A flat INCONSISTENT verdict lists the
    disagreeing tags but destroys that structure, which is the part a reader actually
    needs. This reports it instead of hiding it.
    """
    out: dict = {}
    for tracked, r in results.items():
        grp = db["group"].get(tracked)
        if grp not in ("inflate", "deflate"):
            continue
        if r["exact_matches"]:
            out.setdefault(grp, []).append((tracked, 1.0, r["exact_matches"][0]))
        elif r["top_candidates"]:
            score, tag = r["top_candidates"][0]
            out.setdefault(grp, []).append((tracked, score, tag))
    return {g: sorted(v, key=lambda x: -x[1]) for g, v in out.items()}


def integration_shape(files_present: dict, db: dict) -> str:
    """Which halves of zlib this tree ships — a *description*, not a penalty. See the
    component README §6: a decompression-only copy is a normal, complete integration."""
    groups = {db["group"].get(t) for t in files_present}
    has_inf = "inflate" in groups
    has_def = "deflate" in groups
    if has_inf and has_def:
        return "full (inflate + deflate)"
    if has_inf:
        return "decompression-only subset (inflate side; no deflate.c/trees.c)"
    if has_def:
        return "compression-only subset (deflate side)"
    return "no core files"


def resolve_group(target: Path, db: dict) -> dict:
    """Print-free resolution of one candidate location.

    Returns {"target", "status", "versions", "tags", "detail", "files", "shape",
    "declared", "ambiguous"}; `versions` is the resolved release set (empty when
    unresolved) as plain version strings."""
    files_present, ambiguous = find_files_present(target, db)
    anchors_found = [a for a in ANCHORS if a in files_present]

    results = {t: evaluate_file(p, t, db) for t, p in files_present.items()}
    out = {"target": str(target), "files": results, "anchors_found": anchors_found,
           "shape": integration_shape(files_present, db),
           "declared": declared_versions(files_present),
           "groups": group_consensus(results, db),
           "ambiguous": ambiguous, "versions": [], "tags": []}

    if len(anchors_found) < ANCHOR_QUORUM:
        out["status"] = "INCOMPLETE"
        out["detail"] = (f"anchor quorum not met: found {anchors_found}, need "
                         f"{ANCHOR_QUORUM} of {ANCHORS}. zlib presence can't be confirmed "
                         f"from this tree alone.")
        return out

    def finish(status, tags, detail):
        out["status"] = status
        out["tags"] = sorted(tags)
        out["versions"] = sorted({tag_to_version(t) for t in tags})
        out["detail"] = detail
        return out

    exact_sets = {t: set(r["exact_matches"]) for t, r in results.items()}
    with_exact = {t for t, tags in exact_sets.items() if tags}
    without_exact = set(results) - with_exact

    if not without_exact:
        common = set.intersection(*exact_sets.values())
        if common:
            return finish("CONFIRMED", common,
                          "all present tracked files exact-match a common release")
        return finish("MIXED_VERSION", set.union(*exact_sets.values()),
                      "every file exact-matches, but no single release is common to all: "
                      + "; ".join(f"{t}={sorted(v)}" for t, v in sorted(exact_sets.items())))

    if with_exact:
        exact_union = set.union(*(exact_sets[t] for t in with_exact))
        exact_common = set.intersection(*(exact_sets[t] for t in with_exact))
        fuzzy_top = {results[t]["top_candidates"][0][1] for t in without_exact
                     if results[t]["top_candidates"]}
        pinned = (exact_common or exact_union)
        overlap = pinned & fuzzy_top
        detail = ("unmodified file(s) pin the base release; "
                  + ", ".join(f"{t}=EXACT {sorted(exact_sets[t])}"
                              for t in sorted(with_exact))
                  + "; modified: "
                  + ", ".join(f"{t}~{results[t]['top_candidates'][0][1]}"
                              f"@{results[t]['top_candidates'][0][0]:.2f}"
                              for t in sorted(without_exact)
                              if results[t]["top_candidates"]))
        if not overlap:
            detail += ("; NOTE exact-matched release(s) and the modified files' closest "
                       "release(s) don't overlap — may span more than one base version")
        return finish("PARTIALLY_MODIFIED", pinned, detail)

    top1 = {t: (r["top_candidates"][0] if r["top_candidates"] else None)
            for t, r in results.items()}
    best_overall = max((v[0] for v in top1.values() if v), default=0.0)
    if best_overall < POSITIVE_EVIDENCE_CEILING:
        out["status"] = "NOT_THIS_COMPONENT"
        out["detail"] = (f"no tracked file reaches the positive-evidence ceiling "
                         f"({POSITIVE_EVIDENCE_CEILING}); best is {best_overall:.3f}. "
                         "Filenames and API may match, but the content does not "
                         "(scores: "
                         + ", ".join(f"{t}={v[0]:.3f}"
                                     for t, v in sorted(top1.items()) if v) + ")")
        return out

    tags = {v[1] for v in top1.values() if v}
    if len(tags) == 1:
        return finish("LIKELY_CONSISTENT", tags,
                      "no file exact-matches, but every file's closest release agrees — "
                      "treat as a modified copy of that base, not a confirmed version")
    return finish("INCONSISTENT", tags,
                  "no file exact-matches and closest releases disagree: "
                  + ", ".join(f"{t}~{v[1]}@{v[0]:.2f}" for t, v in sorted(top1.items()) if v))


def scan_tree(path: Path, db: dict | None = None) -> list:
    """One resolved group per candidate location. zlib's tracked files all sit in one
    flat directory upstream, so a tree is treated as a single vendored copy."""
    db = db or load_db()
    return [resolve_group(path, db)]


def analyze_group(res: dict, db: dict) -> None:
    print(f"\n{'=' * 74}\nCandidate location: {res['target']}\n{'=' * 74}")
    for tracked in sorted(res["files"]):
        r = res["files"][tracked]
        print(f"\n  {tracked}  ({r['path']})")
        if r["exact_matches"]:
            print(f"    EXACT match -> {', '.join(r['exact_matches'])}")
        elif r["top_candidates"]:
            print("    No exact match. Closest known releases by fingerprint similarity:")
            for score, tag in r["top_candidates"]:
                print(f"      {score:.3f}  {tag}")
        else:
            print(f"    No reference data for {tracked} — can't compare.")

    missing = [t for t in db["files"] if t not in res["files"]]
    if missing:
        print(f"\n  (not present in this tree: {missing})")
    print(f"  integration shape: {res['shape']}")

    if res["ambiguous"]:
        print("\n  Ambiguous filenames resolved by score (flat layout — path not used):")
        for tracked, a in sorted(res["ambiguous"].items()):
            print(f"    {tracked}: chose {a['chosen']} @{a['score']}")
            for rej in a["rejected"]:
                print(f"      rejected {rej}")

    if res["declared"]:
        print("\n  Declared version strings (confirm-only — NOT used for the verdict):")
        for src, ver in sorted(res["declared"].items()):
            print(f"    {src} = {ver}")
        distinct = set(res["declared"].values())
        if len(distinct) > 1:
            print(f"    !! the tree declares {len(distinct)} different versions: "
                  f"{sorted(distinct)}")
        if res["versions"] and not (distinct & set(res["versions"])):
            print(f"    !! declared {sorted(distinct)} disagrees with content-derived "
                  f"{res['versions']}")


    if res.get("groups") and res["status"] in ("INCONSISTENT", "MIXED_VERSION",
                                               "PARTIALLY_MODIFIED", "LIKELY_CONSISTENT"):
        print("\n  Per-half consensus (zlib's inflate and deflate sides can be"
              " vendored from different eras):")
        for grp in sorted(res["groups"]):
            print(f"    {grp:<8} " + ", ".join(f"{t}~{tag}@{sc:.2f}"
                                               for t, sc, tag in res["groups"][grp]))

    print(f"\n  {res['status']}" + (f" -> {res['versions']}" if res["versions"] else ""))
    print(f"    {res['detail']}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    target = Path(sys.argv[1])
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        sys.exit(1)

    db = load_db()
    for res in scan_tree(target, db):
        if not res["files"]:
            print(f"No tracked zlib files found under {target}")
            continue
        analyze_group(res, db)


if __name__ == "__main__":
    main()
