"""Identify which FreeRTOS-Kernel **port** a candidate tree vendored, and whether that
port is MPU-capable — the fact that decides whether an MPU-scoped kernel CVE applies.

Design notes:

- **Identification is by content, never by path.** A vendored tree routinely renames or
  flattens `portable/<compiler>/<arch>/` (ESP-IDF, vendor SDKs and build-system copies all
  do), so the directory name is treated as a *hint to report*, not as evidence. Every
  candidate directory's files are matched against every known port in the reference DB.
- **Duplicate upstream layouts collapse.** Upstream ships some ARMv8-M ports twice (e.g.
  `portable/GCC/ARM_CM33/non_secure` and
  `portable/ARMv8M/non_secure/portable/GCC/ARM_CM33`) with identical content, so equally
  scoring matches that share (compiler, arch, security) are reported as one port with
  several upstream paths.
- **MPU applicability is a classification, not a guess.** Dedicated `*_MPU` ports are
  always MPU; ARMv8-M ports are MPU-*capable*, decided at build time by
  `configENABLE_MPU`, so the tree's `FreeRTOSConfig.h` is read as separate evidence and
  reported as such. With no config found the answer is UNKNOWN, never "no".

This complements ../version-fingerprint (which answers *which release*) — the two
together are what turn "kernel 10.5.1, maybe affected" into "kernel 10.5.1, GCC
ARM_CM4_MPU port, affected".

Usage: python match_port.py <directory>
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "version-fingerprint"))
from freertos_fingerprint import fingerprint_source  # noqa: E402

DB_PATH = Path(__file__).parent / "reference" / "port_fingerprints.json"
# Below this Jaccard score a "closest port" is noise, not a modified port.
FUZZY_FLOOR = 0.30
CONFIG_RE = re.compile(r"^\s*#\s*define\s+(configENABLE_MPU|configENABLE_TRUSTZONE|"
                       r"configUSE_MPU_WRAPPERS_V1|portUSING_MPU_WRAPPERS)\s+(\S+)",
                       re.MULTILINE)


def load_db() -> dict:
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def find_port_dirs(target: Path, port_files: list) -> dict:
    """Group candidate port files by the directory they sit in."""
    names = set(port_files)
    groups: dict = {}
    if target.is_file():
        if target.name in names:
            groups[target.parent] = {target.name: target}
        return groups
    for path in target.rglob("*"):
        if path.is_file() and path.name in names:
            groups.setdefault(path.parent, {})[path.name] = path
    return groups


def score_file(fp: dict, db: dict, filename: str) -> dict:
    """Score one target file against every known port that ships a file of that name."""
    target_winnow = set(fp["winnow"])
    per_port = {}
    for port_id, files in db["content"].items():
        bucket = files.get(filename)
        if not bucket:
            continue
        exact = bucket.get(fp["sha256"])
        best_score, best_tags = 0.0, []
        for entry in bucket.values():
            ref = set(entry["winnow"])
            if not target_winnow and not ref:
                continue
            score = len(target_winnow & ref) / (len(target_winnow | ref) or 1)
            if score > best_score:
                best_score, best_tags = score, entry["tags"]
        per_port[port_id] = {"exact_tags": sorted(exact["tags"]) if exact else [],
                             "score": best_score, "fuzzy_tags": sorted(best_tags)}
    return per_port


def resolve_dir(directory: Path, files_present: dict, db: dict) -> dict:
    """Resolve one candidate directory to a port identity + version window."""
    per_file = {name: score_file(fingerprint_source(p.read_text(encoding="utf-8", errors="replace")),
                                 db, name)
                for name, p in sorted(files_present.items())}

    # Aggregate per candidate port: exact matches count double-weight against fuzzy ones.
    totals: dict = {}
    for name, ports in per_file.items():
        for port_id, res in ports.items():
            agg = totals.setdefault(port_id, {"exact_files": [], "scores": [], "files": {}})
            agg["files"][name] = res
            agg["scores"].append(res["score"])
            if res["exact_tags"]:
                agg["exact_files"].append(name)

    ranked = []
    for port_id, agg in totals.items():
        meta = db["ports"][port_id]
        mean = sum(agg["scores"]) / len(agg["scores"])
        ranked.append({"port_id": port_id, **{k: meta[k] for k in
                                              ("compiler", "arch", "family", "security", "mpu", "tier")},
                       "exact_files": sorted(agg["exact_files"]),
                       "mean_score": mean, "files": agg["files"]})
    # Most exact-matched files first, then similarity.
    ranked.sort(key=lambda r: (len(r["exact_files"]), r["mean_score"]), reverse=True)

    out = {"directory": directory, "files_present": sorted(files_present),
           "candidates": ranked[:8]}
    if not ranked or (not ranked[0]["exact_files"] and ranked[0]["mean_score"] < FUZZY_FLOOR):
        out["status"] = "UNKNOWN_PORT"
        out["versions"] = []
        return out

    best = ranked[0]
    # Collapse upstream duplicate layouts: same logical port, identical evidence.
    same = [r for r in ranked
            if (r["compiler"], r["arch"], r["security"]) == (best["compiler"], best["arch"], best["security"])
            and len(r["exact_files"]) == len(best["exact_files"])
            and abs(r["mean_score"] - best["mean_score"]) < 1e-9]
    out["port"] = {k: best[k] for k in ("compiler", "arch", "family", "security", "mpu", "tier")}
    out["upstream_paths"] = sorted(r["port_id"] for r in same)

    # Version window: intersect the tag sets of every exactly-matched file; fall back to
    # the union of closest-match tags when nothing matched exactly (a modified port).
    exact_sets = [set(best["files"][f]["exact_tags"]) for f in best["exact_files"]]
    if exact_sets:
        common = set.intersection(*exact_sets)
        out["versions"] = sorted(common)
        out["status"] = "IDENTIFIED" if common else "IDENTIFIED_MIXED"
    else:
        fuzzy = set()
        for res in best["files"].values():
            fuzzy |= set(res["fuzzy_tags"])
        out["versions"] = sorted(fuzzy)
        out["status"] = "IDENTIFIED_MODIFIED"
    return out


def read_mpu_config(target: Path) -> list:
    """Read MPU-relevant build configuration from any FreeRTOSConfig.h in the tree.

    This is *composition evidence* (what the build selects), not triage: it is reported
    with the file it came from, and never overrides port classification silently.
    """
    found = []
    paths = ([target] if target.is_file() and target.name == "FreeRTOSConfig.h"
             else list(target.rglob("FreeRTOSConfig.h")) if target.is_dir() else [])
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        settings = {m.group(1): m.group(2) for m in CONFIG_RE.finditer(text)}
        if settings:
            found.append({"path": str(path), "settings": settings})
    return found


MPU_FILE_NAMES = {"mpu_wrappers.c", "mpu_wrappers_v2.c", "mpu_wrappers_v2_asm.c",
                  "mpu_wrappers_v2_asm.S"}


def mpu_status_unidentified(res: dict, db: dict) -> dict:
    """MPU verdict for a directory that matched no known port.

    An unidentified port is not automatically "unknown MPU". If *no* MPU-capable port
    scores anywhere near the target and the directory ships none of the MPU-specific
    files, that is **negative evidence**: whatever this port is, it is not one of the
    MPU ports an MPU-scoped advisory applies to. A heavily modified MPU port would still
    score well above the floor against its own upstream (the core-file experiment's
    modified ESP-IDF `tasks.c` still scored 0.56), so a near-zero score means *different
    code*, not *modified code*.
    """
    if MPU_FILE_NAMES & set(res["files_present"]):
        return {"mpu": "UNKNOWN", "why": "unidentified port that ships MPU wrapper files",
                "confidence": "none"}
    mpu_scores = [c["mean_score"] for c in res["candidates"]
                  if db["ports"][c["port_id"]]["mpu"] in ("always", "optional")]
    best = max(mpu_scores, default=0.0)
    if best < FUZZY_FLOOR:
        return {"mpu": "NOT_SUPPORTED",
                "why": f"unidentified port, but no MPU-capable port scores above "
                       f"{FUZZY_FLOOR:.2f} (best {best:.3f}) and no MPU wrapper files are "
                       f"present — this is different code, not a modified MPU port",
                "confidence": "negative-evidence"}
    return {"mpu": "UNKNOWN",
            "why": f"unidentified port with non-trivial similarity ({best:.3f}) to an "
                   f"MPU-capable port — needs a closer look", "confidence": "none"}


def mpu_status(port: dict, configs: list) -> dict:
    """Combine port classification + config evidence into an MPU verdict."""
    if port["mpu"] == "always":
        return {"mpu": "ENABLED", "why": f"{port['arch']} is a dedicated MPU port"}
    if port["mpu"] == "none":
        return {"mpu": "NOT_SUPPORTED",
                "why": f"{port['arch']} ({port['family']}) has no MPU support"}
    values = {c["settings"].get("configENABLE_MPU") for c in configs} - {None}
    if values == {"1"}:
        return {"mpu": "ENABLED", "why": "ARMv8-M port with configENABLE_MPU 1"}
    if values == {"0"}:
        return {"mpu": "DISABLED", "why": "ARMv8-M port with configENABLE_MPU 0"}
    if values:
        return {"mpu": "UNKNOWN", "why": f"conflicting configENABLE_MPU values {sorted(values)}"}
    return {"mpu": "UNKNOWN",
            "why": "ARMv8-M port: MPU is a build-time option and no FreeRTOSConfig.h "
                   "with configENABLE_MPU was found in this tree"}


def scan_ports(target: Path, db: dict = None) -> list:
    """Programmatic entry point — resolve every candidate port directory, print nothing."""
    db = db or load_db()
    configs = read_mpu_config(target)
    results = []
    for directory, files_present in sorted(find_port_dirs(target, db["port_files"]).items()):
        res = resolve_dir(directory, files_present, db)
        res["mpu_config_evidence"] = configs
        res["mpu_status"] = (mpu_status(res["port"], configs) if res.get("port")
                             else mpu_status_unidentified(res, db))
        results.append(res)
    return results


def print_result(res: dict) -> None:
    print(f"\n{'=' * 74}\nCandidate port directory: {res['directory']}\n{'=' * 74}")
    print(f"  files: {', '.join(res['files_present'])}")
    if res["status"] == "UNKNOWN_PORT":
        m = res["mpu_status"]
        print("\n  UNKNOWN PORT — no known FreeRTOS port matches these files closely enough")
        for c in res["candidates"][:3]:
            print(f"    closest: {c['port_id']}  score {c['mean_score']:.3f}")
        print(f"    MPU: {m['mpu']} ({m['confidence']}) — {m['why']}")
        return

    p, m = res["port"], res["mpu_status"]
    print(f"\n  {res['status']}: {p['compiler']} / {p['arch']}"
          f"{'/' + p['security'] if p['security'] else ''}  ({p['family']})")
    print(f"    upstream path(s): {', '.join(res['upstream_paths'])}")
    print(f"    version window: {res['versions'] or '(unresolved)'}")
    print(f"    MPU: {m['mpu']} — {m['why']}")
    for ev in res["mpu_config_evidence"]:
        print(f"      config evidence: {ev['path']} -> {ev['settings']}")
    best = res["candidates"][0]
    for name, r in sorted(best["files"].items()):
        detail = (f"EXACT -> {len(r['exact_tags'])} tag(s)" if r["exact_tags"]
                  else f"closest {r['score']:.3f}")
        print(f"      {name}: {detail}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    target = Path(sys.argv[1])
    if not target.exists():
        print(f"No such path: {target}", file=sys.stderr)
        sys.exit(1)
    results = scan_ports(target)
    if not results:
        print(f"No port-layer files found under {target}")
        return
    for res in results:
        print_result(res)


if __name__ == "__main__":
    main()
