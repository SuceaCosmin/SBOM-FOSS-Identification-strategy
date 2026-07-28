"""Close the vuln loop: detected component + version -> applicable CVEs, via GHSA's
**per-repository** advisory feed.

Why this source and not the others (see README.md, "Advisory-source fitness"):
  - NVD/CPE discriminates by version but FreeRTOS's CPEs are keyed to the *AWS
    distribution* versioning (`202212.01`), which a detected kernel semver (`V10.4.3`)
    never matches — that reconciliation is the paused mapping-layer work.
  - OSV has no FreeRTOS records at all, and its bare-`name` matching is version-inert.
  - GHSA's *global* feed has no C/C++ ecosystem — `affects=freertos` returns 0.
  - GHSA's *per-repository* feed (`/repos/{owner}/{repo}/security-advisories`) carries
    FreeRTOS-Kernel's CVE-2024-28115 with `vulnerable_version_range: <=10.6.1`, in
    **kernel semver** — the same scheme the detector outputs. No reconciliation needed,
    which is why this is the one slice of vuln lookup that works today.

So the lookup is: canonical identity -> `{owner}/{repo}` -> repo advisory feed ->
parse `vulnerable_version_range` -> test membership -> verdict.

Coverage is explicit, never implied: a component with no mapping, or a mapped repo whose
maintainers publish advisories elsewhere, returns NOT_COVERED — *not* "no known vulns".

Usage:
  python ghsa_vuln_lookup.py --component freertos-kernel --version V10.4.3
  python ghsa_vuln_lookup.py --component freertos-kernel --version V10.4.3 --json OUT.json
  python ghsa_vuln_lookup.py --refresh          # re-fetch the cached advisory feeds
"""
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

CACHE = Path(__file__).parent / "ghsa_repo_advisories.json"
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "advisory-fitness-probe"}

# Canonical identity (as the detection pipeline would emit it) -> advisory-source
# coordinate. This *is* the mapping layer, in miniature: identity and vuln-lookup key
# are different keys, and each source needs its own map.
COMPONENT_MAP = {
    "pkg:github/freertos/freertos-kernel": {
        "aliases": ["freertos-kernel", "freertos"],
        "ghsa_repo": "FreeRTOS/FreeRTOS-Kernel",
        "version_scheme": "kernel-semver",
        "self_publishes": True,
        "note": "Maintainers self-publish; ranges are in kernel semver, the same scheme "
                "the version fingerprinter resolves to.",
    },
    "pkg:github/freertos/coremqtt": {
        "aliases": ["coremqtt"],
        "ghsa_repo": "FreeRTOS/coreMQTT",
        "version_scheme": "semver",
        "self_publishes": True,
        "note": "Self-publishes, but the one advisory states a bare version, not a range.",
    },
    "pkg:github/mbed-tls/mbedtls": {
        "aliases": ["mbedtls"],
        "ghsa_repo": "Mbed-TLS/mbedtls",
        "version_scheme": "semver",
        "self_publishes": False,
        "note": "Publishes advisories on its own security page, not via GHSA. Use "
                "NVD/CPE (cpe:2.3:a:arm:mbed_tls), which does discriminate by version.",
    },
    "pkg:github/lwip-tcpip/lwip": {
        "aliases": ["lwip"],
        "ghsa_repo": "lwip-tcpip/lwip",
        "version_scheme": "semver",
        "self_publishes": False,
        "note": "Repo feed returns 0 advisories (the repo is itself only a mirror of "
                "git.savannah.gnu.org). Use NVD/CPE (cpe:2.3:a:lwip_project:lwip) via "
                "nvd_vuln_lookup.py, which does discriminate by version.",
    },
    "pkg:github/arm-software/cmsis_5": {
        "aliases": ["cmsis"],
        "ghsa_repo": None,
        "version_scheme": "semver",
        "self_publishes": False,
        "note": "No GHSA repo advisories. NVD has a CPE only for cmsis-rtos.",
    },
}


def resolve_component(name: str):
    """Accept a purl or a short alias; return (purl, entry) or (None, None)."""
    key = name.lower()
    if key in COMPONENT_MAP:
        return key, COMPONENT_MAP[key]
    for purl, entry in COMPONENT_MAP.items():
        if key in entry["aliases"]:
            return purl, entry
    return None, None


# ---------------------------------------------------------------- advisory feed ----

def fetch_repo_advisories(repo: str) -> list:
    url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    time.sleep(1)
    return [{"ghsa_id": a.get("ghsa_id"), "cve_id": a.get("cve_id"),
             "severity": a.get("severity"), "summary": a.get("summary"),
             "html_url": a.get("html_url"),
             "ranges": [{"ecosystem": (v.get("package") or {}).get("ecosystem"),
                         "name": (v.get("package") or {}).get("name"),
                         "vulnerable_version_range": v.get("vulnerable_version_range"),
                         "patched_versions": v.get("patched_versions")}
                        for v in a.get("vulnerabilities", [])]}
            for a in data]


def refresh_cache() -> dict:
    """Re-fetch every mapped repo's advisories into the on-disk cache. Kept as a cache
    so the lookup is reproducible offline and doesn't burn the 60 req/hour anon quota."""
    repos = {e["ghsa_repo"] for e in COMPONENT_MAP.values() if e["ghsa_repo"]}
    cache = {"generated": time.strftime("%Y-%m-%d"),
             "api": "https://api.github.com/repos/{owner}/{repo}/security-advisories",
             "repos": {}}
    for repo in sorted(repos):
        cache["repos"][repo] = fetch_repo_advisories(repo)
        print(f"  {repo}: {len(cache['repos'][repo])} advisories")
    CACHE.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"cache -> {CACHE}")
    return cache


def load_cache() -> dict:
    if not CACHE.exists():
        print(f"No advisory cache at {CACHE}; run with --refresh first.", file=sys.stderr)
        sys.exit(1)
    return json.loads(CACHE.read_text(encoding="utf-8"))


# ------------------------------------------------------------ version handling ----

TAG_RE = re.compile(r"""^v?
    (?P<nums>\d+(?:\.\d+){0,3})
    (?P<suffix>.*)$""", re.VERBOSE | re.IGNORECASE)
LTS_RE = re.compile(r"-LTS-Patch-(\d+)$", re.IGNORECASE)
RC_RE = re.compile(r"-?rc(\d+)$", re.IGNORECASE)


def parse_version(tag: str) -> dict:
    """Normalize a release tag into something comparable against advisory ranges.

    Handles the tag-shape zoo the FreeRTOS-Kernel reference DB actually contains:
      V10.6.1                -> plain kernel semver
      V10.4.1-kernel-only    -> packaging suffix, same release content -> semver 10.4.1
      V10.4.3-LTS-Patch-3    -> maintenance branch off 10.4.3; linearly comparable, but
                                flagged (a mainline range can't express backports)
      V9.0.0rc1 / -rc1       -> prerelease, sorts before the release
      V202110.00-SMP         -> *date* scheme (AWS distribution versioning), NOT
                                comparable against a kernel-semver range at all
    """
    raw = tag
    scheme, flags = "semver", []
    body = tag
    m = LTS_RE.search(body)
    lts = None
    if m:
        lts = int(m.group(1))
        body = body[:m.start()]
        flags.append(f"LTS maintenance branch (patch {lts}) off the base release")
    if body.lower().endswith("-kernel-only"):
        body = body[: -len("-kernel-only")]
    if body.upper().endswith("-SMP"):
        body = body[:-4]
        flags.append("SMP branch tag")
    pre = None
    m = RC_RE.search(body)
    if m:
        pre = int(m.group(1))
        body = body[: m.start()]

    m = TAG_RE.match(body)
    if not m or m.group("suffix").strip("-_. "):
        return {"raw": raw, "scheme": "unknown", "flags": flags}
    parts = [int(p) for p in m.group("nums").split(".")]
    # A 6-digit leading component is a date (YYYYMM), i.e. the AWS distribution scheme.
    if parts[0] >= 100000:
        return {"raw": raw, "scheme": "date", "parts": parts, "flags": flags}
    parts += [0] * (3 - len(parts)) if len(parts) < 3 else []
    return {"raw": raw, "scheme": scheme, "parts": parts, "pre": pre,
            "lts_patch": lts, "flags": flags}


def sort_key(v: dict):
    # Prereleases sort before their release (semver rule); LTS patch level breaks ties
    # among tags sharing a base release.
    return (tuple(v["parts"]), 0 if v.get("pre") else 1, v.get("pre") or 0,
            v.get("lts_patch") or 0)


def compare(a: dict, b: dict) -> int:
    ka, kb = sort_key(a), sort_key(b)
    return (ka > kb) - (ka < kb)


# -------------------------------------------------------------- range handling ----

CLAUSE_RE = re.compile(r"^(?P<op><=|>=|<|>|=)?\s*(?P<ver>\S+)$")
OPS = {"<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0,
       ">=": lambda c: c >= 0, "=": lambda c: c == 0}


def parse_range(spec: str) -> dict:
    """Parse a GHSA `vulnerable_version_range`.

    The documented grammar is comma-separated comparator clauses ANDed together
    (`>= 1.0.0, < 1.0.5`). Real FreeRTOS-org advisories also contain two forms that are
    *not* that grammar, so they are detected rather than silently mis-evaluated:
      `202212.01, 202112.00` -> a hand-written enumeration (ANDing it is unsatisfiable)
      `v5.0.0`               -> a single bare version, i.e. an implied `=`
    """
    if not spec:
        return {"kind": "missing"}
    clauses = []
    for part in spec.split(","):
        m = CLAUSE_RE.match(part.strip())
        if not m:
            return {"kind": "unparseable", "reason": f"clause {part.strip()!r} not understood"}
        clauses.append((m.group("op"), parse_version(m.group("ver"))))
    bare = [c for c in clauses if c[0] is None]
    if not bare:
        return {"kind": "conjunction", "clauses": clauses}
    if len(bare) == len(clauses):
        kind = "exact" if len(clauses) == 1 else "enumeration"
        return {"kind": kind, "clauses": clauses,
                "nonconforming": "bare version(s) with no comparator; treated as "
                                 + ("equality" if kind == "exact" else "an OR-enumeration")}
    return {"kind": "unparseable",
            "reason": "mix of comparator and bare clauses — ambiguous"}


def evaluate(version: dict, spec: str) -> dict:
    """Verdict for one detected version against one advisory range."""
    rng = parse_range(spec)
    if rng["kind"] in ("missing", "unparseable"):
        return {"verdict": "UNDETERMINED", "range_kind": rng["kind"],
                "reason": rng.get("reason", "advisory states no version range")}
    if version["scheme"] != "semver":
        return {"verdict": "UNDETERMINED", "range_kind": rng["kind"],
                "reason": f"detected version {version['raw']!r} is on the "
                          f"{version['scheme']} scheme; the advisory range is not — "
                          f"version-scheme reconciliation needed"}

    notes = list(version.get("flags", []))
    if rng.get("nonconforming"):
        notes.append(f"non-conforming range: {rng['nonconforming']}")

    results = []
    for op, ref in rng["clauses"]:
        if ref["scheme"] != version["scheme"]:
            return {"verdict": "UNDETERMINED", "range_kind": rng["kind"],
                    "reason": f"range bound {ref['raw']!r} is on the {ref['scheme']} "
                              f"scheme, detected version is {version['scheme']} — "
                              f"not comparable", "notes": notes}
        results.append(OPS[op or "="](compare(version, ref)))

    hit = all(results) if rng["kind"] == "conjunction" else any(results)
    if hit and version.get("lts_patch") is not None:
        notes.append("verdict is a linear-ordering result: this is an LTS maintenance "
                     "tag, and a mainline range cannot express backported fixes — "
                     "confirm against the LTS branch's own changelog")
    return {"verdict": "AFFECTED" if hit else "NOT_AFFECTED",
            "range_kind": rng["kind"], "notes": notes}


# ----------------------------------------------------------------------- lookup ----

def lookup(component: str, version_tag: str, cache: dict = None) -> dict:
    cache = cache or load_cache()
    purl, entry = resolve_component(component)
    if not entry:
        return {"component": component, "coverage": "NOT_COVERED",
                "reason": "no canonical-identity -> GHSA repo mapping for this component"}
    if not entry["ghsa_repo"]:
        return {"component": purl, "coverage": "NOT_COVERED",
                "reason": f"no GHSA repo advisory feed. {entry['note']}"}

    advisories = cache["repos"].get(entry["ghsa_repo"])
    if advisories is None:
        return {"component": purl, "coverage": "NOT_COVERED",
                "reason": f"{entry['ghsa_repo']} not in the advisory cache; run --refresh"}
    if not advisories and not entry["self_publishes"]:
        return {"component": purl, "ghsa_repo": entry["ghsa_repo"],
                "coverage": "NOT_COVERED",
                "reason": f"repo publishes no GHSA advisories. {entry['note']}"}

    version = parse_version(version_tag)
    findings = []
    for adv in advisories:
        for r in adv["ranges"]:
            res = evaluate(version, r["vulnerable_version_range"])
            findings.append({"ghsa_id": adv["ghsa_id"], "cve_id": adv["cve_id"],
                             "severity": adv["severity"], "summary": adv["summary"],
                             "url": adv["html_url"],
                             "vulnerable_version_range": r["vulnerable_version_range"],
                             "patched_versions": r["patched_versions"], **res})
    return {"component": purl, "ghsa_repo": entry["ghsa_repo"],
            "version": version_tag, "version_parsed": version,
            "coverage": "COVERED", "advisory_count": len(advisories),
            "findings": findings}


def print_lookup(res: dict, indent: str = "") -> None:
    if res["coverage"] != "COVERED":
        print(f"{indent}{res['component']}: NOT COVERED by GHSA repo advisories — "
              f"{res['reason']}")
        print(f"{indent}  (this means 'this source does not cover it', NOT 'no known vulns')")
        return
    print(f"{indent}{res['component']} @ {res['version']}  "
          f"[source: GHSA {res['ghsa_repo']}, {res['advisory_count']} advisories]")
    affected = [f for f in res["findings"] if f["verdict"] == "AFFECTED"]
    for f in res["findings"]:
        mark = {"AFFECTED": "!!", "NOT_AFFECTED": "  ", "UNDETERMINED": "??"}[f["verdict"]]
        print(f"{indent}  {mark} {f['verdict']:<13} {f['cve_id'] or f['ghsa_id']} "
              f"({f['severity']}) range {f['vulnerable_version_range']!r}"
              f" -> fixed in {f['patched_versions']!r}")
        if f["verdict"] == "UNDETERMINED":
            print(f"{indent}       reason: {f['reason']}")
        if f["verdict"] == "AFFECTED":
            # Version membership is necessary, not sufficient: an advisory's real
            # applicability condition (which port, which config) lives in prose only.
            print(f"{indent}       scope: {f['summary']}")
        for note in f.get("notes", []):
            print(f"{indent}       note: {note}")
    if affected:
        print(f"{indent}  => {len(affected)} applicable CVE(s): "
              f"{', '.join(f['cve_id'] or f['ghsa_id'] for f in affected)}")
    elif not res["findings"]:
        print(f"{indent}  => no advisories published for this repo")
    else:
        print(f"{indent}  => no applicable CVE from this source")


def main() -> None:
    args = sys.argv[1:]
    if "--refresh" in args:
        refresh_cache()
        if "--component" not in args:
            return
    if "--component" not in args or "--version" not in args:
        print(__doc__)
        sys.exit(1)
    component = args[args.index("--component") + 1]
    version = args[args.index("--version") + 1]
    res = lookup(component, version)
    print_lookup(res)
    if "--json" in args:
        out = Path(args[args.index("--json") + 1])
        out.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        print(f"\nresult -> {out}")


if __name__ == "__main__":
    main()
