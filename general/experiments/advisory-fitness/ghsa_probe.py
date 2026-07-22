"""GHSA (GitHub Advisory Database) fitness probe.

The third standard scanner source after OSV and NVD. GHSA is *ecosystem-scoped*
(npm/pip/maven/go/rubygems/nuget/composer/rust/…) — there is **no C/C++
ecosystem** — so the expectation is near-zero package-queryable coverage for
embedded C. This probe confirms it and characterizes the one form of presence
that does exist (unreviewed CVE mirrors with no package/version mapping).

GitHub REST API `/advisories` (https://docs.github.com/rest/security-advisories).
Unauthenticated: 60 requests/hour — this probe makes ~4. `affects=<pkg>` filters
by affected package name (ecosystem-scoped); `cve_id=` looks up by CVE.

Usage:
  python ghsa_probe.py [--json OUT.json]
"""
import collections
import json
import sys
import time
import urllib.request

BASE = "https://api.github.com/advisories"


def ghsa(qs):
    req = urllib.request.Request(f"{BASE}?{qs}",
                                 headers={"Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        return {"error": str(e)}
    time.sleep(1)
    if isinstance(data, dict):                       # error object, not a list
        return {"api_message": data.get("message")}
    ecos = collections.Counter()
    ids = []
    for a in data:
        ids.append((a.get("ghsa_id"), a.get("cve_id")))
        for v in a.get("vulnerabilities", []):
            ecos[(v.get("package") or {}).get("ecosystem")] += 1
    return {"count": len(data), "ecosystems": dict(ecos), "sample": ids[:6]}


PROBES = [
    ("known mbedtls CVE by id", "cve_id=CVE-2024-45157"),
    ("affects=mbedtls (package query)", "affects=mbedtls&per_page=20"),
    ("affects=freertos (package query)", "affects=freertos&per_page=20"),
    ("100 most-recent (what ecosystems exist)", "per_page=100&sort=published"),
]


def main():
    out_json = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None
    results = []
    for label, qs in PROBES:
        res = ghsa(qs)
        results.append({"label": label, "query": qs, "result": res})
        print(f"  {label}: {json.dumps({k: v for k, v in res.items() if k != 'sample'})}")
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"generated": time.strftime("%Y-%m-%d"), "api": BASE,
                       "results": results}, f, indent=2)
            f.write("\n")
        print(f"\nresults -> {out_json}")


if __name__ == "__main__":
    main()
