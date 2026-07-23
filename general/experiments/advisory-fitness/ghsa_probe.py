"""GHSA (GitHub Advisory Database) fitness probe.

The third standard scanner source after OSV and NVD. GHSA is *ecosystem-scoped*
(npm/pip/maven/go/rubygems/nuget/composer/rust/…) — there is **no standard C/C++
ecosystem** — so the expectation is near-zero *package-queryable* coverage for
embedded C. This probe confirms that for the global `/advisories` feed AND, crucially,
tests a **second access path** the first version of this experiment missed: the
per-repository `/repos/{owner}/{repo}/security-advisories` feed, where upstream
maintainers who self-publish advisories DO carry real, version-ranged records keyed to
the *upstream* version scheme (FreeRTOS-Kernel does; mbedTLS does not).

GitHub REST API (https://docs.github.com/rest/security-advisories).
Unauthenticated: 60 requests/hour — this probe makes ~10.
- Global `/advisories`: `affects=<pkg>` filters by affected package name
  (ecosystem-scoped); `cve_id=` looks up by CVE.
- Repo `/repos/{owner}/{repo}/security-advisories`: advisories the repo maintainers
  published directly. These can carry `vulnerable_version_range` even for a non-standard
  ecosystem name (e.g. `freertos-kernel`).

Usage:
  python ghsa_probe.py [--json OUT.json]
"""
import collections
import json
import sys
import time
import urllib.request

BASE = "https://api.github.com/advisories"
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "advisory-fitness-probe"}


def _get(url):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        return {"error": str(e)}
    time.sleep(1)
    return data


def ghsa(qs):
    data = _get(f"{BASE}?{qs}")
    if isinstance(data, dict):                       # error object, not a list
        return {"api_message": data.get("message") or data.get("error")}
    ecos = collections.Counter()
    ids = []
    for a in data:
        ids.append((a.get("ghsa_id"), a.get("cve_id")))
        for v in a.get("vulnerabilities", []):
            ecos[(v.get("package") or {}).get("ecosystem")] += 1
    return {"count": len(data), "ecosystems": dict(ecos), "sample": ids[:6]}


def repo_advisories(repo):
    """Per-repository published advisories — the second access path. Reports each
    advisory's ecosystem/name and vulnerable_version_range, which is the version-ranged
    data the global feed omits for embedded C."""
    data = _get(f"https://api.github.com/repos/{repo}/security-advisories?per_page=100")
    if isinstance(data, dict):
        return {"api_message": data.get("message") or data.get("error")}
    advs = []
    for a in data:
        advs.append({
            "ghsa_id": a.get("ghsa_id"),
            "cve_id": a.get("cve_id"),
            "severity": a.get("severity"),
            "ranges": [{"ecosystem": (v.get("package") or {}).get("ecosystem"),
                        "name": (v.get("package") or {}).get("name"),
                        "vulnerable_version_range": v.get("vulnerable_version_range"),
                        "patched_versions": v.get("patched_versions")}
                       for v in a.get("vulnerabilities", [])],
        })
    return {"count": len(data), "advisories": advs}


PROBES = [
    ("known mbedtls CVE by id", "cve_id=CVE-2024-45157"),
    ("affects=mbedtls (package query)", "affects=mbedtls&per_page=20"),
    ("affects=freertos (package query)", "affects=freertos&per_page=20"),
    ("100 most-recent (what ecosystems exist)", "per_page=100&sort=published"),
]

# Second access path: repos whose maintainers publish advisories directly.
REPO_PROBES = [
    "FreeRTOS/FreeRTOS-Kernel",
    "FreeRTOS/FreeRTOS",
    "FreeRTOS/coreMQTT",
    "Mbed-TLS/mbedtls",
]


def main():
    out_json = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None
    results = []
    print("Global /advisories feed:")
    for label, qs in PROBES:
        res = ghsa(qs)
        results.append({"path": "global", "label": label, "query": qs, "result": res})
        print(f"  {label}: {json.dumps({k: v for k, v in res.items() if k != 'sample'})}")

    print("\nPer-repository /security-advisories feed:")
    repo_results = []
    for repo in REPO_PROBES:
        res = repo_advisories(repo)
        repo_results.append({"path": "repo", "repo": repo, "result": res})
        n = res.get("count", res.get("api_message"))
        ranged = sum(1 for a in res.get("advisories", [])
                     for r in a["ranges"] if r["vulnerable_version_range"])
        print(f"  {repo}: {n} advisories, {ranged} with a version range")
    results.extend(repo_results)

    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"generated": time.strftime("%Y-%m-%d"),
                       "api": BASE, "results": results}, f, indent=2)
            f.write("\n")
        print(f"\nresults -> {out_json}")


if __name__ == "__main__":
    main()
