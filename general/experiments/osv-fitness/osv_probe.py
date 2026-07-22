"""OSV.dev fitness probe: does this repo's pipeline output (upstream purl +
version / version-window) drive OSV.dev to return the right CVEs?

The whole research exists to produce SBOMs that drive *vulnerability scanning*.
Every prior experiment stopped at `purl + version`; this one feeds that output
into OSV.dev (https://osv.dev, free API) and records what comes back. It tests:

  1. purl-flavor recognition — do the GitHub-flavored purls we declare
     (pkg:github/mbed-tls/mbedtls) resolve, or does OSV need ecosystem purls?
  2. version discrimination — does a version / version-window actually filter
     the CVE set, or is matching inert?
  3. coverage — which of our components OSV knows at all.

Read-only GETs/POSTs against a public API. No key needed. Paced politely.

Usage:
  python osv_probe.py                 # run the matrix, print summary
  python osv_probe.py --json OUT.json # also write pretty-printed results

Results are a live snapshot — CVE *counts* drift as OSV ingests advisories; the
*shape* of the findings (which coordinates return >0, whether version filters)
is the durable result. See README.md for the interpreted writeup.
"""
import json
import re
import sys
import time
import urllib.request

API = "https://api.osv.dev/v1/query"
CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def query(body):
    """POST one OSV query; return (raw_vuln_count, distinct_CVE_ids)."""
    req = urllib.request.Request(
        API, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r)
            break
        except Exception as e:                       # transient network/5xx
            if attempt == 2:
                return {"error": str(e)}
            time.sleep(2 * (attempt + 1))
    vulns = data.get("vulns", [])
    cves = sorted(set(CVE_RE.findall(json.dumps(vulns))))
    time.sleep(0.4)                                  # be polite to the free API
    return {"raw_vulns": len(vulns), "cve_count": len(cves),
            "cves_sample": cves[:6]}


def pkg(version=None, **package):
    body = {"package": package}
    if version is not None:
        body["version"] = version
    return body


# --- test matrix ------------------------------------------------------------
# Each entry: (label, query-body). Grouped by the question it answers.
MATRIX = [
    # -- methodology control: a purl OSV DOES index, proving the harness ------
    ("CONTROL pypi/django @3.0.0 (should be >0)",
     pkg(purl="pkg:pypi/django", version="3.0.0")),

    # -- mbedTLS: declared purl vs fallbacks ---------------------------------
    ("mbedtls: declared purl pkg:github/mbed-tls/mbedtls @2.28.0",
     pkg(purl="pkg:github/mbed-tls/mbedtls", version="2.28.0")),
    ("mbedtls: bare name @2.28.0",
     pkg(name="mbedtls", version="2.28.0")),
    ("mbedtls: name+Debian @2.28.0-1",
     pkg(name="mbedtls", ecosystem="Debian", version="2.28.0-1")),
    ("mbedtls: purl pkg:deb/debian/mbedtls @2.28.0",
     pkg(purl="pkg:deb/debian/mbedtls", version="2.28.0")),

    # -- version discrimination: bare name is inert vs ecosystem-qualified ----
    ("mbedtls bare @2.28.0 (real)", pkg(name="mbedtls", version="2.28.0")),
    ("mbedtls bare @3.6.2 (real)", pkg(name="mbedtls", version="3.6.2")),
    ("mbedtls bare @99.0.0 (impossible)", pkg(name="mbedtls", version="99.0.0")),
    ("mbedtls Debian @2.28.0-1 (real)",
     pkg(name="mbedtls", ecosystem="Debian", version="2.28.0-1")),
    ("mbedtls Debian @99.0.0 (impossible)",
     pkg(name="mbedtls", ecosystem="Debian", version="99.0.0")),

    # -- static-lib version cases (from the symbol-tier findings) ------------
    ("mbedtls bare @3.5.0 (TI libmbedcrypto; manifest lied 3.4.0)",
     pkg(name="mbedtls", version="3.5.0")),
    ("mbedtls bare @2.22.0 (Wi-SUN EOL; misdeclared 5.15.7)",
     pkg(name="mbedtls", version="2.22.0")),

    # -- FreeRTOS: total coverage check --------------------------------------
    ("freertos: declared purl pkg:github/freertos/freertos-kernel @10.4.3",
     pkg(purl="pkg:github/freertos/freertos-kernel", version="10.4.3")),
    ("freertos: bare name @10.4.3", pkg(name="freertos", version="10.4.3")),
    ("freertos: name freertos-kernel @10.4.3",
     pkg(name="freertos-kernel", version="10.4.3")),
    ("freertos: name amazon-freertos @10.4.3",
     pkg(name="amazon-freertos", version="10.4.3")),

    # -- CMSIS: umbrella-granularity component -------------------------------
    ("cmsis: declared purl pkg:github/arm-software/cmsis_5 @5.9.0",
     pkg(purl="pkg:github/arm-software/cmsis_5", version="5.9.0")),
    ("cmsis: bare name @5.9.0", pkg(name="cmsis", version="5.9.0")),

    # -- nanopb --------------------------------------------------------------
    ("nanopb: declared purl pkg:github/nanopb/nanopb @0.3.9.3",
     pkg(purl="pkg:github/nanopb/nanopb", version="0.3.9.3")),
    ("nanopb: bare name @0.3.9.3", pkg(name="nanopb", version="0.3.9.3")),
]


def main():
    out_json = None
    if "--json" in sys.argv:
        out_json = sys.argv[sys.argv.index("--json") + 1]

    results = []
    for label, body in MATRIX:
        res = query(body)
        results.append({"label": label, "query": body, "result": res})
        if "error" in res:
            print(f"  ERR   {label}: {res['error']}")
        else:
            flag = "  " if res["cve_count"] else "0!"
            print(f"  {flag} {res['raw_vulns']:>4} vulns / "
                  f"{res['cve_count']:>3} CVEs  {label}")

    if out_json:
        payload = {"generated": time.strftime("%Y-%m-%d"),
                   "api": API, "results": results}
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
        print(f"\nresults -> {out_json}")


if __name__ == "__main__":
    main()
