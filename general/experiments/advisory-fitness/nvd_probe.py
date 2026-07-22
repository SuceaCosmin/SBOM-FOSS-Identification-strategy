"""NVD/CPE fitness probe — the upstream-accurate counterpart to osv_probe.py.

OSV.dev turned out version-inert for embedded C (see README / osv_probe.py):
its only queryable coverage is distro advisories, and a bare name+version query
returns the whole historical CVE pile regardless of version. NVD is CPE-based,
and CPE 2.3 match ranges are *upstream* version ranges — so this probe tests
whether NVD gives the version discrimination OSV lacked.

NVD REST API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0), no key
needed but rate-limited to 5 requests / 30 s unauthenticated — so this paces
requests 6.5 s apart. `virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>`
returns CVEs whose CPE configurations match that product+version, honoring the
versionStartIncluding/versionEndExcluding ranges NVD records — i.e. real
version-range matching.

The mapping this validates for the generator: canonical identity -> CPE 2.3.
CPEs were discovered via the CPE dictionary API (keywordSearch) and are recorded
inline below with the finding that motivated each.

Usage:
  python nvd_probe.py                 # run matrix, print summary
  python nvd_probe.py --json OUT.json # also write pretty-printed results

Live snapshot — counts drift as NVD ingests CVEs; the durable finding is that an
*impossible* version returns 0 (real range matching) where OSV returned 83.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PACE = 6.5  # seconds between requests (unauthenticated limit: 5 / 30 s)


def nvd(virtual_match):
    url = f"{BASE}?virtualMatchString={urllib.parse.quote(virtual_match)}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=40) as r:
                data = json.load(r)
            break
        except Exception as e:
            if attempt == 2:
                return {"error": str(e)}
            time.sleep(PACE * (attempt + 1))
    ids = [v["cve"]["id"] for v in data.get("vulnerabilities", [])]
    time.sleep(PACE)
    return {"total": data.get("totalResults", 0), "sample": sorted(ids)[:6]}


# (label, cpe vendor:product:version) — CPEs discovered via the CPE dictionary.
MATRIX = [
    # mbedTLS: arm:mbed_tls is the only vendor/product (346 CPE names). Version
    # discrimination is the headline test — real vs impossible versions.
    ("mbedtls arm:mbed_tls @2.28.0 (real)", "cpe:2.3:a:arm:mbed_tls:2.28.0"),
    ("mbedtls arm:mbed_tls @3.6.2 (real, newer)", "cpe:2.3:a:arm:mbed_tls:3.6.2"),
    ("mbedtls arm:mbed_tls @99.0.0 (IMPOSSIBLE)", "cpe:2.3:a:arm:mbed_tls:99.0.0"),
    ("mbedtls arm:mbed_tls @2.22.0 (Wi-SUN EOL)", "cpe:2.3:a:arm:mbed_tls:2.22.0"),
    ("mbedtls arm:mbed_tls @3.5.0 (TI libmbedcrypto)", "cpe:2.3:a:arm:mbed_tls:3.5.0"),

    # FreeRTOS: has CPEs (amazon:freertos, amazon:amazon_web_services_freertos)
    # but the CVEs are the 2018 AWS-FreeRTOS TCP-stack set, keyed to AWS
    # *distribution* versioning — our kernel semver 10.4.3 does NOT match them.
    ("freertos amazon:freertos @10.4.3 (our kernel semver)",
     "cpe:2.3:a:amazon:freertos:10.4.3"),
    ("freertos amazon:freertos (all versions)", "cpe:2.3:a:amazon:freertos"),
    ("freertos amazon:amazon_web_services_freertos (all)",
     "cpe:2.3:a:amazon:amazon_web_services_freertos"),

    # CMSIS: only arm:cmsis-rtos has a CPE (the RTOS-classification gotcha);
    # Core/DSP/NN have none -> effectively uncovered.
    ("cmsis arm:cmsis-rtos @5.9.0", "cpe:2.3:a:arm:cmsis-rtos:5.9.0"),
    ("cmsis arm:cmsis-rtos (all versions)", "cpe:2.3:a:arm:cmsis-rtos"),
]


def main():
    out_json = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None
    results = []
    for label, cpe in MATRIX:
        res = nvd(cpe)
        results.append({"label": label, "cpe": cpe, "result": res})
        if "error" in res:
            print(f"  ERR  {label}: {res['error']}")
        else:
            print(f"  {res['total']:>4} CVEs  {label}")
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"generated": time.strftime("%Y-%m-%d"), "api": BASE,
                       "results": results}, f, indent=2)
            f.write("\n")
        print(f"\nresults -> {out_json}")


if __name__ == "__main__":
    main()
