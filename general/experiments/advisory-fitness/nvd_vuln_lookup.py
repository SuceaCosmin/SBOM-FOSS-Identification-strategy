"""Canonical identity + detected version -> NVD/CPE advisory verdict.

The CPE-based sibling of ghsa_vuln_lookup.py, written for the lwIP phase-3 pass
(2026-07-29) because lwIP's advisories live in NVD, not in a GitHub repo feed —
`lwip-tcpip/lwip`'s per-repo security-advisories endpoint returns 0. Same interface as
the GHSA module (`load_cache` / `lookup` / `print_lookup`) so end_to_end_*.py can swap
one for the other.

This is the *fit* source identified by the advisory-fitness probes: CPE 2.3 match
configurations carry real upstream version ranges (versionStartIncluding /
versionEndExcluding / …), so an impossible version returns nothing while a real one
returns the right set.

Scope: this maps identity+version -> CVEs and stops. Whether a CVE actually impacts a
build (file compiled in? feature enabled? reachable?) is triage and belongs to the SBOM
consumer's VEX process — see general/sbom-generator-architecture.md rec. 13.

Coverage is a first-class output. Three ways NVD can fail to answer, all recorded
rather than collapsed into "no known vulns":
  NOT_COVERED    no CPE product exists for this component
  NOT_QUERYABLE  no version was resolved by detection, so no range can be tested
  UNDETERMINED   (per finding) the CVE's own CPE binding can't be version-matched —
                 e.g. NVD bound it to the literal version `-`, so no version matches it

Usage:
  python nvd_vuln_lookup.py --refresh                 # re-fetch the CVE cache
  python nvd_vuln_lookup.py <component> <version>     # e.g. lwip 2.1.2
"""
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

CACHE_PATH = Path(__file__).parent / "nvd_cve_cache.json"
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PACE = 6.5   # unauthenticated NVD limit is 5 requests / 30 s

# ---------------------------------------------------------------- component map ----
# canonical identity (what the detector emits) -> this source's coordinate.
# The whole point of the mapping layer: the purl is NOT the lookup key.
COMPONENT_MAP = {
    "pkg:github/lwip-tcpip/lwip": {
        "aliases": ["lwip"],
        "cpe_product": "cpe:2.3:a:lwip_project:lwip",
        "version_scheme": "semver",
        "note": "Upstream releases are semver (2.2.1); the CPE dictionary only lists "
                "up to 2.1.2, but range-based CVE bindings are still evaluated against "
                "any version, so newer releases are queryable.",
        # Advisories for lwIP code shipped inside a vendor distribution are filed
        # against the VENDOR's product, not lwip_project:lwip. These are recorded so a
        # scan that knows it is looking at a vendor tree can widen the query.
        # See the README's "carrier-indexed advisories" finding.
        "carrier_products": {
            "cpe:2.3:a:espressif:esp-idf": "ESP-IDF's lwIP component (CVE-2026-45160 is "
                                           "in Espressif's own dhcpserver.c, not upstream)",
            "cpe:2.3:a:microchip:advanced_software_framework":
                "Microchip ASF's bundled lwIP example DHCP server (CVE-2024-7490)",
        },
    },
    "pkg:github/madler/zlib": {
        "aliases": ["zlib"],
        "cpe_product": "cpe:2.3:a:zlib:zlib",
        "version_scheme": "semver-4",   # x.y.z and x.y.z.n both occur, both are releases
        "note": "Real version discrimination (1.1.4 -> 5 CVEs, 1.2.3 -> 7, 1.2.11 -> 4, "
                "1.2.13 -> 3, 1.3.2 -> 0, impossible 99.0.0 -> 0). NOTE the CPE "
                "dictionary ALSO contains a fully deprecated `cpe:2.3:a:gnu:zlib` "
                "(zlib is not a GNU project); querying it returns 0 for every version, "
                "so a mapping layer that takes the first keywordSearch hit reports a "
                "clean bill of health for every zlib ever shipped.",
        # zlib CVEs are bound to zlib:zlib *and* to dozens of downstream products
        # (Python, MariaDB, Node.js, Apple, NetApp, Siemens). Unlike lwIP, the upstream
        # binding is present, so these are not needed to find zlib's own CVEs — they are
        # recorded because a scan that knows it is looking at a carrier tree may want the
        # carrier's own advisories too.
        "carrier_products": {},
    },
    "pkg:github/mbed-tls/mbedtls": {
        "aliases": ["mbedtls"],
        "cpe_product": "cpe:2.3:a:arm:mbed_tls",
        "version_scheme": "semver",
        "note": "The confirmed primary path for Mbed TLS: real version discrimination "
                "(2.28.0 -> 23 CVEs, 3.6.2 -> 11, impossible 99.0.0 -> 0).",
        "carrier_products": {},
    },
    "pkg:github/freertos/freertos-kernel": {
        "aliases": ["freertos-kernel", "freertos"],
        "cpe_product": "cpe:2.3:a:amazon:freertos",
        "version_scheme": "aws-distribution",
        "note": "SCHEME MISMATCH — NVD keys FreeRTOS CVEs to AWS-distribution versions "
                "(202012.00 etc.), while detection resolves kernel semver (10.4.3). "
                "Do not query until the reconciliation layer exists; use the GHSA "
                "per-repo feed, which is in kernel semver.",
        "carrier_products": {},
        "blocked": True,
    },
    "pkg:github/arm-software/cmsis_5": {
        "aliases": ["cmsis"],
        "cpe_product": None,
        "version_scheme": "semver",
        "note": "No CPE for CMSIS-Core/DSP/NN or the pack; NVD has only cmsis-rtos "
                "(part 'o'). Not covered by this source.",
        "carrier_products": {},
    },
}


def resolve_component(name: str):
    key = name.lower()
    if key in COMPONENT_MAP:
        return key, COMPONENT_MAP[key]
    for purl, entry in COMPONENT_MAP.items():
        if key in entry["aliases"]:
            return purl, entry
    return None, None


# --------------------------------------------------------------------- fetching ----

def _get(url: str) -> dict:
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.load(r)
        except Exception as exc:                                # noqa: BLE001
            if attempt == 3:
                raise
            print(f"  retry ({exc})", file=sys.stderr)
            time.sleep(10)
    return {}


def fetch_product_cves(cpe_product: str) -> list:
    """All CVEs whose CPE configurations reference this product, with the version
    constraints that apply *to that product* extracted."""
    data = _get(f"{BASE}?virtualMatchString={urllib.parse.quote(cpe_product)}")
    time.sleep(PACE)
    product_key = ":".join(cpe_product.split(":")[2:5])   # a:vendor:product
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        constraints = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    parts = match["criteria"].split(":")
                    if ":".join(parts[2:5]) != product_key:
                        continue
                    constraints.append({
                        "version": parts[5],
                        "startIncluding": match.get("versionStartIncluding"),
                        "startExcluding": match.get("versionStartExcluding"),
                        "endIncluding": match.get("versionEndIncluding"),
                        "endExcluding": match.get("versionEndExcluding"),
                        "vulnerable": match.get("vulnerable", True),
                    })
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d["lang"] == "en"), "")
        out.append({"cve_id": cve["id"], "published": cve.get("published", "")[:10],
                    "summary": desc[:300], "constraints": constraints})
    return out


def refresh_cache() -> dict:
    cache = {"_fetched": time.strftime("%Y-%m-%d"), "products": {}}
    for purl, entry in COMPONENT_MAP.items():
        product = entry.get("cpe_product")
        if not product:
            continue
        print(f"fetching {product} …", file=sys.stderr)
        cache["products"][product] = fetch_product_cves(product)
        for carrier in entry.get("carrier_products", {}):
            if carrier in cache["products"]:
                continue
            print(f"fetching carrier {carrier} …", file=sys.stderr)
            cache["products"][carrier] = fetch_product_cves(carrier)
    CACHE_PATH.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {CACHE_PATH}", file=sys.stderr)
    return cache


def load_cache() -> dict:
    if not CACHE_PATH.exists():
        return refresh_cache()
    return json.loads(CACHE_PATH.read_text(encoding="utf-8"))


# ------------------------------------------------------------- version handling ----

_NUM_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$")


def parse_version(raw: str) -> dict:
    m = _NUM_RE.match(raw.strip())
    if not m:
        return {"raw": raw, "scheme": "unknown"}
    return {"raw": raw, "scheme": "numeric",
            "parts": tuple(int(g) if g else 0 for g in m.groups())}


def _cmp(a: dict, b: dict) -> int:
    return (a["parts"] > b["parts"]) - (a["parts"] < b["parts"])


def evaluate(version: dict, constraint: dict) -> dict:
    """Membership of one detected version in one CPE match constraint."""
    # NVD marks each cpeMatch with `vulnerable: true/false`. A `false` entry inside an
    # AND configuration means the product is the *environment / precondition* for someone
    # else's flaw, not the vulnerable party. Found via zlib (2026-08-18):
    # CVE-2025-0725 is a **libcurl** integer overflow whose config is
    #   AND( curl <8.12.0 [vulnerable], libcurl <8.12.0 [vulnerable],
    #        zlib <=1.2.0.3 [NOT vulnerable] )
    # — but `virtualMatchString=cpe:2.3:a:zlib:zlib:1.1.4` still returns it, because the
    # query API matches on CPE *presence*, not on vulnerability role. Reading the flag is
    # what stops a curl vulnerability being reported as a zlib one. The constraint was
    # already captured by fetch_product_cves(); it just wasn't consulted.
    if not constraint.get("vulnerable", True):
        return {"verdict": "CONTEXT_ONLY",
                "why": "this product is listed with vulnerable=false — it is a "
                       "precondition for another product's flaw, not the vulnerable "
                       "component"}
    if version["scheme"] != "numeric":
        return {"verdict": "UNDETERMINED",
                "why": f"detected version {version['raw']!r} is not numerically comparable"}

    fixed = constraint["version"]
    bounds = {k: constraint[k] for k in
              ("startIncluding", "startExcluding", "endIncluding", "endExcluding")
              if constraint[k]}

    # NVD's placeholder version literals. `-` means "no version information" and `*`
    # with no bounds means "all versions" — the first is unmatchable by version, the
    # second is a range so wide it carries no discrimination. Both are recorded as
    # UNDETERMINED rather than silently answering yes or no.
    if fixed == "-" and not bounds:
        return {"verdict": "UNDETERMINED",
                "why": "CVE is bound to the literal CPE version '-' (no version "
                       "information), so no version can match it"}
    if fixed == "*" and not bounds:
        return {"verdict": "UNDETERMINED",
                "why": "CVE is bound to '*' with no range bounds — applies to all "
                       "versions, giving no version discrimination"}

    if fixed not in ("*", "-"):
        target = parse_version(fixed)
        if target["scheme"] != "numeric":
            return {"verdict": "UNDETERMINED",
                    "why": f"CVE pins a non-numeric version {fixed!r}"}
        hit = _cmp(version, target) == 0
        return {"verdict": "AFFECTED" if hit else "NOT_AFFECTED",
                "why": f"CVE pins exactly {fixed}"}

    hit = True
    for key, bound in bounds.items():
        b = parse_version(bound)
        if b["scheme"] != "numeric":
            return {"verdict": "UNDETERMINED", "why": f"bound {key}={bound!r} unparseable"}
        c = _cmp(version, b)
        if key == "startIncluding" and c < 0:
            hit = False
        elif key == "startExcluding" and c <= 0:
            hit = False
        elif key == "endIncluding" and c > 0:
            hit = False
        elif key == "endExcluding" and c >= 0:
            hit = False
    return {"verdict": "AFFECTED" if hit else "NOT_AFFECTED",
            "why": "range " + ", ".join(f"{k}={v}" for k, v in sorted(bounds.items()))}


# ----------------------------------------------------------------------- lookup ----

def lookup(component: str, version_tag: str, cache: dict = None) -> dict:
    purl, entry = resolve_component(component)
    if not entry:
        return {"component": component, "coverage": "NOT_COVERED", "findings": [],
                "note": "no NVD/CPE mapping recorded for this component"}
    if not entry.get("cpe_product"):
        return {"component": purl, "coverage": "NOT_COVERED", "findings": [],
                "note": entry["note"]}
    if entry.get("blocked"):
        return {"component": purl, "coverage": "NOT_COVERED", "findings": [],
                "cpe_product": entry["cpe_product"], "note": entry["note"]}
    if not version_tag:
        return {"component": purl, "coverage": "NOT_QUERYABLE", "findings": [],
                "cpe_product": entry["cpe_product"],
                "note": "detection resolved no version — a detection gap, not a clean "
                        "bill of health"}

    cache = cache or load_cache()
    cves = cache["products"].get(entry["cpe_product"], [])
    version = parse_version(version_tag)

    findings = []
    for cve in cves:
        if not cve["constraints"]:
            findings.append({"cve_id": cve["cve_id"], "verdict": "UNDETERMINED",
                             "why": "CVE references the product with no version "
                                    "constraint at all",
                             "summary": cve["summary"]})
            continue
        results = [evaluate(version, c) for c in cve["constraints"]]
        if any(r["verdict"] == "AFFECTED" for r in results):
            chosen = next(r for r in results if r["verdict"] == "AFFECTED")
        elif all(r["verdict"] == "CONTEXT_ONLY" for r in results):
            # Every binding for this product is vulnerable=false: the CVE is somebody
            # else's, and no version of ours can make it ours. Reported, not counted.
            chosen = results[0]
        elif all(r["verdict"] == "UNDETERMINED" for r in results):
            chosen = results[0]
        else:
            chosen = next(r for r in results
                          if r["verdict"] in ("NOT_AFFECTED", "CONTEXT_ONLY"))
        findings.append({"cve_id": cve["cve_id"], "verdict": chosen["verdict"],
                         "why": chosen["why"], "summary": cve["summary"]})

    return {"component": purl, "coverage": "COVERED", "cpe_product": entry["cpe_product"],
            "version": version_tag, "findings": findings,
            "carrier_products": entry.get("carrier_products", {}),
            "note": entry["note"]}


def print_lookup(res: dict, indent: str = "") -> None:
    if res["coverage"] != "COVERED":
        print(f"{indent}{res['coverage']}: {res['note']}")
        return
    affected = [f for f in res["findings"] if f["verdict"] == "AFFECTED"]
    undet = [f for f in res["findings"] if f["verdict"] == "UNDETERMINED"]
    print(f"{indent}{res['cpe_product']} @ {res['version']}: "
          f"{len(affected)} AFFECTED, {len(undet)} UNDETERMINED, "
          f"{len(res['findings']) - len(affected) - len(undet)} NOT_AFFECTED")
    for f in res["findings"]:
        mark = {"AFFECTED": "!!", "NOT_AFFECTED": "  ", "UNDETERMINED": "??"}[f["verdict"]]
        print(f"{indent}  {mark} {f['cve_id']}: {f['verdict']} ({f['why']})")
    if res.get("carrier_products"):
        print(f"{indent}  carrier products (query these too when the tree is a known "
              f"vendor distribution):")
        for cpe, why in res["carrier_products"].items():
            print(f"{indent}    - {cpe}: {why}")


def main() -> None:
    if "--refresh" in sys.argv:
        refresh_cache()
        return
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    print_lookup(lookup(sys.argv[1], sys.argv[2]))


if __name__ == "__main__":
    main()
