"""Build a reference fingerprint database for FreeRTOS-Kernel's **port layer**
(`portable/<compiler>/<arch>/…`) — the layer the core-file experiment
(../version-fingerprint) deliberately skipped, and the layer CVE-2024-28115 actually
lives in.

Why a separate DB: the core kernel files answer *"which FreeRTOS-Kernel release is
this?"*. They cannot answer *"which port?"* — and the port is what decides whether a
kernel CVE applies at all (CVE-2024-28115 affects only ARMv7-M MPU ports and ARMv8-M
ports built with MPU support). So this DB is indexed by **(port, tag)**, not by tag
alone, and every port carries a machine-readable MPU classification.

Two tiers, to keep the DB proportionate (see README "Reference DB size"):
  - **full**  — MPU-relevant ports (arch ends in `_MPU`, or is an ARMv8-M core, or the
    shared ARMv8M/Common trees): every port file fingerprinted. These are the ports whose
    identity and version must be pinned precisely.
  - **ident** — every other port (Xtensa, RISC-V, PIC, non-MPU ARM, …): only `port.c` +
    `portmacro.h`, enough to *identify* the port and thereby rule the CVE out. Their
    versions don't need pinning for this question.

Mines from a **local git clone** rather than raw.githubusercontent fetches: this DB spans
~2 200 MPU blobs plus the identification tier across 60+ tags, which is thousands of
files — HTTP-per-file (as ../version-fingerprint does for 7 files × 60 tags) would be
both slow and rude.

Pitfall worth recording: a **blobless** clone (`--filter=blob:none`) is the wrong tool
here even though it looks like the frugal choice. It defers blob download, so the
`cat-file --batch` below turns into thousands of lazy per-blob network fetches and hangs.
A full clone of this repo is ~150 MB and ~25 s — use it.

Usage:
  python build_port_db.py [--clone <dir>]     # clones if <dir> doesn't exist
Output: reference/port_fingerprints.json
"""

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "version-fingerprint"))
from build_reference_db import pretty_json          # noqa: E402  (shared formatter)
from freertos_fingerprint import fingerprint_source  # noqa: E402

REPO_URL = "https://github.com/FreeRTOS/FreeRTOS-Kernel.git"
OUT_PATH = Path(__file__).parent / "reference" / "port_fingerprints.json"
DEFAULT_CLONE = Path(tempfile.gettempdir()) / "freertos-kernel-portdb-clone"

# Same tag scope as the core-file DB: real V7-V11 releases.
TAG_RE = re.compile(r"^V(?:[789]|1[01])\.")
# Port-layer filenames worth fingerprinting. `.s`/`.S` assembly is included for
# completeness but see the README caveat: the shared normalizer strips C comments only,
# so assembly comments (`;`, `@`) survive into the fingerprint.
PORT_FILES = {"port.c", "portmacro.h", "portmacrocommon.h", "portasm.c", "portasm.h",
              "portasm.s", "portasm.S", "portASM.S", "mpu_wrappers.c",
              "mpu_wrappers_v2.c", "mpu_wrappers_v2_asm.c", "mpu_wrappers_v2_asm.S"}
IDENT_FILES = {"port.c", "portmacro.h"}

ARMV8M_CORE_RE = re.compile(r"^ARM_CM(23|33|35P|55|85)(P)?(_NTZ)?$")
ARMV7M_MPU_RE = re.compile(r"^ARM_CM([34]F?)_MPU$")


def sh(clone: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(clone), *args],
                          capture_output=True, text=True, check=True).stdout


def ensure_clone(clone: Path) -> None:
    if (clone / ".git").exists():
        print(f"Using existing clone at {clone}")
        return
    print(f"Cloning {REPO_URL} (full) -> {clone} …")
    subprocess.run(["git", "clone", "--quiet", REPO_URL, str(clone)],
                   check=True)


def classify_port(port_dir: str) -> dict:
    """Derive (compiler, arch, family, mpu) from an upstream port directory path.

    `mpu` is the field that decides advisory applicability:
      "always"   — a dedicated MPU port (ARM_CM3_MPU, ARM_CM4F_MPU, ARM_CRx_MPU, …).
      "optional" — an ARMv8-M port, where the MPU is a build-time option
                   (`configENABLE_MPU`); presence alone does not decide.
      "none"     — no MPU support in this port.
    """
    rel = port_dir[len("portable/"):]
    parts = rel.split("/")
    security = next((p for p in parts if p in ("secure", "non_secure")), None)

    if parts[0] == "ARMv8M":
        # Legacy layout: ARMv8M/<security>[/portable/<compiler>/<arch>][/...]
        compiler, arch = "(common)", "(common)"
        if "portable" in parts:
            i = parts.index("portable")
            compiler = parts[i + 1] if len(parts) > i + 1 else "(common)"
            arch = parts[i + 2] if len(parts) > i + 2 else "(common)"
        return {"compiler": compiler, "arch": arch, "family": "ARMv8-M",
                "security": security, "mpu": "optional"}

    if parts[0] == "ThirdParty":
        compiler = parts[1] if len(parts) > 1 else "(unknown)"
        arch = parts[2] if len(parts) > 2 else "(unknown)"
        family = "ARMv8-M" if ARMV8M_CORE_RE.match(arch.replace("_TFM", "")) else arch
        return {"compiler": compiler, "arch": arch, "family": f"ThirdParty/{family}",
                "security": security, "mpu": "none"}

    compiler = parts[0]
    arch = parts[1] if len(parts) > 1 else "(common)"
    if ARMV7M_MPU_RE.match(arch):
        return {"compiler": compiler, "arch": arch, "family": "ARMv7-M",
                "security": security, "mpu": "always"}
    if arch.endswith("_MPU"):        # ARM_CRx_MPU and any future non-v7M MPU port
        return {"compiler": compiler, "arch": arch,
                "family": "ARMv7-R/A" if arch.startswith("ARM_CR") else "other",
                "security": security, "mpu": "always"}
    if ARMV8M_CORE_RE.match(arch):
        return {"compiler": compiler, "arch": arch, "family": "ARMv8-M",
                "security": security, "mpu": "optional"}
    family = "ARMv7-M" if arch.startswith("ARM_CM") else ("ARM" if arch.startswith("ARM") else arch)
    return {"compiler": compiler, "arch": arch, "family": family,
            "security": security, "mpu": "none"}


def port_tier(meta: dict) -> str:
    return "full" if meta["mpu"] in ("always", "optional") else "ident"


def main() -> None:
    args = sys.argv[1:]
    clone = Path(args[args.index("--clone") + 1]) if "--clone" in args else DEFAULT_CLONE
    ensure_clone(clone)

    tags = sorted(t for t in sh(clone, "tag").split() if TAG_RE.match(t))
    print(f"{len(tags)} release tags in scope")

    ports: dict = {}
    content: dict = {}
    blob_cache: dict = {}          # blob sha -> fingerprint, so shared content is hashed once
    scanned = 0
    t0 = time.time()

    for tag in tags:
        listing = sh(clone, "ls-tree", "-r", tag, "--", "portable").splitlines()
        entries = []
        for line in listing:
            meta_part, path = line.split("\t", 1)
            _mode, otype, sha = meta_part.split()
            if otype != "blob":
                continue
            port_dir, _, name = path.rpartition("/")
            if name not in PORT_FILES:
                continue
            entries.append((port_dir, name, sha))

        # Fetch every needed blob for this tag in one batch (avoids one git call per file).
        wanted = [sha for _d, _n, sha in entries if sha not in blob_cache]
        if wanted:
            proc = subprocess.run(["git", "-C", str(clone), "cat-file", "--batch"],
                                  input=("\n".join(wanted) + "\n").encode(),
                                  capture_output=True, check=True)
            buf, pos = proc.stdout, 0
            for sha in wanted:
                nl = buf.index(b"\n", pos)
                _sha, _otype, size = buf[pos:nl].split()
                pos = nl + 1
                body = buf[pos:pos + int(size)]
                pos += int(size) + 1
                blob_cache[sha] = fingerprint_source(body.decode("utf-8", errors="replace"))

        for port_dir, name, sha in entries:
            meta = classify_port(port_dir)
            tier = port_tier(meta)
            if tier == "ident" and name not in IDENT_FILES:
                continue
            port = ports.setdefault(port_dir, {**meta, "tier": tier, "tags": []})
            if tag not in port["tags"]:
                port["tags"].append(tag)

            fp = blob_cache[sha]
            bucket = content.setdefault(port_dir, {}).setdefault(name, {})
            entry = bucket.setdefault(fp["sha256"], {"tags": [], "winnow": fp["winnow"]})
            if tag not in entry["tags"]:
                entry["tags"].append(tag)
            scanned += 1

    db = {
        "repo": "FreeRTOS/FreeRTOS-Kernel",
        "generated": time.strftime("%Y-%m-%d"),
        "source": "local blobless clone (git ls-tree / cat-file --batch)",
        "tags": tags,
        "port_files": sorted(PORT_FILES),
        "ident_files": sorted(IDENT_FILES),
        "tier_note": ("'full' ports (MPU-capable) fingerprint every port file; 'ident' "
                      "ports fingerprint only port.c/portmacro.h — enough to identify the "
                      "port and rule out MPU-scoped advisories."),
        "ports": dict(sorted(ports.items())),
        "content": dict(sorted(content.items())),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(pretty_json(db) + "\n", encoding="utf-8")

    full = sum(1 for p in ports.values() if p["tier"] == "full")
    print(f"{len(ports)} distinct port directories ({full} MPU-relevant / "
          f"{len(ports) - full} identification-only)")
    print(f"{scanned} (tag, port, file) observations -> "
          f"{sum(len(f) for p in content.values() for f in p.values())} unique contents")
    print(f"{OUT_PATH} — {OUT_PATH.stat().st_size / 1_000_000:.1f} MB, "
          f"built in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
