#!/usr/bin/env python3
"""Clean-room extractor: defined global symbols from a static library (*.a).

Parses the ar archive format and each member's ELF32 symbol table directly
(no binutils/nm dependency), the way an SBOM generator would. Emits the
defined external-linkage symbol surface, per member and as a flat set.

Usage:
  python extract_symbols.py LIB.a            # human-readable summary
  python extract_symbols.py LIB.a --json     # pretty JSON to stdout
  python extract_symbols.py LIB.a --flat     # one defined global symbol per line

Handles: GNU ar (short names 'name/', long-name table '//', symbol index '/'
skipped), BSD-style '#1/len' extended names. ELF32 and ELF64 little-endian
objects (ARM targets and stray x86-64 host builds alike); other member
formats are reported and skipped.
"""

import json
import struct
import sys

AR_MAGIC = b"!<arch>\n"

# ELF constants
SHT_SYMTAB = 2
SHN_UNDEF = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NAMES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}


def parse_ar(data):
    """Yield (member_name, bytes) for each real member of an ar archive."""
    if data[:8] != AR_MAGIC:
        raise ValueError("not an ar archive (bad magic)")
    off = 8
    longnames = b""
    while off + 60 <= len(data):
        hdr = data[off : off + 60]
        if hdr[58:60] != b"`\n":
            raise ValueError(f"bad member header at offset {off}")
        rawname = hdr[0:16].decode("ascii", "replace").rstrip()
        size = int(hdr[48:58].decode("ascii").strip())
        body = data[off + 60 : off + 60 + size]
        off += 60 + size + (size & 1)  # members are 2-byte aligned

        if rawname == "/":            # GNU symbol index (armap) - skip
            continue
        if rawname == "//":           # GNU long-name table
            longnames = body
            continue
        if rawname.startswith("/"):   # GNU long-name reference
            noff = int(rawname[1:])
            end = longnames.index(b"\n", noff)
            name = longnames[noff:end].decode("ascii", "replace").rstrip("/")
        elif rawname.startswith("#1/"):  # BSD extended name (prefixes body)
            nlen = int(rawname[3:])
            name = body[:nlen].decode("ascii", "replace").rstrip("\x00")
            body = body[nlen:]
        else:
            name = rawname.rstrip("/")
        yield name, body


def elf_defined_globals(body):
    """Return [(symbol, bind, type)] of defined GLOBAL/WEAK symbols, or None
    if the member is not a little-endian ELF32/ELF64 object. Symbol names are
    architecture-independent, so x86-64 host builds (which do occur in shipped
    SDKs — see README) fingerprint identically to ARM builds."""
    if len(body) < 52 or body[:4] != b"\x7fELF":
        return None
    ei_class, ei_data = body[4], body[5]
    if ei_data != 1 or ei_class not in (1, 2):  # little-endian only
        return None
    if ei_class == 1:  # ELF32
        e_shoff, = struct.unpack_from("<I", body, 32)
        e_shentsize, e_shnum = struct.unpack_from("<HH", body, 46)
        sec_fmt, sym_fmt, sym_size = "<10I", "<IIIBBH", 16
    else:              # ELF64
        e_shoff, = struct.unpack_from("<Q", body, 40)
        e_shentsize, e_shnum = struct.unpack_from("<HH", body, 58)
        sec_fmt, sym_fmt, sym_size = "<IIQQQQIIQQ", "<IBBHQQ", 24
    sections = []
    for i in range(e_shnum):
        f = struct.unpack_from(sec_fmt, body, e_shoff + i * e_shentsize)
        # (type, offset, size, link, entsize) at differing field positions
        sections.append((f[1], f[4], f[5], f[6], f[9]))
    out = []
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type != SHT_SYMTAB:
            continue
        strtab_off, strtab_size = sections[sh_link][1], sections[sh_link][2]
        strtab = body[strtab_off : strtab_off + strtab_size]
        entsize = sh_entsize or sym_size
        for off in range(0, sh_size, entsize):
            if sym_size == 16:
                st_name, st_value, st_sz, st_info, st_other, st_shndx = \
                    struct.unpack_from(sym_fmt, body, sh_offset + off)
            else:
                st_name, st_info, st_other, st_shndx, st_value, st_sz = \
                    struct.unpack_from(sym_fmt, body, sh_offset + off)
            bind, typ = st_info >> 4, st_info & 0xF
            if bind not in (STB_GLOBAL, STB_WEAK) or st_shndx == SHN_UNDEF:
                continue
            end = strtab.index(b"\x00", st_name)
            name = strtab[st_name:end].decode("ascii", "replace")
            if name:
                out.append((name, "WEAK" if bind == STB_WEAK else "GLOBAL",
                            STT_NAMES.get(typ, str(typ))))
    return out


def extract(path):
    with open(path, "rb") as f:
        data = f.read()
    members, skipped = {}, []
    for name, body in parse_ar(data):
        syms = elf_defined_globals(body)
        if syms is None:
            skipped.append(name)
        else:
            members[name] = sorted({s for s, b, t in syms
                                    if t in ("FUNC", "OBJECT", "NOTYPE")})
    flat = sorted({s for syms in members.values() for s in syms})
    return {"archive": path, "member_count": len(members),
            "skipped_non_elf": skipped, "defined_globals": flat,
            "members": members}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if len(args) != 1:
        print(__doc__)
        sys.exit(2)
    result = extract(args[0])
    if "--json" in flags:
        json.dump(result, sys.stdout, indent=2)
        print()
    elif "--flat" in flags:
        print("\n".join(result["defined_globals"]))
    else:
        print(f"{result['archive']}: {result['member_count']} ELF members, "
              f"{len(result['defined_globals'])} defined globals, "
              f"{len(result['skipped_non_elf'])} non-ELF members skipped")
        for m, syms in list(result["members"].items())[:10]:
            print(f"  {m}: {len(syms)} symbols "
                  f"({', '.join(syms[:4])}{'...' if len(syms) > 4 else ''})")


if __name__ == "__main__":
    main()
