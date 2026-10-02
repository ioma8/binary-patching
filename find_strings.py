#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""find_strings.py <file> [pattern] [--arch arm64|x86_64|x86] [--min N]
                   [--section NAME] [--regex] [--all] [--count]

List printable strings in a Mach-O binary with their virtual addresses and
section, so a string you see can be handed straight to `find_refs.py` (or
`fdis.py`). Scans section contents only, so symbol-table/relocation noise
(`strings` over the whole file) is excluded, and skips instruction sections
(`__text` &c.) unless `--all`.

  pattern       substring to match (or a regex with `--regex`)
  --min N       minimum length (default 4)
  --section S   only this section, e.g. `__cstring` (repeatable)
  --regex       treat `pattern` as a regular expression
  --all         also scan instruction sections
  --count       print only the number of matches

Columns: `vmaddr  section  string`.
"""
import re
import struct
import sys

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
CPU = {"arm64": 0x0100000C, "x86_64": 0x01000007, "x86": 0x00000007}
CPU_NAME = {v: k for k, v in CPU.items()}


def read_slice(path: str, arch: str | None):
    """(slice_bytes, arch_name) for the requested (or auto-detected) slice."""
    data = open(path, "rb").read()
    if struct.unpack("<I", data[:4])[0] in (MH_MAGIC, MH_MAGIC_64):        # thin
        cputype = struct.unpack("<I", data[4:8])[0]
        name = CPU_NAME.get(cputype)
        if name is None:
            raise SystemExit(f"{path}: unsupported cputype {cputype:#x}")
        if arch is not None and arch != name:
            raise SystemExit(f"--arch {arch}: {path} is a thin {name} binary")
        return data, name
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        raise SystemExit("not a Mach-O / fat Mach-O")
    found, off = {}, 8
    for _ in range(struct.unpack(">I", data[4:8])[0]):
        if magic == FAT_MAGIC_64:
            cputype = struct.unpack(">I", data[off:off + 4])[0]
            offset, size = struct.unpack(">QQ", data[off + 8:off + 24])
            off += 32
        else:
            cputype = struct.unpack(">I", data[off:off + 4])[0]
            offset, size = struct.unpack(">II", data[off + 8:off + 16])
            off += 20
        found.setdefault(cputype, (offset, size))
    for pref in ([arch] if arch else ["arm64", "x86_64", "x86"]):
        if CPU.get(pref) in found:
            offset, size = found[CPU[pref]]
            return data[offset:offset + size], pref
    raise SystemExit(f"no {arch or 'supported'} slice in fat binary")


def sections(data: bytes):
    """[(sectname, segname, vmaddr, size, fileoff, flags)] with file-backed bytes."""
    is64 = struct.unpack("<I", data[:4])[0] == MH_MAGIC_64
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off, out = (32 if is64 else 28), []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == (LC_SEGMENT_64 if is64 else LC_SEGMENT):
            if is64:
                nsects, so, secsz = struct.unpack_from("<I", data, off + 64)[0], off + 72, 80
            else:
                nsects, so, secsz = struct.unpack_from("<I", data, off + 48)[0], off + 56, 68
            for _ in range(nsects):
                sect = data[so:so + 16].split(b"\0", 1)[0].decode()
                seg = data[so + 16:so + 32].split(b"\0", 1)[0].decode()
                if is64:
                    addr, size, foff = struct.unpack_from("<QQI", data, so + 32)
                    flags = struct.unpack_from("<I", data, so + 64)[0]
                else:
                    addr, size, foff = struct.unpack_from("<III", data, so + 32)
                    flags = struct.unpack_from("<I", data, so + 56)[0]
                if foff and size:
                    out.append((sect, seg, addr, size, foff, flags))
                so += secsz
        off += cmdsize
    return out


def main() -> None:
    arch, minlen, only, use_re, count, all_sects = None, 4, set(), False, False, False
    pos, args, i = [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--arch":
            arch, i = args[i + 1], i + 2
        elif a.startswith("--arch="):
            arch, i = a.split("=", 1)[1], i + 1
        elif a == "--min":
            minlen, i = int(args[i + 1]), i + 2
        elif a == "--section":
            only.add(args[i + 1])
            i += 2
        elif a == "--regex":
            use_re, i = True, i + 1
        elif a == "--all":
            all_sects, i = True, i + 1
        elif a == "--count":
            count, i = True, i + 1
        else:
            pos.append(a)
            i += 1
    if not pos or (arch is not None and arch not in CPU):
        print(__doc__)
        raise SystemExit(1)
    path, pattern = pos[0], (pos[1] if len(pos) > 1 else None)
    if minlen < 1:
        raise SystemExit("--min must be >= 1")

    data, arch = read_slice(path, arch)
    run = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    wanted = re.compile(pattern) if use_re else None

    total, out = 0, []
    CODE = 0x80000000 | 0x00000400               # S_ATTR_PURE/SOME_INSTRUCTIONS
    for sect, seg, addr, size, foff, flags in sections(data):
        if only:
            if sect not in only:
                continue
        elif flags & CODE and not all_sects:
            continue
        for m in run.finditer(data[foff:foff + size]):
            text = m.group().decode()
            if wanted is not None:
                if not wanted.search(text):
                    continue
            elif pattern is not None and pattern not in text:
                continue
            total += 1
            if not count:
                out.append((addr + m.start(), f"{sect:<16}", text))
    if count:
        print(total)
        return
    for va, sect, text in out:
        print(f"{va:016x}  {sect}  {text}")
    if not out and not count:
        print("no strings matched")


if __name__ == "__main__":
    main()
