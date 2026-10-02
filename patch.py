#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""patch.py <file> <manifest> [--dry-run] [--check] [--resign <app>]

Apply a declarative patch manifest to a Mach-O binary, per architecture slice,
asserting the pristine bytes at every site before writing any of them.

Manifest: one site per line, `<arch> <va> <old_hex> <new_hex>  # comment`
  arch    arm64 | x86_64 | *   (* = every slice, same VA)
  va      unslid virtual address, hex
  old_hex expected bytes (asserted; `-` to skip)
  new_hex replacement bytes (must be the same length as old_hex)

All sites are verified first; if any assert fails, nothing is written.
  --dry-run        verify only, never write
  --check          verify the NEW bytes are already present (is it patched?)
  --resign <app>   re-sign with resign.py afterwards

Example manifest:
  arm64 0x1000d7740 fd7bbfa9fd030091 60008052c0035fd6  # GetStatus -> 3
  x86_64 0x000d17a0 554889e5488d6424f0 b803000000c3     # GetStatus -> 3
"""
import os
import struct
import subprocess
import sys

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
CPU_NAMES = {0x0100000C: "arm64", 0x01000007: "x86_64"}
LC_SEGMENT_64 = 0x19


def slice_list(data: bytes):
    """[(arch_name, base_fileoff, size)] for every slice."""
    if struct.unpack("<I", data[:4])[0] == MH_MAGIC_64:
        cpu = struct.unpack("<I", data[4:8])[0]
        return [(CPU_NAMES.get(cpu, hex(cpu)), 0, len(data))]
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        raise SystemExit("not a Mach-O / fat Mach-O")
    out, off = [], 8
    for _ in range(struct.unpack(">I", data[4:8])[0]):
        if magic == FAT_MAGIC_64:
            cputype = struct.unpack(">I", data[off:off + 4])[0]
            offset, size = struct.unpack(">QQ", data[off + 8:off + 24])
            off += 32
        else:
            cputype = struct.unpack(">I", data[off:off + 4])[0]
            offset, size = struct.unpack(">II", data[off + 8:off + 16])
            off += 20
        out.append((CPU_NAMES.get(cputype, hex(cputype)), offset, size))
    return out


def segments(data: bytes, base: int):
    """[(name, vmaddr, vmsize, abs_fileoff, filesize)] for one slice."""
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off, segs = base + 32, []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((name, vmaddr, vmsize, base + fileoff, filesize))
        off += cmdsize
    return segs


def va_to_abs(segs, va: int):
    for _name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= va < vmaddr + vmsize:
            rel = va - vmaddr
            return fileoff + rel if rel < filesize else None
    return None


def parse_manifest(text: str):
    sites = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        p = line.split()
        if len(p) != 4:
            raise SystemExit(f"manifest line {ln}: expected <arch> <va> <old_hex> <new_hex>")
        arch, va, old_s, new_s = p[0].lower(), p[1], p[2], p[3]
        if arch not in ("arm64", "x86_64", "*"):
            raise SystemExit(f"manifest line {ln}: arch must be arm64|x86_64|*")
        old = None if old_s == "-" else bytes.fromhex(old_s.removeprefix("0x"))
        new = bytes.fromhex(new_s.removeprefix("0x"))
        if old is not None and len(old) != len(new):
            raise SystemExit(f"manifest line {ln}: old/new byte lengths differ")
        sites.append((ln, arch, int(va, 16), old, new))
    if not sites:
        raise SystemExit("manifest has no sites")
    return sites


def main() -> None:
    argv, pos, dry, check, resign = sys.argv[1:], [], False, False, None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--dry-run":
            dry, i = True, i + 1
        elif a == "--check":
            check, i = True, i + 1
        elif a == "--resign":
            resign, i = argv[i + 1], i + 2
        else:
            pos.append(a)
            i += 1
    if len(pos) != 2:
        print(__doc__)
        raise SystemExit(1)
    path, manifest = pos
    data = bytearray(open(path, "rb").read())
    sl = slice_list(data)
    seg_cache = {name: segments(data, base) for name, base, _s in sl}

    actions, errors = [], []
    for ln, arch, va, old, new in parse_manifest(open(manifest).read()):
        targets = sl if arch == "*" else [s for s in sl if s[0] == arch]
        if not targets:
            print(f"  line {ln}: no {arch} slice present, skipping")
            continue
        for name, base, _size in targets:
            fo = va_to_abs(seg_cache[name], va)
            if fo is None or fo + len(new) > len(data):
                errors.append(f"line {ln}: {va:#x} not mapped in {name} slice")
                continue
            cur = bytes(data[fo:fo + len(new)])
            want = new if check else (old if old is not None else cur)
            if old is not None and not check and cur != want:
                errors.append(f"line {ln}: {name} {va:#x} pristine bytes differ:\n"
                              f"      expected {want.hex()}\n      found    {cur.hex()}")
            elif check and cur != new:
                errors.append(f"line {ln}: {name} {va:#x} not patched:\n"
                              f"      expected {new.hex()}\n      found    {cur.hex()}")
            actions.append((name, va, fo, cur, new))

    if errors:
        print("PATCH ABORTED — no bytes written:")
        for e in errors:
            print("  " + e)
        raise SystemExit(1)

    verb = "verified" if (dry or check) else "patched"
    for name, va, fo, cur, new in actions:
        print(f"  {verb} {name:<7} va={va:#010x} off={fo:#08x}  {cur.hex()} -> {new.hex()}")
        if not dry and not check:
            data[fo:fo + len(new)] = new

    if not dry and not check:
        open(path, "wb").write(data)
    print(f"{len(actions)} site(s) {verb} in {path}")

    if resign:
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resign.py")
        if not os.path.exists(script):
            raise SystemExit(f"--resign: {script} not found")
        subprocess.run([sys.executable, script, resign], check=True)


if __name__ == "__main__":
    main()
