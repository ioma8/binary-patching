#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""fdis.py <file> <hexaddr> [n] [--arch arm64|x86_64|x86]

Brutally-fast single-site disassembler for arm64, x86_64 and i386 (x86) Mach-O
binaries. Seek straight to the address and disassemble only n instructions with
capstone (O(n)), instead of disassembling the whole binary then grepping
(O(binary)). 10-100x faster than otool-based tools.

Columns: `vmaddr  fileoff  bytes  mnemonic  operands`.
`--arch` selects the slice of a fat binary (default: arm64, then x86_64, then
x86). A thin binary is auto-detected. Run: `./fdis.py <file> <addr> [n]`.
"""
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
# capstone (arch, mode) names, resolved lazily so `import capstone` is the only cost
CAPSTONE = {"arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
            "x86_64": ("CS_ARCH_X86", "CS_MODE_64"),
            "x86": ("CS_ARCH_X86", "CS_MODE_32")}


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


def segments(data: bytes):
    """[(name, vmaddr, vmsize, fileoff, filesize)]; handles 32- and 64-bit."""
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        raise SystemExit("not a 64-bit/32-bit Mach-O")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off, segs = (32 if magic == MH_MAGIC_64 else 28), []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == LC_SEGMENT:
            name = data[off + 8:off + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", data, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segs


def main() -> None:
    args, arch, pos, i = sys.argv[1:], None, [], 0
    while i < len(args):
        if args[i] == "--arch":
            arch, i = args[i + 1], i + 2
        elif args[i].startswith("--arch="):
            arch, i = args[i].split("=", 1)[1], i + 1
        else:
            pos.append(args[i])
            i += 1
    if len(pos) < 2 or (arch is not None and arch not in CPU):
        print(__doc__)
        raise SystemExit(1)
    path, addr_hex = pos[0], pos[1]
    n = int(pos[2]) if len(pos) > 2 else 10
    addr = int(addr_hex, 16)

    data, arch = read_slice(path, arch)
    base_off = None
    for _name, vmaddr, vmsize, fileoff, filesize in segments(data):
        if vmaddr <= addr < vmaddr + vmsize:
            if addr - vmaddr >= filesize:
                raise SystemExit(f"{addr:#x} is in a zerofill segment (no file bytes)")
            base_off = fileoff + (addr - vmaddr)
            break
    if base_off is None:
        raise SystemExit(f"{addr:#x} not in any segment")

    buf = data[base_off: base_off + 4 * n + 32]

    import capstone
    a_name, m_name = CAPSTONE[arch]
    md = capstone.Cs(getattr(capstone, a_name), getattr(capstone, m_name))
    for i, insn in enumerate(md.disasm(buf, addr)):
        if i >= n:
            break
        off = base_off + (insn.address - addr)
        print(f"{insn.address:016x}  {off:08x}  {insn.bytes.hex():<8}  {insn.mnemonic}\t{insn.op_str}")


if __name__ == "__main__":
    main()
