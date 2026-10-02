#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""fdis.py <file> <hexaddr> [n]

Brutally-fast arm64 disassembler. Seek straight to the address and disassemble
only n instructions with capstone (O(n)), instead of disassembling the whole
binary then grepping (O(binary)). 10-100x faster than otool-based tools.

Columns: `vmaddr  fileoff  bytes  mnemonic  operands`.
Run: `./fdis.py <file> <addr> [n]` or `uv run fdis.py <file> <addr> [n]`.
"""
import struct
import sys

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19


def read_slice(path: str) -> bytes:
    data = open(path, "rb").read()
    if struct.unpack("<I", data[:4])[0] == MH_MAGIC_64:          # thin
        cpu = struct.unpack("<I", data[4:8])[0]
        if cpu != CPU_TYPE_ARM64:                                # arm64e shares this cpu type
            raise SystemExit(f"fdis.py is arm64-only; {path} is cputype {cpu:#x}")
        return data
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack(">I", data[4:8])[0]
        off = 8
        for _ in range(nfat):
            if magic == FAT_MAGIC_64:
                cputype, _ = struct.unpack(">II", data[off:off + 8])
                offset, size = struct.unpack(">QQ", data[off + 8:off + 24])
                off += 32
            else:
                cputype, _, offset, size, _ = struct.unpack(">IIIII", data[off:off + 20])
                off += 20
            if cputype == CPU_TYPE_ARM64:
                return data[offset:offset + size]
        raise SystemExit("no arm64 slice in fat binary")
    raise SystemExit("not a Mach-O / fat Mach-O")


def segments(data: bytes):
    if struct.unpack("<I", data[:4])[0] != MH_MAGIC_64:
        raise SystemExit("not a 64-bit Mach-O")
    ncmds = struct.unpack("<I", data[16:20])[0]
    segs, off = [], 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[off:off + 8])
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", data[off + 24:off + 56])
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segs


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    path, addr_hex = sys.argv[1], sys.argv[2]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    addr = int(addr_hex, 16)

    data = read_slice(path)
    base_off = None
    for _name, vmaddr, vmsize, fileoff, filesize in segments(data):
        if vmaddr <= addr < vmaddr + vmsize:
            base_off = fileoff + (addr - vmaddr)
            if addr - vmaddr >= filesize:
                raise SystemExit(f"{addr:#x} is zerofill (no bytes in file)")
            break
    if base_off is None:
        raise SystemExit(f"{addr:#x} not in any segment")

    buf = data[base_off: base_off + 4 * n + 32]

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i, insn in enumerate(md.disasm(buf, addr)):
        if i >= n:
            break
        off = base_off + (insn.address - addr)
        print(f"{insn.address:016x}  {off:08x}  {insn.bytes.hex():<8}  {insn.mnemonic}\t{insn.op_str}")


if __name__ == "__main__":
    main()
