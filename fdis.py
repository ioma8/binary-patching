#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone"]
# ///
"""fdis.py <file> <hexaddr> [n] [--arch arm64|x86_64|x86]

Brutally-fast single-site disassembler for arm64, x86_64 and i386 code in
Mach-O **and PE** binaries. Seek straight to the address and disassemble only n
instructions with capstone (O(n)), instead of disassembling the whole binary
then grepping (O(binary)). 10-100x faster than otool/objdump-based tools.

Columns: `vmaddr  fileoff  bytes  mnemonic  operands`.
`--arch` selects the slice of a fat Mach-O (default: arm64, then x86_64, then
x86); a thin Mach-O or PE image is auto-detected. Run: `./fdis.py <file> <addr>`.
"""
import sys

import binfmt

CAPSTONE = {"arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
            "x86_64": ("CS_ARCH_X86", "CS_MODE_64"),
            "x86": ("CS_ARCH_X86", "CS_MODE_32")}


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
    if len(pos) < 2 or (arch is not None and arch not in binfmt.ORDER):
        print(__doc__)
        raise SystemExit(1)
    path, addr_hex = pos[0], pos[1]
    n = int(pos[2]) if len(pos) > 2 else 10
    addr = int(addr_hex, 16)

    img = binfmt.load(path, arch)
    off = img.va_to_off(addr)
    if off is None:
        raise SystemExit(f"{addr:#x} is not file-backed in this {img.arch} image")
    buf = img.data[off: off + 4 * n + 32]

    import capstone
    a_name, m_name = CAPSTONE[img.arch]
    md = capstone.Cs(getattr(capstone, a_name), getattr(capstone, m_name))
    for i, insn in enumerate(md.disasm(buf, addr)):
        if i >= n:
            break
        fo = off + (insn.address - addr)
        print(f"{insn.address:016x}  {fo:08x}  {insn.bytes.hex():<8}  {insn.mnemonic}\t{insn.op_str}")


if __name__ == "__main__":
    main()
