#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""find_callers.py <file> <target>... [--arch arm64|x86_64|x86] [--no-symbols]

Fast caller finder for Mach-O binaries (arm64, x86_64, i386). Scans `__text`
for direct calls — `BL` (arm64) or `call rel32` (x86_64/i386) — and prints every
call site of each target, annotated with the containing symbol.

Targets are `0xADDR`, `0xADDR=Label`, or a symbol-name substring resolved from
the Mach-O symbol table. The scan is vectorized (NumPy) and names are decoded
lazily, so a 56 MB slice resolves callers in ~10 ms.

Columns: `call_site  caller_symbol+offset`.

Misses: indirect calls (PLT/GOT/vtable, x86 `call [..]`), arm64 tail-calls (`B`),
and calls in the other architecture slices. arm64 is exact (BL is a fixed-width,
word-aligned opcode). The x86/x86_64 scan keys off the `0xE8` opcode byte and is
a heuristic: it finds every real direct call, but can add a spurious caller (on
/bin/ls, 4 of 23 targets gained one). Run `fdis.py` to read a site.
"""
import struct
import sys

import numpy as np

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
CPU = {"arm64": 0x0100000C, "x86_64": 0x01000007, "x86": 0x00000007}
CPU_NAME = {v: k for k, v in CPU.items()}
NLIST = {True: np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                         ("n_desc", "<u2"), ("n_value", "<u8")]),
         False: np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                          ("n_desc", "<u2"), ("n_value", "<u4")])}


def pick_slice(data: bytes, want_cpu: int):
    """(base_fileoff, size, cputype) of the requested slice; auto-detects thin."""
    if struct.unpack("<I", data[:4])[0] in (MH_MAGIC, MH_MAGIC_64):
        return 0, len(data), struct.unpack("<I", data[4:8])[0]
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        raise SystemExit("not a Mach-O / fat Mach-O")
    off = 8
    for _ in range(struct.unpack(">I", data[4:8])[0]):
        if magic == FAT_MAGIC_64:
            cputype = struct.unpack(">I", data[off:off + 4])[0]
            offset, size = struct.unpack(">QQ", data[off + 8:off + 24])
            off += 32
        else:
            cputype = struct.unpack(">I", data[off:off + 4])[0]
            offset, size = struct.unpack(">II", data[off + 8:off + 16])
            off += 20
        if cputype == want_cpu:
            return offset, size, cputype
    raise SystemExit("requested slice not present in fat binary")


def load_commands(data: bytes, base: int, is64: bool):
    """(__text section, symtab) — offsets relative to the slice start."""
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off = base + (32 if is64 else 28)
    text = symtab = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            nsects, so, secsz = struct.unpack_from("<I", data, off + 64)[0], off + 72, 80
        elif cmd == LC_SEGMENT:
            nsects, so, secsz = struct.unpack_from("<I", data, off + 48)[0], off + 56, 68
        else:
            nsects = 0
        for _ in range(nsects):
            if data[so:so + 16].split(b"\0", 1)[0] == b"__text":
                text = struct.unpack_from("<QQI" if is64 else "<III", data, so + 32)
            so += secsz
        if cmd == LC_SYMTAB:
            symtab = struct.unpack_from("<IIII", data, off + 8)
        off += cmdsize
    return text, symtab


def call_sites(buf: "np.ndarray", arch: str, text_va: int):
    """(call_pc, target_va) arrays for every direct call in __text."""
    if arch == "arm64":
        words = buf[: len(buf) // 4 * 4].view("<u4")
        idx = np.flatnonzero((words >> np.uint32(26)) == np.uint32(0x25)).astype(np.int64)
        imm = words[idx].astype(np.int64) & 0x03FFFFFF
        imm = (imm ^ 0x02000000) - 0x02000000                 # sign-extend 26-bit
        pc = text_va + idx * 4
        return pc, pc + (imm << 2)
    idx = np.flatnonzero(buf == 0xE8).astype(np.int64)        # call rel32
    idx = idx[idx + 5 <= len(buf)]
    rel = (buf[idx + 1].astype(np.int64)
           | (buf[idx + 2].astype(np.int64) << 8)
           | (buf[idx + 3].astype(np.int64) << 16)
           | (buf[idx + 4].astype(np.int64) << 24))
    rel = (rel ^ 0x80000000) - 0x80000000                     # sign-extend 32-bit
    pc = text_va + idx
    return pc, pc + 5 + rel


def main() -> None:
    arch, symbols_on, explicit, pos, args, i = "arm64", True, False, [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--arch":
            arch, explicit, i = args[i + 1], True, i + 2
        elif a.startswith("--arch="):
            arch, explicit, i = a.split("=", 1)[1], True, i + 1
        elif a == "--no-symbols":
            symbols_on, i = False, i + 1
        else:
            pos.append(a)
            i += 1
    if len(pos) < 2:
        print(__doc__)
        raise SystemExit(1)
    path, target_args = pos[0], pos[1:]

    want_cpu = CPU.get(arch)
    if want_cpu is None:
        raise SystemExit(f"unknown --arch {arch!r}; use arm64|x86_64|x86")
    data = open(path, "rb").read()
    base, _size, cputype = pick_slice(data, want_cpu)
    if explicit and cputype != want_cpu:
        raise SystemExit(f"--arch {arch}: no {arch} slice in this thin binary")
    arch = CPU_NAME.get(cputype)
    if arch is None:
        raise SystemExit(f"unsupported cputype {cputype:#x}")
    is64 = struct.unpack("<I", data[base:base + 4])[0] == MH_MAGIC_64

    text, symtab = load_commands(data, base, is64)
    if text is None:
        raise SystemExit("no __text section")
    text_va, text_size, text_off = text
    buf = np.frombuffer(data, dtype=np.uint8, count=text_size, offset=base + text_off)
    call_pc, target = call_sites(buf, arch, text_va)

    # ---- symbol table: parse vectors now, decode names on demand -------------
    name_cache: dict[int, str] = {}
    sym_strbase, kstrx, kva = 0, np.empty(0, np.int64), np.empty(0, np.int64)
    sym_va, sym_strx = np.empty(0, np.int64), np.empty(0, np.int64)
    all_strx = None
    _uniq: list = []

    def name_at(strx: int) -> str:
        if strx not in name_cache:
            o = sym_strbase + strx
            name_cache[strx] = data[o:data.index(b"\0", o)].decode("utf-8", "replace")
        return name_cache[strx]

    def name_starts():
        if not _uniq:                                    # built only for a name query
            _uniq.append(np.unique(all_strx) if all_strx is not None and all_strx.size
                         else np.empty(0, np.uint32))
        return _uniq[0]

    if symbols_on and symtab is not None:
        symoff, nsyms, stroff, _strsize = symtab
        sym_strbase = base + stroff
        arr = np.frombuffer(data, dtype=NLIST[is64], count=nsyms, offset=base + symoff)
        keep = ((arr["n_type"] & 0x0E) == 0x0E) & ((arr["n_type"] & 0xE0) == 0)  # N_SECT, not a stab
        sel = np.flatnonzero(keep)
        kstrx = arr["n_strx"][sel].astype(np.int64)
        kva = arr["n_value"][sel].astype(np.int64)
        all_strx = arr["n_strx"]
        if kva.size and np.all(np.diff(kva) >= 0):
            sym_va, sym_strx = kva, kstrx                # table already address-ordered
        elif kva.size:
            order = np.argsort(kva, kind="stable")
            sym_va, sym_strx = kva[order], kstrx[order]

    def label_for(va: int) -> str:
        if sym_va.size == 0:
            return ""
        j = int(np.searchsorted(sym_va, va, "right")) - 1
        if j < 0 or va - sym_va[j] > 0x100000:
            return ""
        off = va - int(sym_va[j])
        return name_at(int(sym_strx[j])) + (f"+{off:#x}" if off else "")

    # ---- resolve targets: hex address, or symbol-name substring --------------
    targets: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    def add(va: int, label: str) -> None:
        key = (va, label)
        if key not in seen:
            seen.add(key)
            targets.append(key)

    for arg in target_args:
        if arg.lower().startswith("0x"):
            left, _, label = arg.partition("=")
            va = int(left, 16)
            add(va, label or label_for(va) or hex(va))
            continue
        if sym_va.size == 0:
            raise SystemExit(f"target {arg!r}: no symbol table to resolve against")
        strbase, end = sym_strbase, sym_strbase + symtab[3]
        hits, p = [], strbase
        while (p := data.find(arg.encode(), p, end)) >= 0:
            hits.append(p - strbase)
            p += 1
        before = len(targets)
        if hits:
            # the greatest name-start <= a match is the name containing it
            uniq = name_starts()
            j = np.searchsorted(uniq, np.array(hits), "right") - 1
            for strx in np.unique(uniq[j[j >= 0]]):
                for si in np.flatnonzero(kstrx == strx):
                    add(int(kva[si]), name_at(int(strx)))
        if len(targets) == before:
            raise SystemExit(f"target {arg!r}: no symbol match")

    # ---- report --------------------------------------------------------------
    if target.size:
        order = np.argsort(target, kind="stable")
        st, sc = target[order], call_pc[order]
    else:
        st, sc = target, call_pc
    for va, label in targets:
        lo = int(np.searchsorted(st, va, "left"))
        hi = int(np.searchsorted(st, va, "right"))
        pcs = np.sort(sc[lo:hi])
        print(f"\n=== callers of {label} ({va:#x}): {len(pcs)} ===")
        for pc in pcs:
            print(f"  {int(pc):016x}  {label_for(int(pc))}".rstrip())


if __name__ == "__main__":
    main()
