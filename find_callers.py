#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""find_callers.py <file> <target>... [--arch arm64|x86_64|x86] [--no-symbols]

Fast caller finder for Mach-O **and PE** binaries (arm64, x86_64, i386). Scans
executable sections for direct calls — `BL` (arm64) or `call rel32` (x86) — and
prints every call site of each target, annotated with the containing symbol.

Targets are `0xADDR`, `0xADDR=Label`, or a symbol-name substring resolved from
the symbol table. The scan is vectorized (NumPy) and names are decoded lazily,
so a 56 MB slice resolves callers in ~10 ms.

Columns: `call_site  caller_symbol+offset`.

Misses: indirect calls (PLT/GOT/vtable, x86 `call [..]`), arm64 tail-calls (`B`),
and calls in the other architecture slices. arm64 is exact (BL is a fixed-width,
word-aligned opcode). The x86 scan keys off the `0xE8` opcode byte and is a
heuristic: it finds every real direct call, but can add a spurious caller.
"""
import sys

import binfmt
import numpy as np

NLIST = {True: np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                         ("n_desc", "<u2"), ("n_value", "<u8")]),
         False: np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                          ("n_desc", "<u2"), ("n_value", "<u4")])}


def call_sites(buf: "np.ndarray", arch: str, text_va: int):
    """(call_pc, target_va) arrays for every direct call in a code region."""
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
    arch, symbols_on, pos, args, i = None, True, [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--arch":
            arch, i = args[i + 1], i + 2
        elif a.startswith("--arch="):
            arch, i = a.split("=", 1)[1], i + 1
        elif a == "--no-symbols":
            symbols_on, i = False, i + 1
        else:
            pos.append(a)
            i += 1
    if len(pos) < 2 or (arch is not None and arch not in binfmt.ORDER):
        print(__doc__)
        raise SystemExit(1)
    path, target_args = pos[0], pos[1:]

    img = binfmt.load(path, arch)
    if not img.code:
        raise SystemExit("no executable section")

    call_pc, target = [], []
    for va, size, fileoff in img.code:
        buf = np.frombuffer(img.data, dtype=np.uint8, count=size, offset=fileoff)
        p, t = call_sites(buf, img.arch, va)
        call_pc.append(p)
        target.append(t)
    call_pc = np.concatenate(call_pc) if call_pc else np.empty(0, np.int64)
    target = np.concatenate(target) if target else np.empty(0, np.int64)

    # ---- symbol table --------------------------------------------------------
    name_cache: dict[int, str] = {}
    sym_strbase = 0
    kstrx = kva = np.empty(0, np.int64)
    sym_va, sym_strx = np.empty(0, np.int64), np.empty(0, np.int64)
    pe_names: list[str] = []
    all_strx = None
    _uniq: list = []

    def name_at(strx: int) -> str:
        if strx not in name_cache:
            o = sym_strbase + strx
            name_cache[strx] = img.data[o:img.data.index(b"\0", o)].decode("utf-8", "replace")
        return name_cache[strx]

    def name_starts():
        if not _uniq:
            _uniq.append(np.unique(all_strx) if all_strx is not None and all_strx.size
                         else np.empty(0, np.uint32))
        return _uniq[0]

    if symbols_on and img.fmt == "macho" and img.symtab:
        symoff, nsyms, stroff, _ss = img.symtab
        sym_strbase = img.base + stroff
        arr = np.frombuffer(img.data, dtype=NLIST[img.is64], count=nsyms,
                            offset=img.base + symoff)
        keep = ((arr["n_type"] & 0x0E) == 0x0E) & ((arr["n_type"] & 0xE0) == 0)  # N_SECT
        sel = np.flatnonzero(keep)
        kstrx = arr["n_strx"][sel].astype(np.int64)
        kva = arr["n_value"][sel].astype(np.int64)
        all_strx = arr["n_strx"]
        if kva.size and np.all(np.diff(kva) >= 0):
            sym_va, sym_strx = kva, kstrx
        elif kva.size:
            order = np.argsort(kva, kind="stable")
            sym_va, sym_strx = kva[order], kstrx[order]
    elif symbols_on and img.fmt == "pe" and img.pe_syms:
        pairs = sorted(img.pe_syms, key=lambda x: x[1])
        sym_va = np.array([v for _n, v in pairs], dtype=np.int64)
        pe_names = [n for n, _v in pairs]

    def label_for(va: int) -> str:
        if sym_va.size == 0:
            return ""
        j = int(np.searchsorted(sym_va, va, "right")) - 1
        if j < 0 or va - sym_va[j] > 0x100000:
            return ""
        off = va - int(sym_va[j])
        name = name_at(int(sym_strx[j])) if img.fmt == "macho" else pe_names[j]
        return name + (f"+{off:#x}" if off else "")

    # ---- resolve targets -----------------------------------------------------
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
        before = len(targets)
        if img.fmt == "pe":
            for name, va in img.pe_syms:
                if arg in name:
                    add(va, name)
        else:
            if sym_va.size == 0:
                raise SystemExit(f"target {arg!r}: no symbol table to resolve against")
            strbase, end = sym_strbase, sym_strbase + img.symtab[3]
            hits, p = [], strbase
            while (p := img.data.find(arg.encode(), p, end)) >= 0:
                hits.append(p - strbase)
                p += 1
            if hits:
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
