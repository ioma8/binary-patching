#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""find_refs.py <file> <target>... [--str <text>] [--arch arm64|x86_64]
                [--no-code] [--no-ptr] [--no-symbols]

Find references to an address, symbol, or string in a Mach-O binary.

  code — instructions that materialize or access the address: `adrp+add`,
         `adrp+ldr/str`, `adr`
  ptr  — 8-byte pointer values equal to the address: vtables, dispatch tables,
         RESSTR indirection (things a code scan cannot see)

Targets are `0xADDR` or a symbol-name substring. `--str <text>` locates a string
literal first, then reports references to it. Vectorized (NumPy); ~10–30 ms on a
56 MB slice.

Columns: `kind  va  detail`.

Misses: references computed at runtime, unaligned pointers, and the other arch
slice. Run `fdis.py` to read a site, `find_callers.py` for the call graph.
"""
import struct
import sys

import numpy as np

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
NLIST64 = np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                    ("n_desc", "<u2"), ("n_value", "<u8")])
SKIP_SEGS = {"__PAGEZERO", "__LINKEDIT"}
KIND = {0: "adrp+add", 1: "adrp+ldr", 2: "adrp+str", 3: "adrp+ldr32",
        4: "adrp+str32", 5: "adr"}


def pick_slice(data: bytes, want_cpu: int):
    if struct.unpack("<I", data[:4])[0] == MH_MAGIC_64:
        return 0, len(data), struct.unpack("<I", data[4:8])[0]
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        raise SystemExit("not a Mach-O / fat Mach-O")
    nfat = struct.unpack(">I", data[4:8])[0]
    off = 8
    for _ in range(nfat):
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


def load_macho(data: bytes, base: int):
    """(segments, __text, symtab); segment/offset values are absolute."""
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off = base + 32
    segs, text, symtab = [], None, None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((name, vmaddr, vmsize, base + fileoff, filesize))
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _ in range(nsects):
                if data[so:so + 16].split(b"\0", 1)[0] == b"__text":
                    addr, size, offset = struct.unpack_from("<QQI", data, so + 32)
                    text = (addr, size, base + offset)
                so += 80
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from("<IIII", data, off + 8)
        off += cmdsize
    return segs, text, symtab


def va_to_fo(segs, va):
    for _name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= va < vmaddr + vmsize:
            off = fileoff + (va - vmaddr)
            return off if va - vmaddr < filesize else None
    return None


def fo_to_va(segs, fo):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if fileoff <= fo < fileoff + filesize and name not in ("__PAGEZERO", "__LINKEDIT"):
            return vmaddr + (fo - fileoff)
    return None


def lookahead(arr, k):
    out = np.zeros_like(arr)
    if k < arr.size:
        out[: arr.size - k] = arr[k:]
    return out


def code_refs(buf, text_va):
    """(ref_pc, target, kind_code) for every adrp-paired or adr address."""
    n = len(buf) // 4
    w = buf[: n * 4].view("<u4")
    pc = text_va + np.arange(n, dtype=np.int64) * 4

    # adrp: op=1, bits[28:24]=10000
    is_adrp = (w & 0x9F000000) == 0x90000000
    imm = (((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 0x3)).astype(np.int64)
    imm = (imm ^ 0x100000) - 0x100000                       # sign-extend 21-bit
    page = (pc & ~0xFFF) + (imm << 12)
    rd = (w & 0x1F).astype(np.int64)

    # memory operands that use one register as base
    add = (w & 0xFF800000) == 0x91000000
    add_ok = add & (((w >> 5) & 0x1F) == (w & 0x1F))         # add xD, xD, #imm
    l64 = (w & 0xFFC00000) == 0xF9400000
    s64 = (w & 0xFFC00000) == 0xF9000000
    l32 = (w & 0xFFC00000) == 0xB9400000
    s32 = (w & 0xFFC00000) == 0xB9000000
    scale = add_ok.astype(np.int64) * (1 << (((w >> 22) & 0x3) * 12)) \
        + l64 * 8 + s64 * 8 + l32 * 4 + s32 * 4
    kind = (add_ok * 0 + l64 * 1 + s64 * 2 + l32 * 3 + s32 * 4)
    mem = add_ok | l64 | s64 | l32 | s32
    base = ((w >> 5) & 0x1F).astype(np.int64)                  # Rn
    off = (((w >> 10) & 0xFFF).astype(np.int64)) * scale

    out_pc, out_tgt, out_kind = [], [], []
    for k in (1, 2, 3):
        m = is_adrp & lookahead(mem, k) & (rd == lookahead(base, k))
        if m.any():
            out_pc.append(pc[m])
            out_tgt.append(page[m] + lookahead(off, k)[m])
            out_kind.append(lookahead(kind, k)[m])
    # adr: op=0, bits[28:24]=10000
    is_adr = (w & 0x9F000000) == 0x10000000
    aimm = (((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 0x3)).astype(np.int64)
    aimm = (aimm ^ 0x100000) - 0x100000
    if is_adr.any():
        out_pc.append(pc[is_adr])
        out_tgt.append(pc[is_adr] + aimm[is_adr])
        out_kind.append(np.full(int(is_adr.sum()), 5, np.int64))
    if not out_pc:
        z = np.empty(0, np.int64)
        return z, z, z
    return (np.concatenate(out_pc), np.concatenate(out_tgt),
            np.concatenate(out_kind).astype(np.int64))


def main() -> None:
    arch, do_code, do_ptr, symbols_on = "arm64", True, True, True
    strs, pos, args, i = [], [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--arch":
            arch, i = args[i + 1], i + 2
        elif a.startswith("--arch="):
            arch, i = a.split("=", 1)[1], i + 1
        elif a == "--str":
            strs.append(args[i + 1])
            i += 2
        elif a == "--no-code":
            do_code, i = False, i + 1
        elif a == "--no-ptr":
            do_ptr, i = False, i + 1
        elif a == "--no-symbols":
            symbols_on, i = False, i + 1
        else:
            pos.append(a)
            i += 1
    if not pos or (len(pos) < 2 and not strs):
        print(__doc__)
        raise SystemExit(1)
    path, target_args = pos[0], pos[1:]

    want_cpu = {"arm64": CPU_ARM64, "x86_64": CPU_X86_64}[arch]
    data = open(path, "rb").read()
    base, _size, cputype = pick_slice(data, want_cpu)
    arch = "arm64" if cputype == CPU_ARM64 else "x86_64"
    if arch != "arm64" and do_code:
        raise SystemExit("code-ref scan is arm64-only; pass --no-code for x86_64")

    segs, text, symtab = load_macho(data, base)
    if text is None:
        raise SystemExit("no __text section")

    name_cache: dict[int, str] = {}
    sym_strbase = 0
    kstrx = kva = np.empty(0, np.int64)
    sym_va = sym_strx = uniq_strx = np.empty(0, np.int64)

    def name_at(strx: int) -> str:
        if strx not in name_cache:
            o = sym_strbase + strx
            name_cache[strx] = data[o:data.index(b"\0", o)].decode("utf-8", "replace")
        return name_cache[strx]

    if symbols_on and symtab is not None:
        symoff, nsyms, stroff, _ss = symtab
        sym_strbase = base + stroff
        arr = np.frombuffer(data, dtype=NLIST64, count=nsyms, offset=base + symoff)
        keep = ((arr["n_type"] & 0x0E) == 0x0E) & ((arr["n_type"] & 0xE0) == 0) \
            & (arr["n_value"] > 0)
        sel = np.flatnonzero(keep)
        kstrx = arr["n_strx"][sel].astype(np.int64)
        kva = arr["n_value"][sel].astype(np.int64)
        order = np.argsort(kva, kind="stable")
        sym_va, sym_strx = kva[order], kstrx[order]
        uniq_strx = np.unique(arr["n_strx"])

    def label_for(va: int) -> str:
        if sym_va.size == 0:
            return ""
        j = int(np.searchsorted(sym_va, va, "right")) - 1
        if j < 0 or va - sym_va[j] > 0x100000:
            return ""
        off = va - int(sym_va[j])
        return name_at(int(sym_strx[j])) + (f"+{off:#x}" if off else "")

    def section_of(va: int) -> str:
        for name, vmaddr, vmsize, _fo, filesize in segs:
            if vmaddr <= va < vmaddr + min(vmsize, filesize):
                return name
        return "?"

    # ---- resolve targets -----------------------------------------------------
    tgt: list[tuple[int, str, str]] = []   # (va, label, origin)
    seen: set[int] = set()

    def add(va: int, label: str, origin: str) -> None:
        if va not in seen:
            seen.add(va)
            tgt.append((va, label, origin))

    for arg in target_args:
        if arg.lower().startswith("0x"):
            left, _, label = arg.partition("=")
            va = int(left, 16)
            add(va, label or label_for(va) or hex(va), "address")
            continue
        if sym_va.size == 0:
            raise SystemExit(f"target {arg!r}: no symbol table to resolve against")
        hits, p = [], sym_strbase
        end = sym_strbase + symtab[3]
        while (p := data.find(arg.encode(), p, end)) >= 0:
            hits.append(p - sym_strbase)
            p += 1
        before = len(tgt)
        if hits:
            j = np.searchsorted(uniq_strx, np.array(hits), "right") - 1
            for strx in np.unique(uniq_strx[j[j >= 0]]):
                for si in np.flatnonzero(kstrx == strx):
                    add(int(kva[si]), name_at(int(strx)), "symbol")
        if len(tgt) == before:
            raise SystemExit(f"target {arg!r}: no symbol match")

    for s in strs:
        needle = s.encode()
        found, p = 0, 0
        while (p := data.find(needle, p)) >= 0:
            va = fo_to_va(segs, p)
            if va is not None:
                add(va, f'"{s}"', "string")
                found += 1
            p += 1
        if not found:
            raise SystemExit(f"string {s!r}: not found")

    # ---- scans ---------------------------------------------------------------
    ref_pc = ref_tgt = ref_kind = np.empty(0, np.int64)
    if do_code and text is not None:
        text_va, text_size, text_abs = text
        buf = np.frombuffer(data, dtype=np.uint8, count=text_size, offset=text_abs)
        ref_pc, ref_tgt, ref_kind = code_refs(buf, text_va)

    ptr_hits: dict[int, list[int]] = {}
    if do_ptr:
        tarr = np.array(sorted(seen), dtype=np.uint64)
        for name, vmaddr, _vmsize, fileoff, filesize in segs:
            if name in SKIP_SEGS or filesize < 8:
                continue
            words = np.frombuffer(data, "<u8", count=filesize // 8, offset=fileoff)
            sel = np.isin(words, tarr)
            for idx in np.flatnonzero(sel):
                ptr_hits.setdefault(int(words[idx]), []).append(int(vmaddr + idx * 8))

    # ---- report --------------------------------------------------------------
    for va, label, origin in tgt:
        origin = "" if origin == "address" else f"  [{origin}]"
        print(f"\n=== refs to {label} ({va:#x}){origin} ===")
        rows = []
        if ref_tgt.size:
            m = ref_tgt == va
            for p, k in zip(ref_pc[m], ref_kind[m]):
                p = int(p)
                rows.append((p, f"code  {p:016x}  {label_for(p) or section_of(p):<40} {KIND[int(k)]}"))
        for p in ptr_hits.get(va, []):
            rows.append((p, f"data  {p:016x}  {section_of(p)}"))
        if not rows:
            print("  (none)")
        for _key, line in sorted(rows):
            print("  " + line)


if __name__ == "__main__":
    main()
