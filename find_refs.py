#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy", "capstone"]
# ///
"""find_refs.py <file> <target>... [--str <text>] [--arch arm64|x86_64|x86]
                [--no-code] [--no-ptr] [--no-symbols]

Find references to an address, symbol, or string in a Mach-O binary (arm64,
x86_64, i386).

  code — instructions that access the address. arm64: `adrp+add`,
         `adrp+ldr/str`, `adr` (exact). x86_64: RIP-relative; i386: absolute.
         Found by matching the 32-bit displacement/immediate field vectorized
         (near-exact: ~1 in 4e9 windows is coincidence).
  ptr  — pointer-sized values equal to the address: vtables, dispatch tables,
         RESSTR indirection (things the code scan cannot see).

Targets are `0xADDR` or a symbol-name substring. `--str <text>` locates a string
literal first, then reports references to it.

Columns: `kind  va  detail`.

Misses: references computed at runtime; unaligned pointers; the other arch
slice; and, on i386, PIC references that go through the GOT rather than an
absolute address. Run `fdis.py` to read a site, `find_callers.py` for the call
graph.
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
SKIP_SEGS = {"__PAGEZERO", "__LINKEDIT"}
KIND = {0: "adrp+add", 1: "adrp+ldr", 2: "adrp+str", 3: "adrp+ldr32",
        4: "adrp+str32", 5: "adr"}


def pick_slice(data: bytes, want_cpu: int):
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


def load_macho(data: bytes, base: int, is64: bool):
    """(segments, __text, symtab); segment/offset values are absolute."""
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off = base + (32 if is64 else 28)
    segs, text, symtab = [], None, None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            name = data[off + 8:off + 24].split(b"\0", 1)[0].decode()
            if is64:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
                nsects, so, secsz = struct.unpack_from("<I", data, off + 64)[0], off + 72, 80
            else:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", data, off + 24)
                nsects, so, secsz = struct.unpack_from("<I", data, off + 48)[0], off + 56, 68
            segs.append((name, vmaddr, vmsize, base + fileoff, filesize))
            for _ in range(nsects):
                if data[so:so + 16].split(b"\0", 1)[0] == b"__text":
                    addr, size, offset = struct.unpack_from("<QQI" if is64 else "<III", data, so + 32)
                    text = (addr, size, base + offset)
                so += secsz
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
        if fileoff <= fo < fileoff + filesize and name not in SKIP_SEGS:
            return vmaddr + (fo - fileoff)
    return None


def code_refs(buf, text_va):
    """arm64: (ref_pc, target, kind) for every adrp-paired or adr address."""
    n = len(buf) // 4
    w = buf[: n * 4].view("<u4")
    top = w & 0x9F000000                                     # shared by adrp/adr
    pcs, tgts, kinds = [], [], []

    A = np.flatnonzero(top == 0x90000000)                     # adrp
    if A.size:
        wa = w[A]
        imm = (((wa >> 5) & 0x7FFFF) << 2 | ((wa >> 29) & 0x3)).astype(np.int64)
        imm = (imm ^ 0x100000) - 0x100000                     # sign-extend 21-bit
        page = ((text_va + A.astype(np.int64) * 4) & ~0xFFF) + (imm << 12)
        rd = (wa & 0x1F).astype(np.int64)
        for k in (1, 2, 3):
            B = A + k
            B = B[B < n]                                      # prefix of A+k
            if B.size == 0:
                break
            wb = w[B]
            sel = ((wb >> 5) & 0x1F).astype(np.int64) == rd[: B.size]
            if not sel.any():
                continue
            nb, wb, pg = B[sel], wb[sel], page[: B.size][sel]
            im = ((wb >> 10) & 0xFFF).astype(np.int64)
            ref = text_va + nb.astype(np.int64) * 4
            add = (wb & 0xFF800000) == 0x91000000
            if add.any():
                off = im[add] << (((wb[add] >> 22) & 0x3).astype(np.int64) * 12)
                pcs.append(ref[add])
                tgts.append(pg[add] + off)
                kinds.append(np.zeros(int(add.sum()), np.int64))
            for code, mask, sh in ((1, (wb & 0xFFC00000) == 0xF9400000, 3),
                                   (2, (wb & 0xFFC00000) == 0xF9000000, 3),
                                   (3, (wb & 0xFFC00000) == 0xB9400000, 2),
                                   (4, (wb & 0xFFC00000) == 0xB9000000, 2)):
                if mask.any():
                    pcs.append(ref[mask])
                    tgts.append(pg[mask] + (im[mask] << sh))
                    kinds.append(np.full(int(mask.sum()), code, np.int64))

    D = np.flatnonzero(top == 0x10000000)                     # adr
    if D.size:
        wd = w[D]
        aimm = (((wd >> 5) & 0x7FFFF) << 2 | ((wd >> 29) & 0x3)).astype(np.int64)
        aimm = (aimm ^ 0x100000) - 0x100000
        pcd = text_va + D.astype(np.int64) * 4
        pcs.append(pcd)
        tgts.append(pcd + aimm)
        kinds.append(np.full(D.size, 5, np.int64))

    if not pcs:
        z = np.empty(0, np.int64)
        return z, z, z
    return (np.concatenate(pcs), np.concatenate(tgts),
            np.concatenate(kinds).astype(np.int64))


def _x86_site(code, text_va, text_size, funcs, pc, md):
    """The instruction whose displacement/immediate field starts at `pc`."""
    import bisect
    if funcs:                                                # forward from the function
        a = bisect.bisect_right(funcs, pc) - 1
        start = funcs[a] if a >= 0 else text_va
        chunk = bytes(code[start - text_va: min(text_size, pc - text_va + 16)])
        for ins in md.disasm(chunk, start):
            if ins.address <= pc < ins.address + ins.size:
                return ins.address
        return None
    for s in range(pc, max(0, pc - text_va - 15) + text_va - 1, -1):   # stripped: scan back
        ins = next(md.disasm(bytes(code[s - text_va:s - text_va + 32]), s), None)
        if ins and ins.address <= pc < ins.address + ins.size:
            return ins.address
    return pc


def code_refs_x86(data, is64, text, funcs, wanted):
    """x86/x86_64: (ref_pc, target) for code refs to `wanted`, near-exact.

    A RIP-relative (x86_64) or absolute (i386) reference stores the target as a
    32-bit field, so scan every 4-byte window: `int32(code[i:i+4])` plus the
    instruction end must equal the target. Per-window coincidence is ~2^-32, so
    the candidates are real; each is then mapped to its instruction with a short
    disassembly. `k` is the trailing immediate (0/1/4 bytes). i386 PIC refs go
    through the GOT and are not found.
    """
    z = np.empty(0, np.int64)
    if not wanted or text[1] < 4:
        return z, z
    text_va, text_size, text_abs = text
    code = np.frombuffer(data, np.uint8, count=text_size, offset=text_abs)
    v = (code[:-3].astype(np.int64) | (code[1:-2].astype(np.int64) << 8)
         | (code[2:-1].astype(np.int64) << 16) | (code[3:].astype(np.int64) << 24))
    v = (v ^ 0x80000000) - 0x80000000                       # int32 windows
    idx = np.arange(v.size, dtype=np.int64)
    md = None
    pcs, tgts, seen = [], [], set()
    for t in sorted(wanted):
        hits = {}
        if is64:
            for k in (0, 1, 4):
                for i in np.flatnonzero(v + idx == t - text_va - 4 - k).tolist():
                    hits.setdefault(int(i), k)
        else:
            hits = {int(i): 0 for i in np.flatnonzero(v == t).tolist()}
        for i in hits:
            if md is None:
                import capstone
                md = capstone.Cs(capstone.CS_ARCH_X86,
                                 capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
            site = _x86_site(code, text_va, text_size, funcs, text_va + i, md)
            if site is not None and (site, t) not in seen:
                seen.add((site, t))
                pcs.append(site)
                tgts.append(t)
    return np.array(pcs, np.int64), np.array(tgts, np.int64)


def main() -> None:
    arch, do_code, do_ptr, symbols_on, explicit = "arm64", True, True, True, False
    strs, pos, args, i = [], [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--arch":
            arch, explicit, i = args[i + 1], True, i + 2
        elif a.startswith("--arch="):
            arch, explicit, i = a.split("=", 1)[1], True, i + 1
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
    if arch not in ("arm64", "x86_64", "x86"):
        raise SystemExit(f"unsupported arch {arch}")

    segs, text, symtab = load_macho(data, base, is64)
    if text is None:
        raise SystemExit("no __text section")

    name_cache: dict[int, str] = {}
    sym_strbase = 0
    kstrx = kva = np.empty(0, np.int64)
    sym_va = sym_strx = np.empty(0, np.int64)
    all_strx = None
    _uniq: list = []
    funcs: list[int] = []

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
        symoff, nsyms, stroff, _ss = symtab
        sym_strbase = base + stroff
        arr = np.frombuffer(data, dtype=NLIST[is64], count=nsyms, offset=base + symoff)
        keep = ((arr["n_type"] & 0x0E) == 0x0E) & ((arr["n_type"] & 0xE0) == 0)  # N_SECT
        sel = np.flatnonzero(keep)
        kstrx = arr["n_strx"][sel].astype(np.int64)
        kva = arr["n_value"][sel].astype(np.int64)
        all_strx = arr["n_strx"]
        if kva.size and np.all(np.diff(kva) >= 0):
            sym_va, sym_strx = kva, kstrx                # table already address-ordered
        elif kva.size:
            order = np.argsort(kva, kind="stable")
            sym_va, sym_strx = kva[order], kstrx[order]
        tva, tsz, _to = text
        funcs = sorted({int(v) for v in kva if tva <= v < tva + tsz})

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
            uniq = name_starts()
            j = np.searchsorted(uniq, np.array(hits), "right") - 1
            for strx in np.unique(uniq[j[j >= 0]]):
                for si in np.flatnonzero(kstrx == strx):
                    add(int(kva[si]), name_at(int(strx)), "symbol")
        if len(tgt) == before:
            raise SystemExit(f"target {arg!r}: no symbol match")

    for s in strs:
        needle = s.encode()
        found, seen_any, p = 0, False, 0
        while (p := data.find(needle, p)) >= 0:
            seen_any = True
            va = fo_to_va(segs, p)
            if va is not None:
                add(va, f'"{s}"', "string")
                found += 1
            p += 1
        if not found:
            where = "only in non-data segments (no ref site)" if seen_any else "not found"
            raise SystemExit(f"string {s!r}: {where}")

    # ---- scans ---------------------------------------------------------------
    ref_pc = ref_tgt = ref_kind = np.empty(0, np.int64)
    if do_code and text is not None:
        text_va, text_size, text_abs = text
        if arch == "arm64":
            buf = np.frombuffer(data, dtype=np.uint8, count=text_size, offset=text_abs)
            ref_pc, ref_tgt, ref_kind = code_refs(buf, text_va)
        else:
            ref_pc, ref_tgt = code_refs_x86(data, is64, text, funcs, set(tgt and seen))
            ref_kind = np.zeros(ref_pc.size, np.int64)

    ptr_hits: dict[int, list[int]] = {}
    if do_ptr:
        psz = 8 if is64 else 4
        tarr = np.array(sorted(seen), dtype=np.uint64)
        # start of section data: the Mach-O header + load commands hold no pointers
        hdr_end = base + (32 if is64 else 28) + struct.unpack_from("<I", data, base + 20)[0]
        for name, vmaddr, _vmsize, fileoff, filesize in segs:
            lo = max(fileoff, hdr_end)
            avail = fileoff + filesize - lo
            if name in SKIP_SEGS or avail < psz:
                continue
            words = np.frombuffer(data, "<u8" if is64 else "<u4", count=avail // psz, offset=lo)
            base_va = vmaddr + (lo - fileoff)
            sel = np.isin(words, tarr)
            for idx in np.flatnonzero(sel):
                ptr_hits.setdefault(int(words[idx]), []).append(int(base_va + idx * psz))

    # ---- report --------------------------------------------------------------
    for va, label, origin in tgt:
        origin = "" if origin == "address" else f"  [{origin}]"
        print(f"\n=== refs to {label} ({va:#x}){origin} ===")
        rows = []
        if ref_tgt.size:
            m = ref_tgt == va
            for p, k in zip(ref_pc[m], ref_kind[m]):
                p = int(p)
                detail = KIND[int(k)] if arch == "arm64" else "code"
                rows.append((p, f"code  {p:016x}  {label_for(p) or section_of(p):<40} {detail}"))
        for p in ptr_hits.get(va, []):
            rows.append((p, f"data  {p:016x}  {section_of(p)}"))
        if not rows:
            print("  (none)")
        for _key, line in sorted(rows):
            print("  " + line)


if __name__ == "__main__":
    main()
