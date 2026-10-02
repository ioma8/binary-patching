#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy", "capstone"]
# ///
"""find_selrefs.py <file> <selector>... [--arch arm64|x86_64|x86] [--no-symbols]

Objective-C selector consumers. Resolves each selector name to its
`__objc_selrefs` slot(s), then reports every code site that loads a slot
(`adrp+ldr` on arm64, RIP-relative on x86_64), across **all** executable
sections.

This is the two-hop chain `find_refs.py` cannot answer in one query:
`__objc_methname` string -> `__objc_selrefs` pointer -> code load. Selector
loads are routinely emitted in `__objc_stubs`, not `__text`, so a `__text`-only
scan reports "(none)" for a method that is very much called.

Columns: `load_site  section  kind  -> selref_va  enclosing_symbol`.

When a load lands in `__objc_stubs`, its enclosing symbol is the
`_objc_msgSend$<selector>` thunk — hand that symbol to `find_callers.py` for the
real consumers, because no one calls the method directly. Full chain:
`find_selrefs.py app isDemo` -> stub -> `find_callers.py app _objc_msgSend$isDemo`.

Misses: selectors resolved at runtime (`sel_registerName`) with no selref slot;
encoded (chained-fixup) selref slots; the other arch slices.

```bash
./find_selrefs.py MyApp isDemo
./find_selrefs.py MyApp --arch x86_64 isDemo
```
"""
import sys

import binfmt
import numpy as np

# The arm64/x86 address decoders live in find_refs.py — one source of truth.
from find_refs import code_refs, code_refs_x86

NLIST = {True: np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                         ("n_desc", "<u2"), ("n_value", "<u8")]),
         False: np.dtype([("n_strx", "<u4"), ("n_type", "u1"), ("n_sect", "u1"),
                          ("n_desc", "<u2"), ("n_value", "<u4")])}
KIND = {0: "adrp+add", 1: "adrp+ldr", 2: "adrp+str", 3: "adrp+ldr32",
        4: "adrp+str32", 5: "adr"}


def find_section(img, name: str):
    for sn, sva, _vsize, foff, fsize, _code, _loaded in img.sections:
        if sn == name:
            return sva, fsize, foff
    return None


def section_of(img, va: int) -> str:
    for name, sva, vsize, _fo, filesize, _c, _l in img.sections:
        if sva <= va < sva + min(vsize, filesize):
            return name
    return "?"


def exact_vas(img, sect, needle: bytes):
    """VAs of NUL-delimited exact occurrences of `needle` in a section."""
    sva, fsize, foff = sect
    out, p, end = [], foff, foff + fsize
    while (p := img.data.find(needle, p, end)) >= 0:
        after = p + len(needle)
        if after < len(img.data) and img.data[after] == 0 \
                and (p == foff or img.data[p - 1] == 0):
            out.append(sva + (p - foff))
        p += 1
    return out


# ponytail: only plain (LC_DYLD_INFO rebase) pointers are decoded. A modern
# binary uses LC_DYLD_CHAINED_FIXUPS and stores an encoded rebase in the slot;
# upgrading means reading dyld_chained_fixups_header -> starts_in_segment
# pointer_format and decoding the target bits (64_OFFSET = image_base + low36).
def pointer_slots(img, sect, value: int):
    """VAs of pointer-sized words in a section equal to `value`."""
    sva, fsize, foff = sect
    psz = 8 if img.is64 else 4
    words = np.frombuffer(img.data, "<u8" if img.is64 else "<u4",
                          count=fsize // psz, offset=foff)
    return [int(sva + i * psz) for i in np.flatnonzero(words == value)]


def load_symbols(img, on: bool):
    """(sym_va, sym_strx, strbase) for Mach-O defined symbols, sorted by VA."""
    empty = np.empty(0, np.int64)
    if not on or img.fmt != "macho" or not img.symtab:
        return empty, empty, 0
    symoff, nsyms, stroff, _ss = img.symtab
    arr = np.frombuffer(img.data, dtype=NLIST[img.is64], count=nsyms,
                        offset=img.base + symoff)
    keep = ((arr["n_type"] & 0x0E) == 0x0E) & ((arr["n_type"] & 0xE0) == 0)  # N_SECT
    sel = np.flatnonzero(keep)
    kva = arr["n_value"][sel].astype(np.int64)
    kstrx = arr["n_strx"][sel].astype(np.int64)
    order = np.argsort(kva, kind="stable")
    return kva[order], kstrx[order], img.base + stroff


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
    path, selectors = pos[0], pos[1:]

    img = binfmt.load(path, arch)
    meth = find_section(img, "__objc_methname")
    sref = find_section(img, "__objc_selrefs")
    if meth is None or sref is None:
        raise SystemExit(f"{path}: no __objc_methname/__objc_selrefs section "
                         f"(not an Objective-C image, or stripped)")

    sym_va, sym_strx, strbase = load_symbols(img, symbols_on)
    names: dict[int, str] = {}

    def label_for(va: int) -> str:
        if sym_va.size == 0:
            return ""
        j = int(np.searchsorted(sym_va, va, "right")) - 1
        if j < 0 or va - int(sym_va[j]) > 0x100000:
            return ""
        strx = int(sym_strx[j])
        if strx not in names:
            o = strbase + strx
            names[strx] = img.data[o:img.data.index(b"\0", o)].decode("utf-8", "replace")
        off = va - int(sym_va[j])
        return names[strx] + (f"+{off:#x}" if off else "")

    def code_loads(wanted: set[int]):
        """(kind, pc, tgt) for every code load of a wanted address."""
        hits = []
        for cva, csize, coff in img.code:
            if img.arch == "arm64":
                buf = np.frombuffer(img.data, dtype=np.uint8, count=csize, offset=coff)
                p, t, k = code_refs(buf, cva)
                for pc, tgt, kind in zip(p.tolist(), t.tolist(), k.tolist()):
                    if tgt in wanted:
                        hits.append((KIND.get(int(kind), "code"), pc, tgt))
            else:
                n = int(np.searchsorted(sym_va, cva + csize))
                lo = int(np.searchsorted(sym_va, cva))
                funcs = sorted({int(v) for v in sym_va[lo:n]})
                p, t = code_refs_x86(img.data, img.is64, (cva, csize, coff),
                                     funcs, set(wanted))
                for pc, tgt in zip(p.tolist(), t.tolist()):
                    if tgt in wanted:
                        hits.append(("rip", pc, tgt))
        return hits

    for sel in selectors:
        name_vas = exact_vas(img, meth, sel.encode())
        print(f'\n=== selector "{sel}": {len(name_vas)} in __objc_methname ===')
        if not name_vas:
            print("  (none)")
            continue
        for name_va in name_vas:
            print(f"  methname  {name_va:016x}  __objc_methname")
            slots = pointer_slots(img, sref, name_va)
            if not slots:
                if getattr(img, "chained", False):
                    print("    (chained fixups: slots hold encoded rebases, not "
                          "plain VAs — see the note in find_selrefs.py)")
                else:
                    print("    (no __objc_selrefs slot — resolved at runtime?)")
                continue
            for slot in slots:
                print(f"  selref    {slot:016x}  __objc_selrefs")
            hits = code_loads(set(slots))
            if not hits:
                print("    (no code load)")
            for kind, pc, tgt in sorted(hits, key=lambda r: r[1]):
                lab = label_for(pc)
                tail = f"  {lab}" if lab else ""
                print(f"  load      {pc:016x}  {section_of(img, pc):<18} "
                      f"{kind:<9} -> {tgt:016x}{tail}")


if __name__ == "__main__":
    main()
