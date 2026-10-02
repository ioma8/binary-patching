#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""patch.py <file> <manifest> [--dry-run] [--check] [--resign <app>]

Apply a declarative patch manifest to a Mach-O **or PE** binary, asserting the
pristine bytes at every site before writing any of them.

Manifest: one site per line, `<arch> <site> <old_hex> <new_hex>  # comment`
  arch    arm64 | x86_64 | x86 | *   (* = every architecture present)
  site    a virtual address (`0x1000d7740`) or an exact symbol name, optional
          `+0xoff`. Symbol sites survive updates that move addresses.
  old_hex expected bytes (asserted; `-` to skip)
  new_hex replacement bytes (must be the same length as old_hex)

All sites are verified first; if any assert fails, nothing is written.
  --dry-run        verify only, never write
  --check          verify the NEW bytes are already present (is it patched?)
  --resign <app>   re-sign with resign.py afterwards (Mach-O only)

Example manifest:
  arm64  0x1000d7740 fd7bbfa9fd030091 60008052c0035fd6       # by address
  x86_64 0x1000d17a0 554889e5488d b803000000c3            # by address
  arm64  _CERTDECODE$_$TCERTDECODER_$__$$_GETSTATUS$$TSTATUS - c0035fd6
"""
import os
import struct
import subprocess
import sys

import binfmt


def lookup_symbol(data: bytes, base: int, is64: bool, st, name: str):
    """Mach-O: unslid VA of an exact, defined symbol name, or None.

    Finds the name in the string table, then the nlist entry whose n_strx points
    at it — a couple of C-speed byte scans, no per-symbol Python loop.
    """
    if st is None:
        return None
    symoff, nsyms, stroff, strsize = st
    esz, vsz = (16, 8) if is64 else (12, 4)
    symoff, stroff = base + symoff, base + stroff
    want, end = name.encode(), stroff + strsize
    p = data.find(want, stroff, end)
    while p >= 0:
        if p + len(want) < end and data[p + len(want)] == 0 \
                and (p == stroff or data[p - 1] == 0):
            pat = struct.pack("<I", p - stroff)          # n_strx to find
            region_end, s = symoff + nsyms * esz, symoff
            while (q := data.find(pat, s, region_end)) >= 0:
                if (q - symoff) % esz == 0:               # the n_strx field
                    n_type = data[q + 4]
                    if (n_type & 0x0E) == 0x0E and (n_type & 0xE0) == 0:  # N_SECT
                        return int.from_bytes(data[q + 8:q + 8 + vsz], "little")
                s = q + 1
        p = data.find(want, p + 1, end)
    return None


def exact_symbol(img, data, name: str):
    if img.fmt == "pe":
        return next((v for n, v in img.pe_syms if n == name), None)
    return lookup_symbol(data, img.base, img.is64, img.symtab, name)


def parse_loc(loc: str):
    """'0xADDR[+off]' -> ('va', addr); 'sym[+0xoff]' -> ('sym', name, off)."""
    base, plus, offs = loc.rpartition("+")
    if not plus:
        base, offs = loc, "0"
    if base.lower().startswith("0x"):
        return ("va", int(base, 16) + int(offs, 16))
    return ("sym", base, int(offs, 16))


def parse_manifest(text: str):
    sites = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        p = line.split()
        if len(p) != 4:
            raise SystemExit(f"manifest line {ln}: expected <arch> <site> <old_hex> <new_hex>")
        arch, loc, old_s, new_s = p[0].lower(), p[1], p[2], p[3]
        if arch not in ("arm64", "x86_64", "x86", "*"):
            raise SystemExit(f"manifest line {ln}: arch must be arm64|x86_64|x86|*")
        old = None if old_s == "-" else bytes.fromhex(old_s.removeprefix("0x"))
        new = bytes.fromhex(new_s.removeprefix("0x"))
        if old is not None and len(old) != len(new):
            raise SystemExit(f"manifest line {ln}: old/new byte lengths differ")
        sites.append((ln, arch, loc, old, new))
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
    present = binfmt.arches(path)
    if not present:
        raise SystemExit("not a Mach-O or PE file")
    images = {a: binfmt.load(path, a) for a in present}
    if resign and any(im.fmt == "pe" for im in images.values()):
        raise SystemExit("--resign: PE Authenticode needs signtool/osslsigncode, "
                         "not codesign (resign.py is macOS-only)")

    actions, errors = [], []
    for ln, arch, loc, old, new in parse_manifest(open(manifest).read()):
        kind, a, *rest = parse_loc(loc)
        if arch != "*" and arch not in present:
            errors.append(f"line {ln}: no {arch} image in this file ({', '.join(present)})")
            continue
        for name in (present if arch == "*" else [arch]):
            img = images[name]
            if kind == "va":
                va = a
            else:
                va = exact_symbol(img, data, a)
                if va is None:
                    errors.append(f"line {ln}: symbol {a!r} not found in {name}")
                    continue
                va += rest[0]
            fo = img.va_to_off(va)
            if fo is None or fo + len(new) > len(data):
                errors.append(f"line {ln}: {loc} -> {va:#x} not mapped in {name}")
                continue
            cur = bytes(data[fo:fo + len(new)])
            want = new if check else (old if old is not None else cur)
            if old is not None and not check and cur != want:
                errors.append(f"line {ln}: {name} {loc} -> {va:#x} pristine bytes differ:\n"
                              f"      expected {want.hex()}\n      found    {cur.hex()}")
            elif check and cur != new:
                errors.append(f"line {ln}: {name} {loc} -> {va:#x} not patched:\n"
                              f"      expected {new.hex()}\n      found    {cur.hex()}")
            actions.append((name, loc, kind, va, fo, cur, new))

    if errors:
        print("PATCH ABORTED — no bytes written:")
        for e in errors:
            print("  " + e)
        raise SystemExit(1)

    verb = "verified" if (dry or check) else "patched"
    for name, loc, kind, va, fo, cur, new in actions:
        extra = f"  ({loc})" if kind == "sym" else ""
        print(f"  {verb} {name:<7} va={va:#010x} off={fo:#08x}{extra}  {cur.hex()} -> {new.hex()}")
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
