"""Format-agnostic image loader shared by the helpers: Mach-O and PE.

`load(path, arch)` returns one architecture's `Image` (virtual addresses,
sections, code regions, symbols). `arches(path)` lists what a file contains.
Supports arm64 / x86_64 / x86 (i386) in both containers. Pure stdlib.
"""
import struct

ORDER = ("arm64", "x86_64", "x86")
MACHO_CPU = {"arm64": 0x0100000C, "x86_64": 0x01000007, "x86": 0x00000007}
PE_MACHINE = {"arm64": 0xAA64, "x86_64": 0x8664, "x86": 0x014C}

FAT = (0xCAFEBABE, 0xCAFEBABF)
MH = (0xFEEDFACE, 0xFEEDFACF)
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02


class Image:
    def __init__(self, fmt, arch, is64, data, base, image_base, segs, sections,
                 code, header_end, symtab=None, pe_syms=None):
        self.fmt = fmt                      # "macho" | "pe"
        self.arch = arch                    # "arm64" | "x86_64" | "x86"
        self.is64 = is64
        self.data = data                    # whole file
        self.base = base                    # slice start (0 for thin/PE)
        self.image_base = image_base
        self.segs = segs                    # [(name, va, vsize, fileoff, filesize)]
        self.sections = sections            # [(name, va, vsize, fileoff, filesize, code, loaded)]
        self.code = code                    # [(va, size, fileoff)]
        self.header_end = header_end
        self.symtab = symtab                # Mach-O (symoff, nsyms, stroff, strsize)
        self.pe_syms = pe_syms or []        # PE [(name, va)]

    @property
    def text(self):
        return self.code[0] if self.code else None

    def va_to_off(self, va):
        for _n, vmaddr, vmsize, fileoff, filesize in self.segs:
            if vmaddr <= va < vmaddr + vmsize:
                rel = va - vmaddr
                return fileoff + rel if rel < filesize else None
        return None

    def off_to_va(self, off):
        for name, vmaddr, _vsize, fileoff, filesize in self.segs:
            if fileoff <= off < fileoff + filesize and name not in ("__PAGEZERO", "__LINKEDIT"):
                return vmaddr + (off - fileoff)
        return None


def _cstr(data, o, limit=None):
    try:
        e = data.index(b"\0", o, limit) if limit is not None else data.index(b"\0", o)
    except ValueError:                                  # no NUL in range (fixed-width field)
        e = limit if limit is not None else len(data)
    return data[o:e]


def _macho_slice(data, arch):
    """(base, size, is64) of the requested Mach-O slice, or None."""
    if struct.unpack("<I", data[:4])[0] in MH:                      # thin
        cpu = struct.unpack("<I", data[4:8])[0]
        return (0, len(data), True) if cpu == MACHO_CPU[arch] else None
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in FAT:
        return None
    off = 8
    for _ in range(struct.unpack(">I", data[4:8])[0]):
        if magic == FAT[1]:
            cpu = struct.unpack(">I", data[off:off + 4])[0]
            o, size = struct.unpack(">QQ", data[off + 8:off + 24])
            off += 32
        else:
            cpu, _sub, o, size, _al = struct.unpack(">IIIII", data[off:off + 20])
            off += 20
        if cpu == MACHO_CPU[arch]:
            return o, size, struct.unpack("<I", data[o:o + 4])[0] in (MH[1],)
    return None


def _load_macho(data, base, arch):
    is64 = struct.unpack("<I", data[base:base + 4])[0] == MH[1]
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    hdr = base + (32 if is64 else 28)
    off, segs, sections, code, symtab = hdr, [], [], [], None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            name = _cstr(data, off + 8, off + 24).decode()
            if is64:
                vm, vms, fo, fs = struct.unpack_from("<QQQQ", data, off + 24)
                nsects, so, secsz = struct.unpack_from("<I", data, off + 64)[0], off + 72, 80
            else:
                vm, vms, fo, fs = struct.unpack_from("<IIII", data, off + 24)
                nsects, so, secsz = struct.unpack_from("<I", data, off + 48)[0], off + 56, 68
            segs.append((name, vm, vms, base + fo, fs))
            for _ in range(nsects):
                sn = _cstr(data, so, so + 16).decode()
                if is64:
                    a, sz, sec_off = struct.unpack_from("<QQI", data, so + 32)
                    fl = struct.unpack_from("<I", data, so + 64)[0]
                else:
                    a, sz, sec_off = struct.unpack_from("<III", data, so + 32)
                    fl = struct.unpack_from("<I", data, so + 56)[0]
                is_code = sn == "__text" or bool(fl & (0x80000000 | 0x400))
                if sec_off and sz:
                    sections.append((sn, a, sz, base + sec_off, sz, is_code, True))
                    if is_code:
                        code.append((a, sz, base + sec_off))
                so += secsz
        elif cmd == LC_SYMTAB:
            symtab = tuple(struct.unpack_from("<IIII", data, off + 8))
        off += cmdsize
    return Image("macho", arch, is64, data, base, 0, segs, sections, code,
                 off, symtab=symtab)


def _load_pe(data, arch):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        raise SystemExit("not a PE image")
    machine = struct.unpack_from("<H", data, e + 4)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    psym, nsym = struct.unpack_from("<II", data, e + 12)
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        is64, ib = True, struct.unpack_from("<Q", data, opt + 24)[0]
    elif magic == 0x10B:
        is64, ib = False, struct.unpack_from("<I", data, opt + 28)[0]
    else:
        raise SystemExit("unknown PE optional-header magic")
    so = opt + optsz
    rows = []
    for i in range(nsec):
        rec = so + i * 40
        raw = data[rec:rec + 8]
        if raw[:1] == b"/" and psym:                       # long name in COFF strtab
            stro = psym + nsym * 18 + int(raw[1:].rstrip(b"\0") or b"0")
            name = _cstr(data, stro).decode("latin1")
        else:
            name = raw.rstrip(b"\0").decode("latin1")
        vsz, rva, rsz, roff = struct.unpack_from("<IIII", data, rec + 8)
        ch = struct.unpack_from("<I", data, rec + 36)[0]
        loaded = bool(ch & 0x40000000) and not (ch & 0x02000000)   # READ, not DISCARDABLE
        rows.append((i + 1, name, ib + rva, vsz, roff, rsz, ch, loaded))
    segs = [(r[1], r[2], r[3], r[4], r[5]) for r in rows if r[4] and r[5]]
    sections, code = [], []
    for _idx, name, va, vsz, roff, rsz, ch, loaded in rows:
        if not roff or not rsz:
            continue
        is_code = bool(ch & 0x20000000) or bool(ch & 0x20)        # EXECUTE or CODE
        sections.append((name, va, vsz, roff, rsz, is_code, loaded))
        if is_code:
            code.append((va, rsz, roff))
    syms = _pe_symbols(data, psym, nsym, rows, ib)
    return Image("pe", arch, is64, data, 0, ib, segs, sections, code,
                 so + nsec * 40, pe_syms=syms)


def _pe_symbols(data, psym, nsym, rows, ib):
    out = []
    if not psym or not nsym:
        return out
    strtab = psym + nsym * 18
    by_idx = {r[0]: r for r in rows}
    i = 0
    while i < nsym:
        rec = psym + i * 18
        raw = data[rec:rec + 8]
        if raw[:4] == b"\0\0\0\0":
            name = _cstr(data, strtab + struct.unpack_from("<I", data, rec + 4)[0]).decode("latin1")
        else:
            name = raw.rstrip(b"\0").decode("latin1")
        value, sect, _typ, stor, aux = struct.unpack_from("<IhHBB", data, rec + 8)
        match = by_idx.get(sect)
        if match and stor in (2, 3) and name and not (value == 0 and name == match[1]):
            out.append((name, match[2] + value))                  # section VA + section-relative value
        i += 1 + aux
    return out


def arches(path):
    """Architecture names present, in preference order (arm64 first)."""
    data = open(path, "rb").read()
    if data[:2] == b"MZ":
        machine = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0]
        name = next((a for a, m in PE_MACHINE.items() if m == machine), None)
        return [name] if name else []
    return [a for a in ORDER if _macho_slice(data, a)]


def load(path, arch=None):
    """The requested (or preferred) architecture's Image."""
    data = open(path, "rb").read()
    if data[:2] == b"MZ":
        machine = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0]
        name = next((a for a, m in PE_MACHINE.items() if m == machine), None)
        if name is None:
            raise SystemExit(f"unsupported PE machine {machine:#x}")
        if arch is not None and arch != name:
            raise SystemExit(f"--arch {arch}: {path} is a thin {name} PE image")
        return _load_pe(data, name)
    present = arches(path)
    if not present:
        raise SystemExit("not a Mach-O or PE file")
    pick = arch or next((a for a in ORDER if a in present), None)
    if pick is None:
        raise SystemExit(f"no supported architecture in {path}")
    sl = _macho_slice(data, pick)
    if sl is None:
        raise SystemExit(f"--arch {pick}: not present ({', '.join(present)})")
    base, _size, _is64 = sl
    return _load_macho(data, base, pick)
