# Utilities

Standalone helpers for reverse-engineering and patching **Mach-O and PE**
binaries, on **arm64, x86_64 and i386**. Each is a single `uv` script with
inline dependencies — run it directly (`./fdis.py ...`); the first run builds
its environment, later runs are fast.

**Conventions**

- The container (Mach-O thin/fat, or PE32/PE32+) is detected automatically;
  `--arch` selects the slice of a fat Mach-O.
- `<arch>` is `arm64`, `x86_64` or `x86` (i386).
- Addresses are **virtual addresses** — for Mach-O exactly as `nm` prints them,
  for PE the `ImageBase + RVA` that `objdump` / `nm` print.
- `./test_utils.py` checks every tool against `otool` / `nm` / `codesign`
  ground truth; `./bench.sh` benchmarks them with
  [hyperfine](https://github.com/sharkdp/hyperfine).

---

## fdis.py — single-site disassembler

```bash
./fdis.py <file> <addr> [n] [--arch arm64|x86_64|x86]
```

Disassembles `n` instructions (default 10) starting at `addr`, by seeking
straight there — far faster than dumping all of `__TEXT`. Columns:
`vmaddr  fileoff  bytes  mnemonic  operands`.

```bash
./fdis.py BCompare 0x1000d7740 4          # arm64
./fdis.py BCompare 0x1000d17a0 4 --arch x86_64
./fdis.py mod.o 0x0 8 --arch x86
```

## find_callers.py — who calls X

```bash
./find_callers.py <file> <target>... [--arch ...] [--no-symbols]
```

Prints every direct call site of each target, annotated with the containing
symbol. A target is `0xADDR`, `0xADDR=Label`, or a symbol-name **substring**
(resolved from the symbol table).

```bash
./find_callers.py BCompare CHECKPROTECTION
./find_callers.py BCompare 0x1001fc060 --no-symbols
```

arm64 is exact (`BL` is fixed-width). The x86/x86_64 scan keys off the `0xE8`
opcode byte: it finds every real direct call but can add a spurious one. Misses
indirect/PLT/vtable calls, arm64 tail-calls, and the other arch slice.

## find_refs.py — who references X

```bash
./find_refs.py <file> <target>... [--str <text>] [--arch ...]
               [--no-code] [--no-ptr] [--no-symbols]
```

Reports two kinds of reference to each target:

- `code` — instructions that access the address.
- `data` — pointer-sized values equal to it (vtables, dispatch tables,
  `RESSTR` indirection) — the indirection a call scan cannot see.

`--str <text>` locates a string literal first, then reports references to it.

```bash
./find_refs.py BCompare 0x101e38228            # by address
./find_refs.py BCompare BCTRIALLEFT            # by symbol-name substring
./find_refs.py BCompare --str "LICENSE KEY"
./find_refs.py BCompare --no-ptr 0x101e38228   # skip the pointer scan
```

arm64 code refs are exact across every executable section (`__text`, `__stubs`,
`__objc_stubs`, …), not just `__text`; x86/x86_64 match the 32-bit
displacement/immediate field vectorized (near-exact). On i386, PIC references
through the GOT are not found.

## find_selrefs.py — Objective-C selector consumers

```bash
./find_selrefs.py <file> <selector>... [--arch ...] [--no-symbols]
```

Resolves an Objective-C selector to its `__objc_selrefs` slot(s), then reports
every code site that loads one, across all executable sections. This is the
two-hop chain `find_refs.py` cannot do in one query: `__objc_methname` string →
`__objc_selrefs` pointer → code load. Selector loads are routinely emitted in
`__objc_stubs` (not `__text`), so a `__text`-only scan reports "(none)" for a
method that is very much called.

```bash
./find_selrefs.py BCompare isDemo
./find_selrefs.py BCompare --arch x86_64 objectForKey:
```

When a load lands in `__objc_stubs`, its enclosing symbol is the
`_objc_msgSend$<selector>` thunk — hand that to `find_callers.py` for the real
callers, because nothing calls the method directly. Selectors with no
`__objc_selrefs` slot (resolved at runtime) and encoded chained-fixup slots are
reported explicitly, never silently skipped.

## find_strings.py — strings with their addresses

```bash
./find_strings.py <file> [pattern] [--arch ...] [--min N] [--section NAME]
                  [--regex] [--all] [--count]
```

Lists printable strings with their virtual address and section, so a string can
be handed straight to `find_refs.py` (or `fdis.py`). Scans section contents
only, so symbol-table/relocation noise (`strings` over the whole file) is
excluded, and skips instruction sections (`__text` &c.) unless `--all`.
`--section` is repeatable; `--min` defaults to 4.

```bash
./find_strings.py BCompare "Trial"
./find_strings.py BCompare --regex "Trial.*expire" --section __const
./find_strings.py BCompare "LICENSE KEY" --count
```

## patch.py — declarative applier

```bash
./patch.py <file> <manifest> [--dry-run] [--check] [--resign <app>]
```

Applies a text manifest, one site per line:

```
<arch> <site> <old_hex> <new_hex>   # comment
```

- `<arch>` — `arm64` | `x86_64` | `x86` | `*` (`*` = every slice).
- `<site>` — a VA (`0x1000d7740`) or an **exact symbol name** (unlike the
  find_* targets, this must match the whole name), optional `+0xoff`. The name
  may contain spaces (ObjC `-[Class sel:]`); the suffix is an offset only when
  it is hex. Symbol sites survive updates that move addresses.
- `<old_hex>` — the pristine bytes, asserted before writing (`-` to skip).
- `<new_hex>` — the replacement, the **same length** as `old_hex`.

Every site is asserted before any byte is written: a mismatch aborts with
nothing written. `--dry-run` asserts only; `--check` verifies the new bytes are
already present; `--resign <app>` re-signs afterwards.

```
arm64  0x1000d7740 fd7bbfa9fd030091 60008052c0035fd6           # by address
x86_64 0x1000d17a0 554889e5488d b803000000c3                  # by address
arm64  _CERTDECODE$_$TCERTDECODER_$__$$_GETSTATUS$$TSTATUS - c0035fd6   # by symbol
arm64  -[CXApplication isDemo]+0x8 00686838 00008052          # ObjC symbol
```

```bash
./patch.py BCompare fix.patch --dry-run
./patch.py "My App.app/Contents/MacOS/App" fix.patch --resign "My App.app"
```

## resign.py — re-sign a binary or bundle

```bash
./resign.py <path> [--runtime] [--identity ID] [--no-verify]
```

Ad-hoc signs **without** the hardened runtime by default — the combination that
lets a re-signed app load its freshly re-signed bundled dylibs (keeping the
runtime enables library validation, which rejects them). `.app` bundles or
directories with `Contents/Info.plist` are signed `--deep`, then verified.

```bash
./resign.py "My App.app"
./resign.py MyBinary --runtime --identity "Developer ID Application: ..."
```

Mach-O only (`codesign`); it refuses a PE image — Authenticode signing needs
`signtool` / `osslsigncode`.

---

## Checks and benchmarks

```bash
./test_utils.py    # 45 tests: builds clang fixtures, checks vs otool/nm/codesign
./bench.sh         # hyperfine timings per arch (set BP_ARM/BP_X86/BP_I386 for big binaries)
```
