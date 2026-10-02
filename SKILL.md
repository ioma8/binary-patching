---
name: binary-patching
description: Patch, bypass, or reverse-engineer a compiled binary without source. Reproduce and read ground truth first, trace the failing path under a debugger, find the split point where two code paths diverge, patch the narrowest site, re-sign, and verify three times. Use when the user wants to remove a check or limit, crack a license, change binary behaviour, or explain why an app, game, plugin, or library does X.
---

# Binary patching

Modify a compiled binary's behaviour without source.

## The loop

1. **Ground truth first.** Read what the target already tells you — its own
   logs, stderr, crash dumps, files written, network, UI text. Reproduce the
   behaviour. *Done when:* you can state "expected X, observed Y" in one line,
   and any crash report is timestamped against your last change.

2. **Classify.** Name the failure: **crash** (exception type + faulting address),
   **assertion** (message), **deliberate exit** (return code / clean shutdown),
   **runs-but-wrong** (visible symptom), or **signature kill**
   (`Code Signature Invalid` / `CODESIGNING`, `SIGKILL`). *Done when:* the
   category is named. Each category starts a different search — "quits after N
   seconds" is a quit, not a crash. A signature kill is the residue of a write
   to a signed image: its backtrace points wherever execution happened to be,
   not at the fault — re-sign and re-run instead of reading the stack.

3. **Trace backward.** Run under a debugger with **ASLR disabled** (runtime
   address == file offset); break on the *terminal* call (`-[NSApplication
   terminate:]`, `exit`, `abort`, the failing syscall), not the first; read the
   **full** backtrace. *Done when:* you hold the chain from symptom to terminal
   call, both halves if it is a cycle.

4. **Find the decision.** The narrowest patchable site. Blocking A but keeping
   B: capture the backtrace of *both*, find the **split point** where they
   diverge, patch there — not the shared handler. Otherwise the **choke point**
   (the one call/compare everything funnels through). Bound the search by
   **consumers**, not the whole binary — enumerate who calls or reads the
   symptom variable (a direct-call scan is exact and cheap); a getter returning
   a field is a *state* site, the *decision* is the branch that consumes it.
   Before committing, prove the candidate runs — set a breakpoint on its call
   site and see it fire. *Done when:* one function/instruction is named and
   confirmed live.

5. **Patch minimal.** Take the lowest rung that holds — constant return →
   branch flip → no-op call → replace body; patch **data** (a flag) over code
   when it will do. No-op the smallest function; assert the pristine bytes at
   the site; patch per-arch slice (emit stubs with an assembler like `rasm2` —
   hand-encoding is a bug farm); re-sign (frameworks first, then `--deep` the
   app); confirm the exact bytes landed. Patch code the target ships itself —
   bundled frameworks/dylibs are local and patchable, system frameworks are
   shared. Behaviour that lives in a compiled resource — a `nib`/storyboard, a
   plist, a PE resource — is a serialized edit, not an instruction; find the
   object that carries the state. Before mutating a structured blob, prove the
   writer by re-serializing the untouched original **byte-identical** — a writer
   that cannot reproduce the original cannot be trusted to edit it, and if the
   format parser ships no writer (Apple `nibarchive`), you write one and prove
   it the same way. *Done when:* bytes verified and `codesign --verify --deep`
   passes.

6. **Verify three times.** The bug is gone **and** the desired behaviour still
   works, three clean runs. Observe on the cheapest **reliable** signal first —
   read the program's own state back (debugger attach), then its log line, then
   the window title; pixels last. Kill every prior instance before each run.
   *Done when:* 3 green. One green run proves nothing.

## Hypothesis loop

When the root cause is not obvious, before patching: form **one** specific,
testable hypothesis — a guess about *why* the expected/observed gap exists, not
a restatement of what you saw. Run **one** surgical test that proves or
disproves it. Record the hypothesis and its conclusion in `HYPOTHESES.csv`
(`proved` / `disproved` / `need more info`). Repeat until a hypothesis is
proved. Never test two hypotheses at once; never skip the record — it is the
audit trail that stops you re-testing the same guess.

## Tooling

**Reach for the in-folder helpers first.** They are self-contained, super fast
(a 50 MB slice answers in well under half a second — 0.06–0.25 s measured — and
milliseconds on a small file), one command each, and work on **Mach-O and PE**
across **arm64 / x86_64 / i386** — no `aaa`, no whole-`__TEXT`/`.text` dump, no
flag archaeology. Only drop to `r2` / `otool` / `objdump` / `lldb` for what they
deliberately do not do: CFG/structural queries, `wx`, dynamic tracing. Usage and
examples: `UTILS.md`.

- **fdis.py** — disassembler for **arm64 / x86_64 / i386** in Mach-O and PE:
  `./fdis.py <file> <addr> [n] [--arch ...]` prints
  `vmaddr fileoff bytes mnemonic operands` by seeking straight to the address —
  one round trip, milliseconds — instead of dumping the whole `__TEXT` like
  `otool` (~510 ms) or r2 `pd` (~380 ms).
- **find_callers.py** — who calls X: `./find_callers.py <file> <0xADDR|name>...
  [--arch ...]`. Vectorized; each call site is annotated with its containing
  symbol, and the caller count is the blast radius of a patch. arm64 is exact
  (BL is fixed-width); the x86/x86_64 scan keys off the `0xE8` opcode byte — it
  finds every real direct call and may add a spurious one. Misses indirect/PLT/
  vtable calls, arm64 tail-calls and the other arch slice.
- **find_refs.py** — who references X: code refs plus pointer refs in data
  (vtables, dispatch tables, `RESSTR` indirection).
  `./find_refs.py <file> <0xADDR|name>... [--str <text>] [--arch ...]`. arm64 code
  refs (`adrp+add`, `adrp+ldr/str`, `adr`) are exact across **every** executable
  section (`__text`, `__stubs`, `__objc_stubs`, …), not just `__text`; x86/x86_64
  match the 32-bit displacement/immediate field vectorized (near-exact; only i386
  PIC refs through the GOT are missed). The pointer scan is pointer-width aware on
  every arch and catches the indirection a call scan cannot.
- **find_selrefs.py** — Objective-C selector consumers:
  `./find_selrefs.py <file> <selector>... [--arch ...]`. Resolves a selector
  through `__objc_methname` → `__objc_selrefs` → the code that loads the slot,
  across every executable section. The load usually sits in `__objc_stubs`; hand
  its enclosing `_objc_msgSend$<sel>` symbol to `find_callers.py` for the real
  callers. Reach for this instead of `find_callers.py` on an ObjC method, which
  returns 0 because callers go through that thunk.
- **find_strings.py** — strings with their **addresses** (not file offsets):
  `./find_strings.py <file> [pattern] [--section S] [--min N] [--regex]`.
  Section contents only, no symbol-table noise; skips `__text` unless `--all`;
  feeds straight into `find_refs.py`.
- **patch.py** — declarative, all-or-nothing applier: it asserts every site
  before writing any. Manifest lines `<arch> <site> <old_hex> <new_hex>` with
  `<arch>` = `arm64`/`x86_64`/`x86`/`*`, and `<site>` a VA or a symbol name
  (symbol sites survive updates that move addresses).
  `--dry-run` / `--check` / `--resign`.
- **resign.py** — `./resign.py <path> [--runtime]`: ad-hoc sign without the
  hardened runtime (the working default), then verify. Mach-O only.

External tools, as fallbacks (examples are `otool`-flavoured; use `objdump` for PE):

- **nm / otool — symbols are the map.** Survey first: an unstripped build names
  the domain (`CHECK*`, `LOAD*`, `IS*`, `Get*`); if symbols exist most of the job
  is reading names. `lipo -thin arm64` / `-create` for universal binaries.
- **r2** — for CFG/structural queries and `wx` (writes): `strings` → xrefs → a
  small `pd` window; read a field's offset/width from the instruction that
  *writes* it, never from memory of the header. Use the in-folder helpers for
  anything they already cover — `r2 -A` on a 50 MB binary is seconds to minutes.
- **lldb** — dynamic tracing, not disassembly: `settings set target.disable-aslr
  true`; `bt`; break on the terminal API. The single most decisive move. In
  stripped dylibs a symbol like `___lldb_unnamed_symbol_1f4f8` — the hex suffix
  is the file offset.
- **codesign** — `-f -s -` the framework, then `--deep --force` the app; delete
  stray bundle-root artifacts first. On a hardened-runtime app re-sign **ad-hoc
  without runtime**: library validation rejects the freshly re-signed bundled
  dylibs if runtime is kept (`resign.py` above does this).
- **osascript** — drive a user action (`tell app "X" to quit`) to capture the
  *correct* backtrace for the split-point diff, or list and diff window titles
  before/after a menu click to identify the handler with no debugger at all.

## r2 cheat sheet

`r2 -q -a arm -b 64 -c '<cmd>' <file>` — `-q` quiet, `-a arm -b 64` = arm64,
`-c` run-and-exit; add `-w` to write. Operate on a `lipo -thin arm64` slice.

| task | command |
|---|---|
| disassemble N insns — **bytes + mnemonic** | `pd N @ 0xADDR` |
| decode one insn (branch target / immediate) | `ao @ 0xADDR` |
| find a symbol's address | `is~Name` |
| find a string | `iz~substring` |
| list sections (find `__bss` for a counter) | `iS` |
| function boundaries | `af @ 0xADDR; afi @ 0xADDR` |
| disassemble a whole function | `pdf @ 0xADDR` |
| xrefs to an address | `axt 0xADDR` (run `aaa` first on stripped bins) |
| search raw bytes | `/x 1f510071` |
| write bytes (quick experiment only) | `wx c0035fd6 @ 0xADDR` |

`pd` is the source of truth for bytes — read the pristine bytes there to assert
a site, and use `ao` to decode a hand-written `b`/`cbz`/`tbz` target. Do the
real patch in Python with `patch.py` (asserts + per-slice), not `wx`.

## Blind routes (each cost real time — the correction)

- Patching state getters before knowing who reads them → find the comparison
  that produces the visible symptom first.
- Assuming a field getter *is* the decision → trace to the branch that consumes
  it. Forcing a getter's return crashes consumers that then read fields the
  alternate state never fills — patch the decision, or the getter **and** every
  newly-reached consumer. Once a consumer scan proves the getter has a single
  reader, the getter *is* the choke point and is the simpler site.
- Blanket early-return on a function family → mixed return conventions crash;
  no-op the one smallest function.
- No-op'ing a dialog's `exec()` only → it is still constructed and trips a
  size/state assert; skip the constructor/caller instead.
- Patching mid-function → confirm the prologue (`sub sp,sp,#N; stp …`) first.
- Breakpoints on raw VAs without disabling ASLR → they never hit; disable ASLR
  or compute the slide from `image list -o`. Raw `--address` breakpoints and
  `$$`-laden symbol names also fail to resolve — prefer a symbol/regex
  breakpoint, or attach after launch.
- Relaunching to re-test while an instance still runs → single-instance or
  cached state makes it a no-op: breakpoints never fire and logs come from the
  *old* PID.
- Scanning `adrp+add` for string xrefs on FPC/Delphi → strings go through
  `RESSTR` symbol indirection and the scan is empty; find `Get*`/`LOAD*` by
  symbol instead. FPC's empty ansistring is nil — remove the nil dereference, do
  not try to satisfy it.
- Verifying from the UI → custom-drawn apps expose no accessibility text, and
  screenshots need Screen Recording permission.
- Hunting an event's *poster* → unbounded; patch the handler or the split point.
- Guessing a struct/field offset → read it from the instruction that writes it.
- Reusing an existing flag as a one-shot counter → other writers corrupt it;
  use a byte you own (e.g. `__bss`).
- Discriminating on a race-dependent flag (e.g. `spontaneous`) → a design
  smell; prefer the deterministic split point.
- Trusting a single green run → "works once" then fails; verify 3×.
- Trusting a stale crash report → timestamp it against the last patch.
- Patching system frameworks (AppKit/dyld) → patch the target's bundled code.
- Broad greps / whole-file reads → xrefs + small `pd` windows; over a large app
  bundle, go straight to `Resources/` and the localization files.
- Empty code xref → "nothing drives it" → the behaviour may be
  **resource-driven**: its entry point lives in a nib/storyboard/plist, not code.
  Check the resources before declaring the path dead.
- Trusting a nib/plist key because it exists → compiled resources carry
  design-time metadata the runtime ignores; test one item and observe before
  building a theory on a key. To remove a UI element, drop its reference from
  the owning collection — do not hunt a hide property that is not honoured.
- Closing the state flag and calling the flow dead → a false flag does not stop
  an explicit action (menu item, button, timer) from re-entering. Enumerate the
  **entry points** as gates and patch each; a residual symptom after a correct
  state patch is a second gate, not a failed first patch.
- Reading a parser's dict view of a repeated-key structure → array-like data
  (repeated keys, one element each) collapses silently; read the raw value list.

## arm64 encoding crib

`file_offset == VA − image base`; `lipo -thin arm64` first so the other slice is
untouched.

| effect | bytes |
|---|---|
| `mov w0,#0 ; ret` | `00 00 80 52 c0 03 5f d6` |
| `mov w0,#1 ; ret` | `20 00 80 52 c0 03 5f d6` |
| `mov w0,#300 ; ret` | `80 25 80 52 c0 03 5f d6` |
| `fmov d0,xzr ; ret` | `e0 03 67 9e c0 03 5f d6` |
| `ret` (4B) | `c0 03 5f d6` |
| `nop` (4B) | `1f 20 03 d5` |
| `mov wN,#imm` (4B) | `0x52800000 \| (imm << 5) \| N` |
| `mov xN,xzr` (4B) | `0xaa1f03e0 \| N` |
| `b <target>` (4B) | `0x14000000 \| ((target−PC) >> 2)` |
| `cmp wN,#imm12` (4B) | `0x71000000 \| (imm12 << 10) \| (N << 5) \| 31` — `cmp w8,#0x14` → `1f 51 00 71`, `cmp w8,#0xfff` → `1f fd 3f 71` |
| `cbz wN,<t>` (4B) | `0x34000000 \| (((t−PC)>>2) << 5) \| N` |
| `tbz wN,#b,<t>` (4B) | `0x36000000 \| (((t−PC)>>2) << 5) \| (b << 19) \| N` |
| `ldrb wN,[xM,#o]` (4B) | `0x39400000 \| (o << 10) \| (M << 5) \| N` |
| `ldrh wN,[xM,#o]` (4B) | `0x79400000 \| ((o/2) << 10) \| (M << 5) \| N` — imm scaled ×2 |

A conditional branch is not a `b` with a different opcode byte: `cbz`/`tbz`/
`b.cond` keep the offset at bit 5, while `b` reads it at bit 0. Swapping the
opcode reuses the wrong bits and lands far from the target — re-encode from the
destination.
