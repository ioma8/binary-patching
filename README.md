# binary-patching

Reverse-engineer and patch a compiled binary without source: trace the failing
path, find the *split point* where two code paths diverge, patch the narrowest
site, re-sign, and verify.

## Install

```bash
npx skills add ioma8/binary-patching
```

[![skills.sh](https://skills.sh/b/ioma8/binary-patching)](https://skills.sh/ioma8/binary-patching)

## What it does

A six-step loop for modifying compiled binaries deterministically:

1. **Ground truth first** — read logs, crash dumps, files, network before any disassembly.
2. **Classify** — crash vs assertion vs deliberate exit vs runs-but-wrong.
3. **Trace backward** — debugger with ASLR off, break on the terminal call, full backtrace.
4. **Find the decision** — the *split point* (two paths diverge) or *choke point* (one call/compare).
5. **Patch minimal** — no-op the smallest function, assert pristine bytes, re-sign.
6. **Verify three times** — bug gone *and* desired behaviour intact.

Includes the tooling (`lldb`, `r2`, `nm`/`otool`, `lipo`, `codesign`, `osascript`),
the hypothesis loop, and the arm64 encoding crib — all inline in
[`SKILL.md`](SKILL.md).

Ships five helpers for **arm64, x86_64 and i386** Mach-O binaries:
[`fdis.py`](fdis.py) — fast single-site disassembler;
[`find_callers.py`](find_callers.py) and [`find_refs.py`](find_refs.py) —
caller / reference finders; [`patch.py`](patch.py) — declarative
patch applier (address- or symbol-addressed); and [`resign.py`](resign.py) —
ad-hoc re-signer. Usage for every helper: [`UTILS.md`](UTILS.md).

Run [`test_utils.py`](test_utils.py) to check them: it builds a C fixture with
clang (arm64, x86_64, i386, fat) and validates every tool against `otool` /
`nm` / `codesign` ground truth. [`bench.sh`](bench.sh) benchmarks each helper
per architecture with [hyperfine](https://github.com/sharkdp/hyperfine).

## License

MIT
