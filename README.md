# binary-patching

Reverse-engineer and patch a compiled binary without source: reproduce the
symptom, trace the failing path under a debugger, find the *split point* where
two code paths diverge, patch the narrowest site, re-sign, and verify three
times.

## Install

```bash
npx skills add ioma8/binary-patching
```

[![skills.sh](https://skills.sh/b/ioma8/binary-patching)](https://skills.sh/ioma8/binary-patching)

## What it does

The method — a six-step loop (ground truth → classify → trace backward → find
the split point → minimal patch → verify 3×), the hypothesis loop, the blind
routes, and the arm64 encoding crib — lives in [`SKILL.md`](SKILL.md).

Ships six fast helpers for **arm64, x86_64 and i386** Mach-O binaries:
[`fdis.py`](fdis.py) — disassembler; [`find_callers.py`](find_callers.py) /
[`find_refs.py`](find_refs.py) / [`find_strings.py`](find_strings.py) — callers,
references and strings with their addresses; [`patch.py`](patch.py) —
declarative, all-or-nothing applier; [`resign.py`](resign.py) — ad-hoc
re-signer. Usage: [`UTILS.md`](UTILS.md).

```bash
./test_utils.py    # 32 tests vs otool / nm / codesign ground truth
./bench.sh         # hyperfine timings per architecture
```

## License

MIT
