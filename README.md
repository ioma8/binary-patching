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

## License

MIT
