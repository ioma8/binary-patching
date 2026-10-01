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
   or **runs-but-wrong** (visible symptom). *Done when:* the category is named.
   Each category starts a different search — "quits after N seconds" is a quit,
   not a crash.

3. **Trace backward.** Run under a debugger with **ASLR disabled** (runtime
   address == file offset); break on the *terminal* call (`-[NSApplication
   terminate:]`, `exit`, `abort`, the failing syscall), not the first; read the
   **full** backtrace. *Done when:* you hold the chain from symptom to terminal
   call, both halves if it is a cycle.

4. **Find the decision.** The narrowest patchable site. Blocking A but keeping
   B: capture the backtrace of *both*, find the **split point** where they
   diverge, patch there — not the shared handler. Otherwise the **choke point**
   (the one call/compare everything funnels through). *Done when:* one
   function/instruction is named.

5. **Patch minimal.** No-op the smallest function; assert the pristine bytes at
   the site; patch per-arch slice; re-sign (frameworks first, then `--deep` the
   app); confirm the exact bytes landed. *Done when:* bytes verified and
   `codesign --verify --deep` passes.

6. **Verify three times.** The bug is gone **and** the desired behaviour still
   works, three clean runs. *Done when:* 3 green. One green run proves nothing.

## Hypothesis loop

When the root cause is not obvious, before patching: form **one** specific,
testable hypothesis — a guess about *why* the expected/observed gap exists, not
a restatement of what you saw. Run **one** surgical test that proves or
disproves it. Record the hypothesis and its conclusion in `HYPOTHESES.csv`
(`proved` / `disproved` / `need more info`). Repeat until a hypothesis is
proved. Never test two hypotheses at once; never skip the record — it is the
audit trail that stops you re-testing the same guess.

## Tooling

- **lldb** — `settings set target.disable-aslr true`; `bt`; break on the
  terminal API. The single most decisive move.
- **r2** — `strings` → xrefs → a small `pd` window; read a field's offset/width
  from the instruction that *writes* it, never from memory of the header.
- **nm / otool** — symbol addresses; `lipo -thin arm64` / `-create` for
  universal binaries.
- **codesign** — `-f -s -` the framework, then `--deep --force` the app; delete
  stray bundle-root artifacts first.
- **osascript** — drive a user action (`tell app "X" to quit`) to capture the
  *correct* backtrace for the split-point diff.

## Anti-patterns

Guessing offsets/fields · trusting a single green run · hunting an event's
poster (unbounded) · blanket early-return on a function family (mixed return
conventions → crash) · patching mid-function (confirm the prologue first) ·
trusting a stale crash report · reading whole binaries instead of xrefs.

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
