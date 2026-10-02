#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""find_strings.py <file> [pattern] [--arch arm64|x86_64|x86] [--min N]
                   [--section NAME] [--regex] [--all] [--count]

List printable strings in a Mach-O **or PE** binary with their virtual addresses
and section, so a string you see can be handed straight to `find_refs.py` (or
`fdis.py`). Scans section contents only, so symbol-table/relocation noise
(`strings` over the whole file) is excluded, and skips instruction sections
(`__text` / `.text`) and non-loaded sections unless `--all`.

  pattern       substring to match (or a regex with `--regex`)
  --min N       minimum length (default 4)
  --section S   only this section, e.g. `__cstring` / `.rdata` (repeatable)
  --regex       treat `pattern` as a regular expression
  --all         also scan instruction sections
  --count       print only the number of matches

Columns: `vmaddr  section  string`.
"""
import re
import sys

import binfmt


def main() -> None:
    arch, minlen, only, use_re, count, all_sects = None, 4, set(), False, False, False
    pos, args, i = [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--arch":
            arch, i = args[i + 1], i + 2
        elif a.startswith("--arch="):
            arch, i = a.split("=", 1)[1], i + 1
        elif a == "--min":
            minlen, i = int(args[i + 1]), i + 2
        elif a == "--section":
            only.add(args[i + 1])
            i += 2
        elif a == "--regex":
            use_re, i = True, i + 1
        elif a == "--all":
            all_sects, i = True, i + 1
        elif a == "--count":
            count, i = True, i + 1
        else:
            pos.append(a)
            i += 1
    if not pos or (arch is not None and arch not in binfmt.ORDER):
        print(__doc__)
        raise SystemExit(1)
    path, pattern = pos[0], (pos[1] if len(pos) > 1 else None)
    if minlen < 1:
        raise SystemExit("--min must be >= 1")

    img = binfmt.load(path, arch)
    run = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    wanted = re.compile(pattern) if use_re else None

    total, out = 0, []
    for name, va, _vsize, fileoff, filesize, is_code, loaded in img.sections:
        if only:
            if name not in only:
                continue
        elif not loaded or (is_code and not all_sects):
            continue
        for m in run.finditer(img.data[fileoff:fileoff + filesize]):
            text = m.group().decode()
            if wanted is not None:
                if not wanted.search(text):
                    continue
            elif pattern is not None and pattern not in text:
                continue
            total += 1
            if not count:
                out.append((va + m.start(), f"{name:<16}", text))
    if count:
        print(total)
        return
    for va, sect, text in out:
        print(f"{va:016x}  {sect}  {text}")
    if not out:
        print("no strings matched")


if __name__ == "__main__":
    main()
