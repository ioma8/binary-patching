#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""resign.py <path> [--runtime] [--identity ID] [--no-verify]

Re-sign a Mach-O binary or `.app` bundle, then verify the result.

Defaults to an **ad-hoc, non-hardened** signature — the combination that lets a
re-signed app load its freshly re-signed bundled dylibs. Keeping the hardened
runtime (`--runtime`) enables library validation, which rejects those dylibs
unless you also add a `disable-library-validation` entitlement.

  --runtime        keep the hardened runtime (`--options runtime`)
  --identity ID    signing identity (default `-` = ad-hoc)
  --no-verify      skip the post-sign verification

Bundles (`*.app`, or a dir with `Contents/Info.plist`) are signed `--deep`.
"""
import os
import subprocess
import sys


def main() -> None:
    runtime, verify, identity, pos, args, i = False, True, "-", [], sys.argv[1:], 0
    while i < len(args):
        a = args[i]
        if a == "--runtime":
            runtime, i = True, i + 1
        elif a == "--identity":
            identity, i = args[i + 1], i + 2
        elif a == "--no-verify":
            verify, i = False, i + 1
        else:
            pos.append(a)
            i += 1
    if len(pos) != 1:
        print(__doc__)
        raise SystemExit(1)
    path = pos[0]
    if not os.path.exists(path):
        raise SystemExit(f"no such path: {path}")
    if os.path.isfile(path) and open(path, "rb").read(2) == b"MZ":
        raise SystemExit("resign.py is macOS-only (codesign); PE Authenticode "
                         "signing needs signtool / osslsigncode")
    is_bundle = path.endswith(".app") or os.path.exists(
        os.path.join(path, "Contents", "Info.plist"))

    sign = ["codesign", "--force"]
    if is_bundle:
        sign.append("--deep")
    if runtime:
        sign += ["--options", "runtime"]
    sign += ["--sign", identity, path]
    print("$ " + " ".join(sign))
    if subprocess.run(sign).returncode:
        raise SystemExit("codesign failed")

    if verify:
        v = ["codesign", "--verify", "--strict", "--verbose=2"]
        if is_bundle:
            v.append("--deep")
        v.append(path)
        print("$ " + " ".join(v))
        if subprocess.run(v).returncode:
            raise SystemExit("verification failed")

    info = subprocess.run(["codesign", "-dv", path], capture_output=True, text=True).stderr
    flags = next((l.split("flags=", 1)[1].split()[0]
                  for l in info.splitlines() if "flags=" in l), "?")
    print(f"OK  {path}  identity={identity}  runtime={runtime}  flags={flags}")


if __name__ == "__main__":
    main()
