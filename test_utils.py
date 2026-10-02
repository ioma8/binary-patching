#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy", "capstone"]
# ///
"""Crucial tests for the helpers here, on real Mach-O binaries.

Builds a tiny C fixture (arm64, x86_64, fat) with clang and checks every tool
against independent ground truth from otool / nm / codesign. Run: ./test_utils.py

Each test is here because it fails when the tool's logic breaks, not to raise
coverage.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = {n: os.path.join(HERE, n) for n in
        ("fdis.py", "find_callers.py", "find_refs.py", "find_strings.py",
         "patch.py", "resign.py")}
FX = {}

C_SRC = r"""
#include <stdio.h>
int g_counter = 0;
__attribute__((noinline)) void target_fn(void) { g_counter += 7; }
__attribute__((noinline)) void other_fn(void) { g_counter += 1; }
int main(void) { target_fn(); other_fn(); target_fn(); printf("%d\n", g_counter); return 0; }
"""

# i386 links no libSystem, so objects must avoid external calls (an unresolved
# `calll 0x0` placeholder would look like a call to address 0).
C_SRC_OBJ = r"""
int g_counter = 0;
__attribute__((noinline)) void target_fn(void) { g_counter += 7; }
__attribute__((noinline)) void other_fn(void) { g_counter += 1; }
int main(void) { target_fn(); other_fn(); target_fn(); return g_counter; }
"""


def run(tool, *args):
    return subprocess.run([TOOL[tool], *args], capture_output=True, text=True)


def otool_tv(path):
    out = subprocess.run(["otool", "-tv", path], capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+)\t(\S+)\t?(.*)$", line)
        if m:
            rows.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return rows


def nm_sym(path, name):
    for line in subprocess.run(["nm", path], capture_output=True, text=True).stdout.splitlines():
        f = line.split()
        if len(f) == 3 and f[2] == name:
            return int(f[0], 16)
    return None


def arm_calls_to(path, symname):
    """bl <symname> sites (ground truth)."""
    return {a for a, m, o in otool_tv(path) if m == "bl" and o == symname}


def x86_calls_to(path, target_va):
    """call <target_va> sites (ground truth)."""
    sites = set()
    for a, m, o in otool_tv(path):
        if m.startswith("call"):
            try:
                if int(o, 16) == target_va:
                    sites.add(a)
            except ValueError:
                pass
    return sites


def otool_refs_to(path, va):
    """Instructions that materialize `va` via adrp+add/ldr/str (ground truth).

    Tracks adrp results per register and invalidates a register whenever some
    other instruction overwrites it (e.g. `mov x9, sp`), so it does not invent
    references the code never makes.
    """
    reg, refs = {}, set()
    for site, m, o in otool_tv(path):
        ops = [x.strip() for x in o.split(",")] if o else []
        dst = ops[0] if ops and re.fullmatch(r"[xw]\d+", ops[0]) else None
        if m == "adrp" and len(ops) >= 2:
            mm = re.match(r"-?\d+\s*;\s*(0x[0-9a-f]+)", ops[1])
            if mm and dst:
                reg[dst] = int(mm.group(1), 16)
            continue
        mm = (re.match(r"\[(x\d+)(?:,\s*#(0x[0-9a-f]+))?\]", ops[1])
              if len(ops) >= 2 else None)
        if mm and mm.group(1) in reg and m in ("ldr", "str", "ldrb", "strb"):
            if reg[mm.group(1)] + int(mm.group(2) or "0", 16) == va:
                refs.add(site)
        if m == "add" and len(ops) == 3:
            am, im = re.match(r"(x\d+)", ops[1]), re.match(r"#(0x[0-9a-f]+)", ops[2])
            if am and im and am.group(1) in reg:
                val = reg[am.group(1)] + int(im.group(1), 16)
                if val == va:
                    refs.add(site)
                if dst:
                    reg[dst] = val
                continue
        if dst:
            reg.pop(dst, None)
    return refs


def otool_x86_refs(path, va):
    """x86_64 ground truth: instructions whose RIP-relative target is `va`."""
    rows, refs = otool_tv(path), set()
    for i, (a, _m, o) in enumerate(rows):
        size = rows[i + 1][0] - a if i + 1 < len(rows) else 16
        mm = re.search(r"(0x[0-9a-f]+)\(%rip\)", o)
        if mm and a + size + int(mm.group(1), 16) == va:
            refs.add(a)
    return refs


def find_callers_sites(out):
    return {int(m.group(1), 16) for m in re.finditer(r"^\s+([0-9a-f]{16})\s", out, re.M)}


def find_refs_sites(out, kind):
    return {int(m.group(1), 16) for m in re.finditer(rf"^\s+{kind}\s+([0-9a-f]{{16}})", out, re.M)}


def codesign_flags(path):
    out = subprocess.run(["codesign", "-dv", path], capture_output=True, text=True).stderr
    m = re.search(r"flags=(\S+)", out)
    return m.group(1) if m else ""


def setUpModule():
    for t in ("clang", "otool", "nm", "lipo", "codesign"):
        if not shutil.which(t):
            raise unittest.SkipTest(f"{t} not available")
    d = tempfile.mkdtemp(prefix="bpatch-test-")
    src = os.path.join(d, "fx.c")
    with open(src, "w") as f:
        f.write(C_SRC)
    for arch, name in (("arm64", "arm"), ("x86_64", "x86")):
        subprocess.run(["clang", "-O0", "-arch", arch, "-o", os.path.join(d, name), src],
                       check=True)
    subprocess.run(["clang", "-O0", "-arch", "arm64", "-arch", "x86_64",
                    "-o", os.path.join(d, "fat"), src], check=True)
    # i386 links no executable (no i386 libSystem), so use relocatable objects
    obj_src = os.path.join(d, "fx_obj.c")
    with open(obj_src, "w") as f:
        f.write(C_SRC_OBJ)
    subprocess.run(["clang", "-O0", "-arch", "i386", "-c",
                    "-o", os.path.join(d, "i386.o"), obj_src], check=True)
    subprocess.run(["clang", "-O0", "-arch", "i386", "-arch", "x86_64", "-arch", "arm64",
                    "-c", "-o", os.path.join(d, "multi.o"), obj_src], check=True)
    FX.update(dir=d,
              arm=os.path.join(d, "arm"), x86=os.path.join(d, "x86"),
              fat=os.path.join(d, "fat"), i386=os.path.join(d, "i386.o"),
              multi=os.path.join(d, "multi.o"))
    for arch, key in (("arm", "arm"), ("x86", "x86")):
        FX[f"{key}_target"] = nm_sym(FX[key], "_target_fn")
        FX[f"{key}_counter"] = nm_sym(FX[key], "_g_counter")
    FX["i386_target"] = nm_sym(FX["i386"], "_target_fn")
    FX["i386_counter"] = nm_sym(FX["i386"], "_g_counter")


def tearDownModule():
    shutil.rmtree(FX.get("dir", ""), ignore_errors=True)


class TestFdis(unittest.TestCase):
    def test_arm64_disassembles(self):
        r = run("fdis.py", FX["arm"], hex(FX["arm_target"]), "3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("adrp", r.stdout)
        self.assertIn("ldr", r.stdout)

    def test_fat_picks_arm64(self):
        r = run("fdis.py", FX["fat"], hex(FX["arm_target"]), "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("adrp", r.stdout)

    def test_thin_x86_decodes_as_x86(self):
        """Regression: a thin x86_64 binary was silently decoded as arm64."""
        r = run("fdis.py", FX["x86"], hex(FX["x86_target"]), "3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("push", r.stdout)
        self.assertNotIn("adrp", r.stdout)

    def test_x86_disassembles_object(self):
        r = run("fdis.py", FX["i386"], hex(FX["i386_target"]), "3", "--arch", "x86")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("push", r.stdout)
        self.assertIn("mov", r.stdout)

    def test_three_arch_fat_selects_each(self):
        for arch, want in (("x86", "push"), ("x86_64", "push"), ("arm64", "adrp")):
            r = run("fdis.py", FX["multi"], "0x0", "2", "--arch", arch)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(want, r.stdout, arch)


class TestFindCallers(unittest.TestCase):
    def test_arm64_exact(self):
        expect = arm_calls_to(FX["arm"], "_target_fn")
        self.assertEqual(len(expect), 2)
        r = run("find_callers.py", FX["arm"], "_target_fn")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(find_callers_sites(r.stdout), expect)

    def test_x86_64_exact_on_fixture(self):
        expect = x86_calls_to(FX["x86"], FX["x86_target"])
        self.assertEqual(len(expect), 2)
        r = run("find_callers.py", FX["x86"], "--arch", "x86_64", "_target_fn")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(find_callers_sites(r.stdout), expect)

    def test_x86_exact_on_object(self):
        expect = x86_calls_to(FX["i386"], FX["i386_target"])
        self.assertEqual(len(expect), 2)
        r = run("find_callers.py", FX["i386"], "--arch", "x86", "_target_fn")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(find_callers_sites(r.stdout), expect)

    def test_symbol_substring_and_hex_agree(self):
        by_name = run("find_callers.py", FX["arm"], "target_fn")
        by_hex = run("find_callers.py", FX["arm"], hex(FX["arm_target"]), "--no-symbols")
        self.assertEqual(find_callers_sites(by_name.stdout), find_callers_sites(by_hex.stdout))

    def test_no_match_fails(self):
        r = run("find_callers.py", FX["arm"], "_definitely_absent_xyz")
        self.assertNotEqual(r.returncode, 0)

    def test_arch_mismatch_on_thin_fails(self):
        """Regression: --arch was silently ignored for a thin binary."""
        r = run("find_callers.py", FX["arm"], "--arch", "x86_64", hex(FX["arm_target"]))
        self.assertNotEqual(r.returncode, 0)

    def test_unknown_arch_is_clean_error(self):
        r = run("find_callers.py", FX["arm"], "--arch", "bogus", hex(FX["arm_target"]))
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)


class TestFindRefs(unittest.TestCase):
    def test_code_refs_exact(self):
        expect = otool_refs_to(FX["arm"], FX["arm_counter"])
        self.assertEqual(len(expect), 5)
        r = run("find_refs.py", FX["arm"], "--no-ptr", hex(FX["arm_counter"]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(find_refs_sites(r.stdout, "code"), expect)

    def test_str_finds_literal_and_its_code_ref(self):
        r = run("find_refs.py", FX["arm"], "--str", "%d")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(find_refs_sites(r.stdout, "code"))

    def test_ptr_scan_ignores_macho_header(self):
        """Regression: an 8-byte value in the load commands was reported as a ptr."""
        r = run("find_refs.py", FX["arm"], "--str", "%d")
        self.assertNotIn("0000000100000170", r.stdout)
        self.assertIn("0x10000057c", r.stdout)

    def test_str_present_only_in_symbol_table_reports_so(self):
        r = run("find_refs.py", FX["arm"], "--str", "_target_fn")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("non-data", r.stdout + r.stderr)

    def test_x86_64_code_refs_exact(self):
        expect = otool_x86_refs(FX["x86"], FX["x86_counter"])
        self.assertEqual(len(expect), 5)
        r = run("find_refs.py", FX["x86"], "--arch", "x86_64", "--no-ptr",
                hex(FX["x86_counter"]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(find_refs_sites(r.stdout, "code"), expect)

    def test_x86_ptr_scan_and_arch(self):
        ok = run("find_refs.py", FX["i386"], "--arch", "x86", "--no-code",
                 hex(FX["i386_counter"]))
        self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_x86_arch_mismatch_fails(self):
        r = run("find_refs.py", FX["x86"], "--arch", "arm64", hex(FX["x86_counter"]))
        self.assertNotEqual(r.returncode, 0)


class TestFindStrings(unittest.TestCase):
    def test_literal_with_va_then_refs(self):
        """A discovered string VA feeds straight into find_refs."""
        r = run("find_strings.py", FX["arm"], "%d", "--min", "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = re.search(r"^([0-9a-f]+)\s+__cstring\s+%d", r.stdout, re.M)
        self.assertIsNotNone(m, r.stdout)
        refs = run("find_refs.py", FX["arm"], hex(int(m.group(1), 16)))
        self.assertTrue(find_refs_sites(refs.stdout, "code"))

    def test_section_filter(self):
        c = run("find_strings.py", FX["arm"], "%d", "--min", "2", "--section", "__cstring")
        d = run("find_strings.py", FX["arm"], "%d", "--min", "2", "--section", "__data")
        self.assertIn("%d", c.stdout)
        self.assertNotIn("%d", d.stdout)

    def test_regex_and_count(self):
        r = run("find_strings.py", FX["arm"], "--regex", "%.*", "--min", "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("%d", r.stdout)
        self.assertTrue(run("find_strings.py", FX["arm"], "--count").stdout.strip().isdigit())

    def test_all_arches(self):
        for arch, key in (("arm64", "arm"), ("x86_64", "x86"), ("x86", "i386")):
            r = run("find_strings.py", FX[key], "--arch", arch)
            self.assertEqual(r.returncode, 0, r.stderr)


class TestPatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bpatch-patch-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _copy(self, src):
        dst = os.path.join(self.tmp, os.path.basename(src) + ".copy")
        shutil.copy(src, dst)
        return dst

    def _manifest(self, text):
        p = os.path.join(self.tmp, "m.patch")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_apply_then_check(self):
        tgt = self._copy(FX["arm"])
        m = self._manifest(f"arm64 {hex(FX['arm_target'])} - c0035fd6\n")
        self.assertEqual(run("patch.py", tgt, m).returncode, 0)
        self.assertEqual(run("patch.py", tgt, m, "--check").returncode, 0)
        off = FX["arm_target"] - 0x100000000
        with open(tgt, "rb") as f:
            self.assertEqual(f.read()[off:off + 4], bytes.fromhex("c0035fd6"))

    def test_abort_on_wrong_pristine(self):
        tgt = self._copy(FX["arm"])
        with open(tgt, "rb") as f:
            before = f.read()
        m = self._manifest(f"arm64 {hex(FX['arm_target'])} 00000000 c0035fd6\n")
        r = run("patch.py", tgt, m)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ABORTED", r.stdout)
        with open(tgt, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_symbol_site_resolves(self):
        tgt = self._copy(FX["arm"])
        m = self._manifest("arm64 _target_fn - c0035fd6\n")
        r = run("patch.py", tgt, m)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(hex(FX["arm_target"]), r.stdout)

    def test_x86_symbol_site_at_zero(self):
        """An object's first function sits at address 0; lookup must not skip it."""
        tgt = self._copy(FX["i386"])
        m = self._manifest("x86 _target_fn - c3\n")
        r = run("patch.py", tgt, m)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("va=0x00000000", r.stdout)

    def test_three_arch_wildcard(self):
        tgt = self._copy(FX["multi"])
        m = self._manifest("* _target_fn - c3\n")
        r = run("patch.py", tgt, m)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("3 site(s)", r.stdout)

    def test_arch_line_without_slice_fails(self):
        """Regression: a manifest for the wrong arch exited 0 as a silent no-op."""
        tgt = self._copy(FX["arm"])
        m = self._manifest(f"x86_64 {hex(FX['x86_target'])} - c0035fd6\n")
        r = run("patch.py", tgt, m)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ABORTED", r.stdout)

    def test_wildcard_symbol_patches_both_slices(self):
        tgt = self._copy(FX["fat"])
        m = self._manifest("* _target_fn - c0035fd6\n")
        r = run("patch.py", tgt, m)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("2 site(s)", r.stdout)


class TestResign(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bpatch-resign-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _copy(self):
        dst = os.path.join(self.tmp, "bin")
        shutil.copy(FX["arm"], dst)
        return dst

    def test_adhoc_default(self):
        p = self._copy()
        self.assertEqual(run("resign.py", p, "--no-verify").returncode, 0)
        self.assertEqual(codesign_flags(p), "0x2(adhoc)")

    def test_runtime_opt_in(self):
        p = self._copy()
        self.assertEqual(run("resign.py", p, "--runtime", "--no-verify").returncode, 0)
        self.assertIn("0x10002", codesign_flags(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
