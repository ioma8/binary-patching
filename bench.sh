#!/usr/bin/env bash
# Benchmark every helper with hyperfine, per architecture (arm64/x86_64/i386).
#
# Builds small real fixtures with clang. For scan-bound numbers, point
# BP_ARM / BP_X86 / BP_I386 at larger binaries (addresses are read from nm) and
# raise RUNS. Needs: hyperfine, clang, nm.  Usage: ./bench.sh
set -euo pipefail
cd "$(dirname "$0")"
for t in hyperfine clang nm; do
  command -v "$t" >/dev/null || { echo "missing $t (brew install $t)"; exit 1; }
done

D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
printf '%s\n' 'int g_counter=0;' \
  '__attribute__((noinline)) void target_fn(void){g_counter+=7;}' \
  '__attribute__((noinline)) void other_fn(void){g_counter+=1;}' \
  'int main(void){target_fn();other_fn();target_fn();return g_counter;}' > "$D/fx.c"
clang -O0 -arch arm64  -o "$D/arm"      "$D/fx.c"
clang -O0 -arch x86_64 -o "$D/x86_64"   "$D/fx.c"
clang -O0 -arch i386   -c -o "$D/i386.o" "$D/fx.c"
clang -O0 -arch i386 -arch x86_64 -arch arm64 -c -o "$D/multi.o" "$D/fx.c"
printf '* _target_fn - c3\n' > "$D/m.patch"

ARM=${BP_ARM:-$D/arm}; X86=${BP_X86:-$D/x86_64}; I386=${BP_I386:-$D/i386.o}
addr() { nm "$1" | awk -v s="$2" '$3==s{print "0x"$1; exit}'; }
A_ARM=$(addr "$ARM" _target_fn); A_X86=$(addr "$X86" _target_fn); A_X86S=$(addr "$X86" _target_fn)
A_I386=$(addr "$I386" _target_fn)
G_ARM=$(addr "$ARM" _g_counter); G_X86=$(addr "$X86" _g_counter); G_I386=$(addr "$I386" _g_counter)

h() { hyperfine --warmup "${WARMUP:-3}" --min-runs "${RUNS:-20}" --style basic "$@"; }

echo "=== fdis: arm64 / x86_64 / i386 ==="
h "./fdis.py $ARM $A_ARM 20" \
  "./fdis.py $X86 $A_X86 20 --arch x86_64" \
  "./fdis.py $I386 $A_I386 20 --arch x86"

echo "=== find_callers: arm64 / x86_64 / i386 ==="
h "./find_callers.py $ARM _target_fn" \
  "./find_callers.py $X86 --arch x86_64 _target_fn" \
  "./find_callers.py $I386 --arch x86 _target_fn"

echo "=== find_refs: arm64 / x86_64 / i386 ==="
h "./find_refs.py $ARM $G_ARM" \
  "./find_refs.py $X86 --arch x86_64 $G_X86" \
  "./find_refs.py $I386 --arch x86 --no-code $G_I386"

echo "=== find_strings: arm64 / x86_64 / i386 ==="
h "./find_strings.py $ARM --min 8" \
  "./find_strings.py $X86 --arch x86_64 --min 8" \
  "./find_strings.py $I386 --arch x86 --min 2"

echo "=== patch (dry-run, 3-arch fat object) ==="
h "./patch.py $D/multi.o $D/m.patch --dry-run"

echo "=== resign (ad-hoc) ==="
h --prepare "cp $ARM $D/rg.bin" "./resign.py $D/rg.bin --no-verify"
