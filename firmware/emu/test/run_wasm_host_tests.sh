#!/usr/bin/env bash
# Compiles firmware host tests to WebAssembly with the emulator's toolchain and runs them under Node, to show that
# the portable modules the emulator links behave the same compiled by Emscripten as by the host compiler.
#
#   bash emu/test/run_wasm_host_tests.sh              # test_fsm + test_pulse (the emulator's key gate + pulse gate)
#   bash emu/test/run_wasm_host_tests.sh respond policy   # any other test/host/test_<name>.cpp
#
# Each test's "// DEPS:" line names the firmware sources it links (as for test/host/run_host_tests.py).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/../build/host-tests"

EMSDK="${EMSDK:-F:/tools/emsdk}"
export EMSDK
export EM_CONFIG="${EM_CONFIG:-$EMSDK/.emscripten}"
emsdk_posix="$EMSDK"
if command -v cygpath >/dev/null 2>&1; then emsdk_posix="$(cygpath -u "$EMSDK")"; fi
NODE_DIR="$(ls -d "$emsdk_posix"/node/*/bin 2>/dev/null | head -1 || true)"
[ -n "$NODE_DIR" ] || NODE_DIR="$(ls -d "$emsdk_posix"/node/* 2>/dev/null | head -1 || true)"
PY_DIR="$(ls -d "$emsdk_posix"/python/* 2>/dev/null | head -1 || true)"
export PATH="$emsdk_posix/upstream/emscripten:${NODE_DIR:+$NODE_DIR:}${PY_DIR:+$PY_DIR:}$PATH"
EMXX="em++"; command -v em++.exe >/dev/null 2>&1 && EMXX="em++.exe"
NODE="node"; command -v node.exe >/dev/null 2>&1 && NODE="node.exe"
mkdir -p "$OUT/tmp"
export TMP="$OUT/tmp" TEMP="$OUT/tmp" TMPDIR="$OUT/tmp"

names=("$@")
[ ${#names[@]} -gt 0 ] || names=(fsm pulse)
fails=0
for n in "${names[@]}"; do
  src="$FW/test/host/test_$n.cpp"
  [ -f "$src" ] || { echo "no such test: $src"; fails=$((fails + 1)); continue; }
  deps="$(head -5 "$src" | sed -n 's#^[[:space:]]*//[[:space:]]*DEPS[[:space:]]*:##p' | head -1)"
  srcs=()
  for d in $deps; do srcs+=("$FW/src/$d.cpp"); done
  "$EMXX" -std=c++14 -O2 -I "$FW/include" -I "$FW/test/host" -DRIPAR_HOST_TEST=1 "$src" "${srcs[@]}" \
    -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=4194304 -sENVIRONMENT=node -o "$OUT/test_$n.js"
  if "$NODE" "$OUT/test_$n.js" > "$OUT/test_$n.log" 2>&1; then
    echo "PASS  test_$n (wasm)  $(tail -1 "$OUT/test_$n.log")"
  else
    echo "FAIL  test_$n (wasm)"; tail -20 "$OUT/test_$n.log"; fails=$((fails + 1))
  fi
done
[ "$fails" -eq 0 ] && echo "== wasm host tests: PASS" || { echo "== wasm host tests: $fails FAILED"; exit 1; }
