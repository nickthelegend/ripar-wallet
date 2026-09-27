#!/usr/bin/env bash
# Reproducible build of the Ripar device emulator: the firmware's portable modules + the emulator driver, compiled
# to WebAssembly with Emscripten (tested with 6.0.10), as an ES module for browsers and Node.
#
#   bash emu/build.sh                 # -> emu/dist/ripar-emu-core.mjs + ripar-emu-core.wasm (+ the JS wrapper)
#   EMU_SINGLE_FILE=1 bash emu/build.sh   # the .wasm embedded in ripar-emu-core.mjs (one ~545 KB file)
#
# Environment: EMSDK (default F:/tools/emsdk on this machine) must hold an activated emsdk; EM_CONFIG defaults to
# $EMSDK/.emscripten. Output in emu/dist/ is meant to be committed: the web companion imports
# emu/dist/ripar-emu.mjs and needs no emsdk.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW="$(cd "$HERE/.." && pwd)"
DIST="$HERE/dist"
GEN="$HERE/build/gen"

EMSDK="${EMSDK:-F:/tools/emsdk}"
export EMSDK
export EM_CONFIG="${EM_CONFIG:-$EMSDK/.emscripten}"
emsdk_posix="$EMSDK"
if command -v cygpath >/dev/null 2>&1; then emsdk_posix="$(cygpath -u "$EMSDK")"; fi
NODE_DIR="$(ls -d "$emsdk_posix"/node/*/bin 2>/dev/null | head -1 || true)"
[ -n "$NODE_DIR" ] || NODE_DIR="$(ls -d "$emsdk_posix"/node/* 2>/dev/null | head -1 || true)"
PY_DIR="$(ls -d "$emsdk_posix"/python/* 2>/dev/null | head -1 || true)"
export PATH="$emsdk_posix/upstream/emscripten:${NODE_DIR:+$NODE_DIR:}${PY_DIR:+$PY_DIR:}$PATH"
EMXX="em++"
if command -v em++.exe >/dev/null 2>&1; then EMXX="em++.exe"; fi
command -v "$EMXX" >/dev/null 2>&1 || { echo "build.sh: em++ not found under $EMSDK" >&2; exit 1; }

mkdir -p "$DIST" "$GEN" "$HERE/build/tmp"
# compiler temporaries next to the build (not in the system temp dir)
export TMP="$HERE/build/tmp" TEMP="$HERE/build/tmp" TMPDIR="$HERE/build/tmp"

# ui.cpp's QR capacity helpers, verbatim (the emulator reports the QR version / ECC the device would draw)
awk '/QR-CAPACITY-BEGIN/{f=1;next} /QR-CAPACITY-END/{f=0} f' "$FW/src/ui.cpp" > "$GEN/qr_capacity.inc"
[ -s "$GEN/qr_capacity.inc" ] || { echo "build.sh: QR-CAPACITY block not found in src/ui.cpp" >&2; exit 1; }

# the portable firmware modules, unchanged (NOT io / pulse / qrscan / ui / store / keys / flows / main)
FW_MODULES="hashes util cbor ur eip712 abi crypto protocol enforcers json_strict tokens policy review respond context fsm pulse_algo vault"
SRCS=()
for m in $FW_MODULES; do SRCS+=("$FW/src/$m.cpp"); done
for m in emu_core emu_state emu_hw emu_ui ppg_synth emu_api; do SRCS+=("$HERE/src/$m.cpp"); done

EXPORTS="_emu_new,_emu_delete,_emu_last_error,_emu_state,_emu_key,_emu_tick,_emu_scan,_emu_finger,_emu_control,_emu_context,_emu_nvs"

FLAGS=(
  -std=c++14 -O2 -Wall
  -I "$FW/include" -I "$FW/test/host" -I "$HERE/src" -I "$GEN"
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createRiparEmuCore
  -sENVIRONMENT=web,node
  -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=8MB -sSTACK_SIZE=1MB
  -sFILESYSTEM=0
  "-sEXPORTED_FUNCTIONS=$EXPORTS"
  -sEXPORTED_RUNTIME_METHODS=cwrap,UTF8ToString
)
OUT="$DIST/ripar-emu-core.mjs"
if [ "${EMU_SINGLE_FILE:-0}" = "1" ]; then
  FLAGS+=(-sSINGLE_FILE=1)
  rm -f "$DIST/ripar-emu-core.wasm"
fi

echo "build.sh: $("$EMXX" --version | head -1)"
"$EMXX" "${FLAGS[@]}" "${SRCS[@]}" -o "$OUT"

# the JS wrapper + its types next to the core
cp "$HERE/js/ripar-emu.mjs" "$DIST/ripar-emu.mjs"
cp "$HERE/js/ripar-emu.d.ts" "$DIST/ripar-emu.d.ts"

echo "build.sh: wrote"
for f in "$DIST"/*; do
  printf '  %-28s %9d bytes  sha256 %s\n' "$(basename "$f")" "$(wc -c < "$f")" "$(sha256sum "$f" | cut -c1-16)"
done
