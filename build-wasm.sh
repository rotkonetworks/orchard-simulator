#!/usr/bin/env bash
# Build the WASM module + JS glue and place it under web/pkg/.
# Requires: rustup target add wasm32-unknown-unknown && cargo install wasm-bindgen-cli
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${PROFILE:-release}"

PROFILE_FLAG=""
PROFILE_DIR="debug"
if [ "$PROFILE" = "release" ]; then
  PROFILE_FLAG="--release"
  PROFILE_DIR="release"
fi

FEATURES="${FEATURES:-wasm}"
cargo build \
  --target wasm32-unknown-unknown \
  --features "$FEATURES" \
  --no-default-features \
  $PROFILE_FLAG \
  --lib

WASM_IN="$CRATE_DIR/target/wasm32-unknown-unknown/$PROFILE_DIR/orchard_simulator.wasm"
OUT_DIR="$CRATE_DIR/web/pkg"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

wasm-bindgen \
  --target web \
  --out-dir "$OUT_DIR" \
  --out-name orchard_simulator \
  "$WASM_IN"

echo
echo "Built $(ls -la "$OUT_DIR"/*.wasm | awk '{print $9, $5}')"
echo "Serve with: (cd web && python3 -m http.server 8000) and open http://localhost:8000"
