#!/usr/bin/env bash
# Build the parallel WASM module (multi-threaded via rayon + SharedArrayBuffer)
# and place it under web/pkg-parallel/. Requires:
#   - nightly Rust toolchain      (for `-Z build-std` + WASM atomics target)
#   - rust-src component          (rustup component add rust-src --toolchain nightly)
#   - wasm-bindgen-cli installed  (cargo install wasm-bindgen-cli --locked)
#
# Produces a WASM that exposes `initThreadPool(num_threads)` alongside the
# normal Orchard exports. Browser worker should call
# `await wasm.initThreadPool(navigator.hardwareConcurrency)` once after init.
#
# The page must be served with both
#   Cross-Origin-Opener-Policy: same-origin
#   Cross-Origin-Embedder-Policy: require-corp
# headers for the browser to enable SharedArrayBuffer. Use the bundled
# `web/serve-parallel.py` script, or any server that emits those headers.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building parallel-WASM Orchard simulator"
echo "========================================"
echo "  - Toolchain: nightly Rust (atomics + build-std)"
echo "  - Target features: +atomics +bulk-memory +mutable-globals"
echo "  - Halo 2 multicore: enabled via orchard/multicore"
echo

# Step 1: build the WASM blob with the parallel feature.
#
# `--shared-memory` + `--max-memory` tell wasm-ld to emit the memory
# section with the shared flag set. Without them the memory is built
# unshared even when the `+atomics` target feature is enabled, which
# causes a `Memory could not be cloned` error when wasm-bindgen-rayon
# tries to postMessage the memory to child workers.
# 4 GiB is the SharedArrayBuffer ceiling.
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base' \
cargo +nightly build \
  --target wasm32-unknown-unknown \
  --features wasm-orchard-parallel \
  --no-default-features \
  --release \
  --lib \
  -Z build-std=panic_abort,std

WASM_IN="$CRATE_DIR/target/wasm32-unknown-unknown/release/orchard_simulator.wasm"
OUT_DIR="$CRATE_DIR/web/pkg-parallel"

if [ ! -f "$WASM_IN" ]; then
  echo "error: expected WASM at $WASM_IN" >&2
  exit 1
fi

# Step 2: generate JS glue with wasm-bindgen. Target `web` so the page
# can dynamic-import the module directly.
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

wasm-bindgen \
  --target web \
  --out-dir "$OUT_DIR" \
  --out-name orchard_simulator \
  "$WASM_IN"

# Step 2b: patch wasm-bindgen-rayon's workerHelpers.js so the dynamic
# import resolves to the actual JS module instead of a directory URL.
# Without a bundler, `import('../../..')` resolves to `pkg-parallel/`
# and the server returns the directory listing as `text/html`, which
# the browser refuses to load as a module. Replace with the explicit
# filename. This is the standard wasm-bindgen-rayon workaround for
# `--target web` builds.
WORKER_HELPER=$(find "$OUT_DIR/snippets" -name workerHelpers.js | head -n1)
if [ -n "$WORKER_HELPER" ]; then
  sed -i "s|await import('../../..')|await import('../../../orchard_simulator.js')|" "$WORKER_HELPER"
  sed -i "s|new URL('./workerHelpers.js', import.meta.url)|new URL('./workerHelpers.js', import.meta.url)|" "$WORKER_HELPER"
  echo "patched workerHelpers.js to use explicit module filename"
fi

# Step 3 (optional): wasm-opt for size. The parallel build is larger than
# the single-threaded one because rayon brings extra runtime; opt -O3 can
# claw some back.
if command -v wasm-opt >/dev/null 2>&1; then
  echo
  echo "Optimising with wasm-opt -O3..."
  wasm-opt -O3 \
    --enable-threads --enable-bulk-memory --enable-mutable-globals \
    "$OUT_DIR/orchard_simulator_bg.wasm" \
    -o "$OUT_DIR/orchard_simulator_bg.wasm"
else
  echo
  echo "wasm-opt not found; skipping size optimisation."
  echo "  cargo install wasm-opt --locked   # to enable"
fi

echo
echo "Built $(ls -la "$OUT_DIR"/*.wasm | awk '{print $9, $5}')"
echo "Serve with: (cd web && python3 serve.py 8000) and open http://localhost:8000"
echo "  -- serve.py already sends Cross-Origin-{Opener,Embedder}-Policy,"
echo "     which the browser needs to enable SharedArrayBuffer."
