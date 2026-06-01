# orchard-simulator

A working `Simulate` algorithm for Halo 2 and the production Zcash
Orchard Action proof. Most ZK code ships `Prove` and `Verify`; the
third algorithm `Simulate` is what makes a proof zero-knowledge in
the first place, and is almost never implemented outside of
security proofs. This crate implements it, alongside the prover and
verifier it shadows.

The web demo at `web/` is an editorial-style 5-page site that walks
through the construction layer by layer, ending with a live
simulator on the production Orchard Action circuit driven from a
browser-side rayon thread pool. The CLI at `src/bin/orchard-cli.rs`
emits proofs as JSON for offline analysis.

## Layout

```
src/
  halo2_circuit.rs        # MulCircuit: single multiplication gate, K=4
  halo2_shim.rs           # programmable Fiat-Shamir transcript shim
  halo2_simulator.rs      # WI + ROM-programmable ZK simulator (on halo2_proofs)
  orchard_action.rs       # the same construction on Orchard's Action circuit
  wasm_halo2.rs           # browser bindings for the halo2_simulator demo
  wasm_orchard.rs         # browser bindings for the orchard simulator
  wasm_orchard_parallel.rs# wasm-bindgen-rayon hook for parallel WASM
  bin/orchard-cli.rs      # CLI driver
tests/
  halo2_byte_structure.rs        # what bytes halo2 emits for MulCircuit
  halo2_joint_distribution.rs    # WI: distributions match across witnesses
  halo2_statistical.rs           # chi-square goodness-of-fit on simulator output
  orchard_statistical.rs         # same, on the real Orchard Action proof
web/                              # static HTML/JS demo
  index.html foundations.html halo2.html orchard.html reference.html
  style.css nav.js halo2.js orchard.js orchard-worker.js orchard-worker-parallel.js serve.py
```

## Two upstream dependencies need adjustment

The `Cargo.toml` currently uses local `path =` references for two
upstream crates. To build from a fresh clone you need to provide
both:

### 1. `orchard` with two `pub fn inner()` accessors

The simulator's programmable-transcript path needs access to the
internal `halo2_proofs::poly::commitment::Params`,
`halo2_proofs::plonk::ProvingKey`, and `VerifyingKey` that the
production `orchard::circuit::ProvingKey` and `VerifyingKey` wrap.
Two upstream PRs would close this gap; until then, the local
checkout needs three small additions:

```rust
// in orchard/src/circuit.rs, on `impl ProvingKey`:
pub fn inner(&self) -> &plonk::ProvingKey<vesta::Affine> { &self.pk }
pub fn params(&self) -> &Params<vesta::Affine> { &self.params }

// on `impl VerifyingKey`:
pub fn inner(&self) -> &plonk::VerifyingKey<vesta::Affine> { &self.vk }
pub fn params(&self) -> &Params<vesta::Affine> { &self.params }

// `Instance::to_halo2_instance` made `pub` (was `pub(crate)`).
```

Point `Cargo.toml`'s `orchard = { path = "..." }` at the patched
checkout.

### 2. `core2 0.3.3` is yanked on crates.io

The upstream `orchard` Cargo.lock pins `core2 0.3.x`, which has been
yanked. The `[patch.crates-io]` table in `Cargo.toml` points at a
cached registry source on the original author's machine. To build
elsewhere, either:

- vendor `core2 0.3.3` (download from a cached registry or any user's
  `~/.cargo/registry/src/.../core2-0.3.3`) and point the patch at the
  local path, or
- bump `core2` to a non-yanked version if compatible.

## Build

```bash
# host-side tests (12 fast + 9 slow `#[ignore]`-gated)
cargo test --features simulator,halo2,orchard
cargo test --features orchard -- --ignored   # ~2.5 min for the slow set

# single-threaded WASM (3.95 MB)
FEATURES=wasm-orchard PROFILE=release bash build-wasm.sh

# parallel WASM via rayon + SharedArrayBuffer (6.7 MB, needs nightly)
rustup component add rust-src --toolchain nightly
bash build-wasm-parallel.sh

# CLI
cargo run --features orchard --release --bin orchard-cli -- --seed 42 --pretty
```

## Serve the demo

```bash
(cd web && python3 serve.py 8000)
```

`serve.py` sets `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp` so the browser enables
`SharedArrayBuffer` (required for the parallel WASM build's rayon
pool). The page auto-detects which build is present in `web/` and
picks the right worker accordingly.

## What's `Simulate`?

A zero-knowledge proof system has three algorithms:

```
Prove   : (stmt, witness, transcript)  → proof
Verify  : (stmt, proof, transcript)    → Accept / Reject
Simulate: (stmt, transcript)           → proof
```

The third one is the load-bearing one. A protocol is zero-knowledge
if and only if a simulator exists whose output is computationally
indistinguishable from a real prover's. The argument: if a simulator
can produce an accepting transcript without the witness, then any
information in a real prover's transcript must already be derivable
from the public statement alone. The prover reveals nothing because
the simulator could have produced the same transcript with nothing.

For multi-witness relations like Orchard's, the simulator works by
sampling a fresh valid witness uniformly and running the production
prover with it. Acceptance of the output by the production verifier
is the zero-knowledge claim, and the witness-uniformity argument
collapses WI and ZK onto each other.

See the
[Foundations page](https://github.com/rotkonetworks/orchard-simulator/blob/main/web/foundations.html)
for the full construction.

## License

MIT OR Apache-2.0. The patched upstream `orchard` and `halo2_proofs`
are themselves MIT OR Apache-2.0.

## References

- Bowe, Grigg, Hopwood. *Halo: Recursive Proof Composition without
  a Trusted Setup*. 2019. <https://eprint.iacr.org/2019/1021>
- Gabizon, Williamson, Ciobotaru. *PLONK*. 2019.
  <https://eprint.iacr.org/2019/953>
- Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell. *Bulletproofs*.
  2018. <https://eprint.iacr.org/2017/1066>
- Feige, Shamir. *Witness Indistinguishable and Witness Hiding
  Protocols*. 1990.
  <https://dl.acm.org/doi/10.1145/100216.100272>
- Zcash protocol specification.
  <https://zips.z.cash/protocol/protocol.pdf>
- ZIP 244. <https://zips.z.cash/zip-0244>
