//! Zero-knowledge simulator for Halo 2-style proofs.
//!
//! Two layers, both driven through upstream
//! [`halo2_proofs`](https://github.com/zcash/halo2):
//!
//! - [`halo2_simulator`] — a witness-indistinguishable simulator and a
//!   ROM-programmable zero-knowledge simulator for
//!   [`halo2_circuit::MulCircuit`], a single-multiplication-gate Halo 2
//!   circuit. Every byte goes through
//!   `halo2_proofs::plonk::create_proof` and is checked by
//!   `halo2_proofs::plonk::verify_proof`. No re-implementation of the
//!   inner-product argument lives in this crate.
//!
//! - [`orchard_action`] — the same simulator construction lifted to the
//!   production Zcash Orchard Action circuit, driven through
//!   `orchard::circuit::Proof::create` and `Proof::verify`. Patches to
//!   the upstream `orchard` crate expose
//!   `ProvingKey::inner()` and `VerifyingKey::inner()` so the
//!   programmable transcript shim ([`halo2_shim`]) can be plumbed in.
//!
//! The browser demo at `web/` wires both layers via the
//! [`wasm_halo2`] and [`wasm_orchard`] modules. The CLI at
//! `src/bin/orchard-cli.rs` exposes the Orchard path as a JSON-emitting
//! command-line tool. The optional [`wasm_orchard_parallel`] module
//! threads halo2's FFT and MSM steps across a browser-side rayon pool
//! when the page is served with cross-origin isolation headers.

#[cfg(feature = "halo2")]
pub mod halo2_circuit;
#[cfg(feature = "halo2")]
pub mod halo2_shim;
#[cfg(feature = "halo2")]
pub mod halo2_simulator;
#[cfg(feature = "orchard")]
pub mod orchard_action;
#[cfg(all(feature = "wasm", feature = "halo2"))]
pub mod wasm_halo2;
#[cfg(feature = "wasm-orchard")]
pub mod wasm_orchard;
#[cfg(feature = "wasm-orchard-parallel")]
pub mod wasm_orchard_parallel;
