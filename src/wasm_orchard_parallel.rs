//! Browser-side rayon thread pool bootstrap for the parallel WASM build.
//!
//! Exposes `init_thread_pool(num_threads)` to JavaScript via
//! `wasm_bindgen_rayon`. The browser worker calls this once after
//! initialising the WASM module; rayon then uses a pool of inner Web
//! Workers, backed by `SharedArrayBuffer`, to parallelise halo2's FFT
//! and MSM steps inside `Proof::create`.
//!
//! Compute remains 100% client-side. The `Cross-Origin-Opener-Policy`
//! and `Cross-Origin-Embedder-Policy` headers required to enable
//! `SharedArrayBuffer` are pure browser-security metadata; the server
//! never sees the witness, the proof bytes, or the thread state.
//!
//! Gated behind `feature = "wasm-orchard-parallel"`, which in turn
//! enables halo2_proofs' `multicore` feature so the halo2 prover
//! actually dispatches work through the rayon pool.

#![cfg(feature = "wasm-orchard-parallel")]

pub use wasm_bindgen_rayon::init_thread_pool;
