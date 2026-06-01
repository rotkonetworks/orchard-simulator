//! WASM bindings for the halo2_proofs-based simulator experiments.
//!
//! Exposes the `halo2_simulator` paths directly to the browser. No
//! toy re-implementation: every byte the page reports came out of
//! `halo2_proofs::plonk::create_proof` against the
//! `crate::halo2_circuit::MulCircuit` instance, verified by
//! `halo2_proofs::plonk::verify_proof`.
//!
//! Two entry points cover the three experiments on the halo2 page:
//!
//! 1. [`halo2_keygen`] builds and caches the Pasta `Params`,
//!    `ProvingKey`, and `VerifyingKey` for the
//!    `MulCircuit` of size `n = 16` rows. First call is the slow
//!    one (~50 ms host, more in the browser); subsequent runs reuse
//!    the cache.
//! 2. [`halo2_demo`] runs an honest prove + WI simulator + ZK
//!    simulator for the same public `c`, verifies each output under
//!    both Blake2b and the programmable transcript, and reports
//!    proof bytes + verification verdicts.

#![cfg(feature = "wasm")]
#![cfg(feature = "halo2")]
#![allow(missing_docs)]

use crate::halo2_circuit::MulCircuit;
use crate::halo2_shim::{ProgrammableHalo2Read, ProgrammableHalo2Write};
use crate::halo2_simulator;

use ff::{Field, PrimeField};
use halo2_proofs::pasta::{vesta, EqAffine};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::SeedableRng;
use serde::Serialize;
use std::io::Cursor;
use std::sync::OnceLock;
use wasm_bindgen::prelude::*;

type C = EqAffine;
type F = vesta::Scalar;

/// Circuit size `n = 2^K`. `K = 4` means a 16-row polynomial; small
/// enough to keygen fast in the browser, large enough to exercise
/// every halo2 prover path (commit, vanish, evaluate, multipoint,
/// IPA).
const K_LOG: u32 = 4;

struct Halo2Keys {
    params: Params<C>,
    pk: ProvingKey<C>,
    vk: VerifyingKey<C>,
}

static HALO2_KEYS: OnceLock<Halo2Keys> = OnceLock::new();

/// Build (and cache) the Pasta `Params`, `ProvingKey`, and
/// `VerifyingKey` for `MulCircuit`. Idempotent.
#[wasm_bindgen]
pub fn halo2_keygen() -> Result<JsValue, JsError> {
    if HALO2_KEYS.get().is_some() {
        return Ok(JsValue::from_str("already-initialized"));
    }
    let params: Params<C> = Params::new(K_LOG);
    let empty = MulCircuit::<F>::new(F::ZERO, F::ZERO);
    let vk = keygen_vk(&params, &empty).map_err(|e| JsError::new(&format!("keygen_vk: {e:?}")))?;
    let pk = keygen_pk(&params, vk.clone(), &empty)
        .map_err(|e| JsError::new(&format!("keygen_pk: {e:?}")))?;
    let keys = Halo2Keys { params, pk, vk };
    let _ = HALO2_KEYS.set(keys);
    Ok(JsValue::from_str("initialized"))
}

#[derive(Serialize)]
pub struct Halo2RunResult {
    /// The public scalar `c` (lowercase hex).
    pub c_hex: String,
    /// Honest prove + verify, Blake2b transcript both ways.
    pub honest: Halo2OneRun,
    /// WI simulator: sample a different witness for the same `c`,
    /// run the honest prover. Bytes verify under Blake2b.
    pub wi_simulator: Halo2OneRun,
    /// ZK simulator: sample uniform Fiat-Shamir challenges, run
    /// `create_proof` with the programmable transcript. Bytes verify
    /// under the same programmable transcript and are rejected by
    /// Blake2b.
    pub zk_simulator: Halo2OneRun,
    /// The challenges the ZK simulator programmed into its
    /// transcript. Lowercase hex.
    pub programmed_challenges_hex: Vec<String>,
    /// Wall-clock time to produce all three proofs.
    pub elapsed_ms: u32,
}

#[derive(Serialize)]
pub struct Halo2OneRun {
    /// Total proof bytes.
    pub bytes_len: usize,
    /// Lowercase hex of the first 64 bytes.
    pub head_hex: String,
    /// Lowercase hex of the last 64 bytes.
    pub tail_hex: String,
    /// Verification result under Blake2b transcript.
    pub verified_blake2b: bool,
    /// Verification result under programmable transcript.
    /// Honest proof never sees a programmable verifier, so this is
    /// `None`. Simulator runs always report both.
    pub verified_programmable: Option<bool>,
}

/// Run one honest prover + two simulator variants on `MulCircuit`
/// for the same public `c`. All three drive
/// `halo2_proofs::plonk::create_proof` directly; none go through a
/// re-implementation of the IPA.
#[wasm_bindgen]
pub fn halo2_demo(c_seed: u32, witness_seed: u32) -> Result<JsValue, JsError> {
    let keys = HALO2_KEYS
        .get()
        .ok_or_else(|| JsError::new("call halo2_keygen() first"))?;

    let mut rng_c = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(c_seed));
    let c = F::random(&mut rng_c);
    let c_hex = scalar_hex(&c);

    let t0 = now_ms();

    // -------- honest prover --------
    let honest = run_honest(&keys.params, &keys.pk, &keys.vk, c, witness_seed)?;

    // -------- WI simulator --------
    let wi_simulator = run_wi_simulator(
        &keys.params,
        &keys.pk,
        &keys.vk,
        c,
        witness_seed.wrapping_add(0x1111_1111),
    )?;

    // -------- ZK simulator with programmable transcript --------
    let challenge_count = transcript_challenge_count();
    let mut rng_chal =
        rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(witness_seed) ^ 0xdead_beef_cafe_babe);
    let challenges: Vec<F> = (0..challenge_count)
        .map(|_| F::random(&mut rng_chal))
        .collect();
    let zk_simulator = run_zk_simulator(
        &keys.params,
        &keys.pk,
        &keys.vk,
        c,
        challenges.clone(),
        witness_seed.wrapping_add(0x2222_2222),
    )?;

    let elapsed_ms = (now_ms() - t0).max(0.0) as u32;

    let result = Halo2RunResult {
        c_hex,
        honest,
        wi_simulator,
        zk_simulator,
        programmed_challenges_hex: challenges.iter().map(scalar_hex).collect(),
        elapsed_ms,
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

fn run_honest(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    vk: &VerifyingKey<C>,
    c: F,
    witness_seed: u32,
) -> Result<Halo2OneRun, JsError> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(witness_seed));
    let a = sample_nonzero(&mut rng)?;
    let a_inv: F =
        Option::from(a.invert()).ok_or_else(|| JsError::new("a is zero (impossible)"))?;
    let b = c * a_inv;

    let circuit = MulCircuit::<F>::new(a, b);
    let mut transcript = Blake2bWrite::<_, C, Challenge255<C>>::init(Vec::new());
    create_proof(
        params,
        pk,
        &[circuit],
        &[&[&[c]]],
        &mut rng,
        &mut transcript,
    )
    .map_err(|e| JsError::new(&format!("honest create_proof: {e:?}")))?;
    let proof = transcript.finalize();

    // Verify under Blake2b.
    let verified_blake2b = verify_blake2b(params, vk, c, &proof);

    Ok(Halo2OneRun {
        bytes_len: proof.len(),
        head_hex: bytes_to_hex(&proof[..proof.len().min(64)]),
        tail_hex: bytes_to_hex(&proof[proof.len().saturating_sub(64)..]),
        verified_blake2b,
        verified_programmable: None,
    })
}

fn run_wi_simulator(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    vk: &VerifyingKey<C>,
    c: F,
    seed: u32,
) -> Result<Halo2OneRun, JsError> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(seed));
    let proof = halo2_simulator::witness_indistinguishable_proof(params, pk, c, &mut rng)
        .map_err(|e| JsError::new(&format!("wi simulator: {e:?}")))?;

    let verified_blake2b = verify_blake2b(params, vk, c, &proof);

    Ok(Halo2OneRun {
        bytes_len: proof.len(),
        head_hex: bytes_to_hex(&proof[..proof.len().min(64)]),
        tail_hex: bytes_to_hex(&proof[proof.len().saturating_sub(64)..]),
        verified_blake2b,
        verified_programmable: None,
    })
}

fn run_zk_simulator(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    vk: &VerifyingKey<C>,
    c: F,
    challenges: Vec<F>,
    seed: u32,
) -> Result<Halo2OneRun, JsError> {
    // Sample a witness for the underlying multi-witness relation
    // c = a*b. The ROM-ZK claim here rests on the uniformity of this
    // sample over the witness set composed with the programmability
    // of the transcript; see the halo2_simulator module docs for the
    // full argument. The byte-level no-witness construction that
    // would close the gap on unique-witness relations is research-
    // status and not implemented in this crate.
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(seed));
    let a = sample_nonzero(&mut rng)?;
    let a_inv: F =
        Option::from(a.invert()).ok_or_else(|| JsError::new("a is zero (impossible)"))?;
    let b = c * a_inv;

    let circuit = MulCircuit::<F>::new(a, b);
    let mut writer =
        ProgrammableHalo2Write::<_, C>::new(Cursor::new(Vec::new()), challenges.clone());
    create_proof(params, pk, &[circuit], &[&[&[c]]], &mut rng, &mut writer)
        .map_err(|e| JsError::new(&format!("zk simulator create_proof: {e:?}")))?;
    let proof = writer.finalize().into_inner();

    let verified_blake2b = verify_blake2b(params, vk, c, &proof);
    let verified_programmable = verify_programmable(params, vk, c, &proof, challenges);

    Ok(Halo2OneRun {
        bytes_len: proof.len(),
        head_hex: bytes_to_hex(&proof[..proof.len().min(64)]),
        tail_hex: bytes_to_hex(&proof[proof.len().saturating_sub(64)..]),
        verified_blake2b,
        verified_programmable: Some(verified_programmable),
    })
}

fn verify_blake2b(params: &Params<C>, vk: &VerifyingKey<C>, c: F, proof: &[u8]) -> bool {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, C, Challenge255<C>>::init(proof);
    verify_proof(params, vk, strategy, &[&[&[c]]], &mut transcript).is_ok()
}

fn verify_programmable(
    params: &Params<C>,
    vk: &VerifyingKey<C>,
    c: F,
    proof: &[u8],
    challenges: Vec<F>,
) -> bool {
    let strategy = SingleVerifier::new(params);
    let mut transcript =
        ProgrammableHalo2Read::<_, C>::new(Cursor::new(proof.to_vec()), challenges);
    verify_proof(params, vk, strategy, &[&[&[c]]], &mut transcript).is_ok()
}

/// Number of Fiat-Shamir challenges the `MulCircuit` proof transcript
/// consumes. Determined empirically by the
/// `crate::halo2_shim::CountingTranscript`: 11 for our K=4 single-gate
/// circuit. Padded slightly so the programmable transcript never runs
/// out of pre-programmed values.
fn transcript_challenge_count() -> usize {
    32
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Maximum rejection-sampling attempts before returning an error. The
/// probability of `F::random` producing zero is ~2<sup>-254</sup> for
/// the Pasta scalar field; 32 attempts is a safety bound against a
/// hostile or broken RNG, never reached in practice.
const MAX_NONZERO_SAMPLE_ATTEMPTS: usize = 32;

fn sample_nonzero(rng: &mut impl rand::RngCore) -> Result<F, JsError> {
    for _ in 0..MAX_NONZERO_SAMPLE_ATTEMPTS {
        let candidate = F::random(&mut *rng);
        if !bool::from(candidate.is_zero()) {
            return Ok(candidate);
        }
    }
    Err(JsError::new("rng failed to produce a nonzero scalar"))
}

fn scalar_hex(s: &F) -> String {
    let bytes = s.to_repr();
    let mut out = String::with_capacity(bytes.as_ref().len() * 2);
    for b in bytes.as_ref() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
