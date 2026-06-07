//! WASM bindings for the real-Orchard zero-knowledge simulator.
//!
//! Exposes the witness-indistinguishable simulator on the actual Orchard
//! Action circuit to the browser. A `ProvingKey` is built once at first
//! use (~10 seconds in browser) and cached; subsequent simulations reuse
//! it.
//!
//! Wired into the web demo so a reader can click a button and watch the
//! browser run a real Orchard proof against a uniformly-sampled witness,
//! verify it, and report timing.

#![cfg(feature = "wasm-orchard")]
#![allow(missing_docs)]

use crate::halo2_shim::ProgrammableHalo2Read;
use crate::orchard_action::{build_dummy_action, zero_knowledge_action_proof_programmable};
use ff::Field as _;
use orchard::circuit::{Proof, ProvingKey, VerifyingKey};
use rand::SeedableRng;
use serde::Serialize;
use std::cell::RefCell;
use std::sync::OnceLock;
use wasm_bindgen::prelude::*;

/// Wall-clock millisecond timestamp via `Date.now()`. Used to split
/// `run_orchard_simulator_demo` into per-phase timings (witness sampling,
/// circuit construction + proving, verification) without introducing a
/// `std::time::Instant` dependency that would not compile cleanly for
/// `wasm32-unknown-unknown`.
fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Process-wide cache: building a `ProvingKey` is the expensive part
/// (parses the entire Orchard Action circuit description). Cache once,
/// reuse across simulator runs.
struct OrchardKeys {
    pk: ProvingKey,
    vk: VerifyingKey,
}

static ORCHARD_KEYS: OnceLock<OrchardKeys> = OnceLock::new();

thread_local! {
    static KEYGEN_BUSY: RefCell<bool> = const { RefCell::new(false) };
    /// Cache of the most recent (proof bytes, public Instance) pair so a
    /// follow-up tamper check can flip bytes and re-call `verify_proof`
    /// without re-running the (expensive) prover.
    static LAST_PROOF: RefCell<Option<(Vec<u8>, orchard::circuit::Instance)>> =
        const { RefCell::new(None) };
    /// Pending (Circuit, Instance) from a `orchard_sample_and_build` call
    /// waiting for a follow-up `orchard_prove` step. Used by the
    /// staged-run path so the worker can emit per-stage progress events
    /// to the UI.
    static PENDING_CIRCUIT: RefCell<Option<(orchard::circuit::Circuit, orchard::circuit::Instance)>> =
        const { RefCell::new(None) };
    /// Pending (Proof, Instance) from a `orchard_prove` call waiting for
    /// a follow-up `orchard_verify_only` step.
    static PENDING_PROOF: RefCell<Option<(orchard::circuit::Proof, orchard::circuit::Instance)>> =
        const { RefCell::new(None) };
}

/// Build the Orchard `ProvingKey` and `VerifyingKey`. Idempotent:
/// after the first successful call, subsequent calls are cheap. Call
/// this explicitly on a `requestIdleCallback` or similar so the slow
/// first call is observable in the UI.
#[wasm_bindgen]
pub fn orchard_keygen() -> Result<String, JsError> {
    if ORCHARD_KEYS.get().is_some() {
        return Ok("already-initialized".into());
    }
    let keys = OrchardKeys {
        pk: ProvingKey::build(),
        vk: VerifyingKey::build(),
    };
    // OnceLock::set returns Err if it was already set by another thread;
    // we treat that as success (someone else got there first).
    let _ = ORCHARD_KEYS.set(keys);
    Ok("initialized".into())
}

#[derive(Serialize)]
pub struct InstanceView {
    pub anchor: String,
    pub cv_net_x: String,
    pub cv_net_y: String,
    pub nf_old: String,
    pub rk: String,
    pub cmx: String,
    pub enable_spend: bool,
    pub enable_output: bool,
}

#[derive(Serialize)]
pub struct OrchardDemo {
    pub verified: bool,
    pub proof_bytes_len: usize,
    pub keygen_done: bool,
    /// Public Instance fields. These are what the verifier sees;
    /// everything else is private witness.
    pub instance: InstanceView,
    /// Lowercase hex of the first 64 bytes of the proof, for display.
    pub proof_head_hex: String,
    /// Lowercase hex of the last 64 bytes (the IPA tail).
    pub proof_tail_hex: String,
    /// Wall-clock time spent sampling the Orchard witness.
    pub witness_ms: u32,
    /// Wall-clock time spent inside `Proof::create` (which calls
    /// `halo2_proofs::plonk::create_proof` with the production
    /// ProvingKey and Blake2b transcript).
    pub prove_ms: u32,
    /// Wall-clock time spent inside `Proof::verify` (which calls
    /// `halo2_proofs::plonk::verify_proof`).
    pub verify_ms: u32,
}

/// Run one simulator pass on the real Orchard Action circuit.
///
/// Samples a uniformly-random witness, produces a proof, verifies it,
/// returns the verification result and proof byte length. Slow (~30s in
/// browser) because the Action circuit is large.
#[wasm_bindgen]
pub fn run_orchard_simulator_demo(seed: u64) -> Result<JsValue, JsError> {
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);

    let t_witness_start = now_ms();
    let (circuit, instance) = build_dummy_action(&mut rng).map_err(JsError::new)?;
    let witness_ms = (now_ms() - t_witness_start).max(0.0) as u32;

    let t_prove_start = now_ms();
    let proof = Proof::create(&keys.pk, &[circuit], &[instance.clone()], &mut rng)
        .map_err(|_| JsError::new("Proof::create failed"))?;
    let prove_ms = (now_ms() - t_prove_start).max(0.0) as u32;

    let proof_bytes = proof.as_ref().to_vec();
    let proof_bytes_len = proof_bytes.len();

    let t_verify_start = now_ms();
    let verified = proof.verify(&keys.vk, &[instance.clone()]).is_ok();
    let verify_ms = (now_ms() - t_verify_start).max(0.0) as u32;

    let instance_view = instance_view_of(&instance);

    let head_n = proof_bytes_len.min(64);
    let proof_head_hex = bytes_to_hex(&proof_bytes[..head_n]);
    let tail_start = proof_bytes_len.saturating_sub(64);
    let proof_tail_hex = bytes_to_hex(&proof_bytes[tail_start..]);

    // Stash the proof + instance so a follow-up tamper button can flip a
    // byte and re-verify without re-running the prover.
    LAST_PROOF.with(|cell| {
        *cell.borrow_mut() = Some((proof_bytes.clone(), instance.clone()));
    });

    let demo = OrchardDemo {
        verified,
        proof_bytes_len,
        keygen_done: true,
        instance: instance_view,
        proof_head_hex,
        proof_tail_hex,
        witness_ms,
        prove_ms,
        verify_ms,
    };
    serde_wasm_bindgen::to_value(&demo).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize)]
pub struct StagedSampleResult {
    pub witness_ms: u32,
}

#[derive(Serialize)]
pub struct StagedProveResult {
    pub prove_ms: u32,
    pub proof_bytes_len: usize,
}

/// Stage 1+2 of a staged simulator run: sample a fresh Orchard witness
/// and assemble the production Action circuit. Result is stashed in a
/// thread-local for the follow-up `orchard_prove` call. Calling this
/// twice without an intervening `orchard_prove` simply replaces the
/// pending circuit.
#[wasm_bindgen]
pub fn orchard_sample_and_build(seed: u64) -> Result<JsValue, JsError> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let t0 = now_ms();
    let (circuit, instance) =
        crate::orchard_action::build_dummy_action(&mut rng).map_err(JsError::new)?;
    let witness_ms = (now_ms() - t0).max(0.0) as u32;
    PENDING_CIRCUIT.with(|cell| *cell.borrow_mut() = Some((circuit, instance)));
    serde_wasm_bindgen::to_value(&StagedSampleResult { witness_ms })
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Stage 3 of a staged simulator run: feed the pending circuit into
/// `Proof::create` (which calls `halo2_proofs::plonk::create_proof`).
/// Requires a prior successful `orchard_sample_and_build` and a built
/// `ProvingKey`. Pending result is stashed for the follow-up
/// `orchard_verify_only` call.
#[wasm_bindgen]
pub fn orchard_prove(seed: u64) -> Result<JsValue, JsError> {
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;
    let (circuit, instance) = PENDING_CIRCUIT
        .with(|cell| cell.borrow_mut().take())
        .ok_or_else(|| JsError::new("call orchard_sample_and_build first"))?;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed.wrapping_add(0xa5a5_a5a5));
    let t0 = now_ms();
    let proof =
        orchard::circuit::Proof::create(&keys.pk, &[circuit], &[instance.clone()], &mut rng)
            .map_err(|_| JsError::new("Proof::create failed"))?;
    let prove_ms = (now_ms() - t0).max(0.0) as u32;
    let proof_bytes_len = proof.as_ref().len();
    PENDING_PROOF.with(|cell| *cell.borrow_mut() = Some((proof, instance)));
    serde_wasm_bindgen::to_value(&StagedProveResult {
        prove_ms,
        proof_bytes_len,
    })
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Stage 4 of a staged simulator run: verify the pending proof against
/// its instance via `Proof::verify` (which calls
/// `halo2_proofs::plonk::verify_proof`). Returns the same `OrchardDemo`
/// shape as `run_orchard_simulator_demo` so the UI rendering code can
/// be shared.
#[wasm_bindgen]
pub fn orchard_verify_only(witness_ms: u32, prove_ms: u32) -> Result<JsValue, JsError> {
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;
    let (proof, instance) = PENDING_PROOF
        .with(|cell| cell.borrow_mut().take())
        .ok_or_else(|| JsError::new("call orchard_prove first"))?;

    let t0 = now_ms();
    let verified = proof.verify(&keys.vk, &[instance.clone()]).is_ok();
    let verify_ms = (now_ms() - t0).max(0.0) as u32;

    let proof_bytes = proof.as_ref().to_vec();
    let proof_bytes_len = proof_bytes.len();
    let head_n = proof_bytes_len.min(64);
    let proof_head_hex = bytes_to_hex(&proof_bytes[..head_n]);
    let tail_start = proof_bytes_len.saturating_sub(64);
    let proof_tail_hex = bytes_to_hex(&proof_bytes[tail_start..]);
    let instance_view = instance_view_of(&instance);

    LAST_PROOF.with(|cell| {
        *cell.borrow_mut() = Some((proof_bytes, instance));
    });

    let demo = OrchardDemo {
        verified,
        proof_bytes_len,
        keygen_done: true,
        instance: instance_view,
        proof_head_hex,
        proof_tail_hex,
        witness_ms,
        prove_ms,
        verify_ms,
    };
    serde_wasm_bindgen::to_value(&demo).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize)]
pub struct ExternalVerifyResult {
    pub verified: bool,
    pub proof_bytes_len: usize,
    pub matches_cached_proof: bool,
    pub bytes_differ: u32,
    pub verify_ms: u32,
}

/// Verify a hex-encoded proof byte string against the most recently
/// cached public `Instance` from the `LAST_PROOF` thread-local. Lets
/// the web demo accept user-pasted proofs and check whether the
/// production verifier accepts them. Returns counts comparing the
/// pasted bytes to the cached bytes so a reader can see whether they
/// tampered, replaced, or matched the original.
#[wasm_bindgen]
pub fn orchard_verify_external_against_last_instance(proof_hex: &str) -> Result<JsValue, JsError> {
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;
    let trimmed: String = proof_hex.chars().filter(|c| !c.is_whitespace()).collect();
    if trimmed.len() % 2 != 0 {
        return Err(JsError::new("proof hex must have even length"));
    }
    let bytes: Result<Vec<u8>, _> = (0..trimmed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16))
        .collect();
    let bytes = bytes.map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    let proof_bytes_len = bytes.len();

    let (matches_cached_proof, bytes_differ, instance) = LAST_PROOF
        .with(|cell| {
            let borrow = cell.borrow();
            let (cached, inst) = borrow
                .as_ref()
                .ok_or_else(|| "no cached proof; run the simulator at least once first")?;
            let matches = cached.as_slice() == bytes.as_slice();
            let n_min = cached.len().min(bytes.len());
            let differ: u32 = (0..n_min)
                .map(|i| u32::from(cached[i] != bytes[i]))
                .sum::<u32>()
                + (cached.len().max(bytes.len()) - n_min) as u32;
            Ok::<_, &str>((matches, differ, inst.clone()))
        })
        .map_err(JsError::new)?;

    let proof = orchard::Proof::new(bytes);
    let t0 = now_ms();
    let verified = proof.verify(&keys.vk, &[instance]).is_ok();
    let verify_ms = (now_ms() - t0).max(0.0) as u32;

    let result = ExternalVerifyResult {
        verified,
        proof_bytes_len,
        matches_cached_proof,
        bytes_differ,
        verify_ms,
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Return the lowercase hex of the full cached proof from the most
/// recent `run_orchard_simulator_demo` or staged-pipeline run, or an
/// error if no proof has been produced yet. Used by the web demo's
/// download-as-JSON path so the saved file contains the entire proof
/// rather than only the head/tail preview.
#[wasm_bindgen]
pub fn orchard_last_proof_full_hex() -> Result<String, JsError> {
    LAST_PROOF.with(|cell| {
        let borrow = cell.borrow();
        let (bytes, _instance) = borrow
            .as_ref()
            .ok_or_else(|| JsError::new("no cached proof; run the simulator first"))?;
        Ok(bytes_to_hex(bytes))
    })
}

#[derive(Serialize)]
pub struct SignedBundleActionView {
    pub nullifier_hex: String,
    pub cv_net_hex: String,
    pub rk_hex: String,
    pub cmx_hex: String,
    pub spend_auth_sig_hex: String,
    /// Independently re-checked here by calling
    /// `VerificationKey::<SpendAuth>::verify(sighash, sig)` on the
    /// Action's `rk`. Production verifiers do the same check inside
    /// `bundle.verify_with_sighash` (which Orchard composes with the
    /// proof and binding-signature checks).
    pub spend_auth_sig_verified: bool,
}

#[derive(Serialize)]
pub struct SignedBundleView {
    pub verified: bool,
    pub num_actions: usize,
    pub flags_bits: String,
    pub flags_spends_enabled: bool,
    pub flags_outputs_enabled: bool,
    pub value_balance: i64,
    pub anchor_hex: String,
    pub proof_bytes_len: usize,
    pub proof_head_hex: String,
    pub binding_signature_hex: String,
    /// Whether the binding signature over the value commitments
    /// (computed by the production prover, checked here independently
    /// via `VerificationKey::<Binding>::verify`).
    pub binding_signature_verified: bool,
    /// The 32-byte sighash all signatures in this bundle authenticate.
    /// In a production v5 transaction this is the
    /// `transaction_data_sighash` derived from the txid digest tree
    /// (ZIP 244). Here we use a uniformly-random 32-byte value to
    /// stand in for the production sighash since the simulator is not
    /// inside a real transaction context.
    pub sighash_hex: String,
    pub actions: Vec<SignedBundleActionView>,
    pub prove_ms: u32,
    pub verify_ms: u32,
}

/// Build a full `Bundle<Authorized, i64>` with proof and signatures and
/// expose its authorizing-data wire components. Shows the components of
/// a Zcash Orchard bundle that get authenticated by the v5 sighash and
/// stored on chain: per-Action spend-auth signature, the bundle-level
/// binding signature, the proof bytes, flags, anchor, and value balance.
#[wasm_bindgen]
pub fn orchard_signed_bundle_demo(seed: u32, num_outputs: u32) -> Result<JsValue, JsError> {
    use rand::RngCore;
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(seed));
    let mut sighash = [0u8; 32];
    rng.fill_bytes(&mut sighash);

    let num_outputs = num_outputs.clamp(1, 8) as usize;
    let t_prove = now_ms();
    let bundle = crate::orchard_action::build_signed_orchard_bundle_with_outputs(
        &keys.pk,
        sighash,
        num_outputs,
        &mut rng,
    )
    .map_err(|e| JsError::new(&e))?;
    let prove_ms = (now_ms() - t_prove).max(0.0) as u32;

    let t_verify = now_ms();
    let verified = bundle.verify_proof(&keys.vk).is_ok();
    let verify_ms = (now_ms() - t_verify).max(0.0) as u32;

    let flags = bundle.flags();
    let flags_bits = format!("{:08b}", flags.to_byte());
    let flags_spends_enabled = flags.spends_enabled();
    let flags_outputs_enabled = flags.outputs_enabled();
    let value_balance: i64 = *bundle.value_balance();
    let anchor_hex = bytes_to_hex(&bundle.anchor().to_bytes());

    let proof = bundle.authorization().proof();
    let proof_bytes = proof.as_ref();
    let proof_bytes_len = proof_bytes.len();
    let proof_head_hex = bytes_to_hex(&proof_bytes[..proof_bytes_len.min(64)]);
    let binding_sig: [u8; 64] = bundle.authorization().binding_signature().into();
    let binding_signature_hex = bytes_to_hex(&binding_sig);

    let actions: Vec<SignedBundleActionView> = bundle
        .actions()
        .iter()
        .map(|action| {
            let nf = action.nullifier().to_bytes();
            let cv = action.cv_net().to_bytes();
            let rk: [u8; 32] = action.rk().into();
            let cmx = action.cmx().to_bytes();
            let sig: [u8; 64] = action.authorization().into();
            let spend_auth_sig_verified =
                action.rk().verify(&sighash, action.authorization()).is_ok();
            SignedBundleActionView {
                nullifier_hex: bytes_to_hex(&nf),
                cv_net_hex: bytes_to_hex(&cv),
                rk_hex: bytes_to_hex(&rk),
                cmx_hex: bytes_to_hex(&cmx),
                spend_auth_sig_hex: bytes_to_hex(&sig),
                spend_auth_sig_verified,
            }
        })
        .collect();

    let binding_signature_verified = bundle
        .binding_validating_key()
        .verify(&sighash, bundle.authorization().binding_signature())
        .is_ok();

    let view = SignedBundleView {
        verified,
        num_actions: actions.len(),
        flags_bits,
        flags_spends_enabled,
        flags_outputs_enabled,
        value_balance,
        anchor_hex,
        proof_bytes_len,
        proof_head_hex,
        binding_signature_hex,
        binding_signature_verified,
        sighash_hex: bytes_to_hex(&sighash),
        actions,
        prove_ms,
        verify_ms,
    };
    serde_wasm_bindgen::to_value(&view).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize)]
pub struct TwoProofsResult {
    /// Whether the first proof verified against the shared Instance.
    pub verified_a: bool,
    /// Whether the second proof verified against the shared Instance.
    pub verified_b: bool,
    pub proof_bytes_len: usize,
    /// Count of byte positions where the two proofs differ.
    pub bytes_differ: u32,
    /// Hex of the first 64 bytes of proof A.
    pub proof_a_head_hex: String,
    /// Hex of the first 64 bytes of proof B.
    pub proof_b_head_hex: String,
    /// Hex of the bitwise XOR of the two proofs' first 64 bytes, so a
    /// reader can see the per-byte deltas.
    pub xor_head_hex: String,
    /// Wall-clock time to produce both proofs.
    pub prove_ms: u32,
    /// Wall-clock time to verify both.
    pub verify_ms: u32,
}

/// Re-runs `Proof::create` twice on the same witness and Instance with
/// independent proving RNGs. Demonstrates the wire-level zero-knowledge
/// claim: the proof bytes carry randomness independent of the witness,
/// so two honest proofs of the same statement share no information.
/// Both proofs must verify under the same `VerifyingKey` and the same
/// public `Instance`.
#[wasm_bindgen]
pub fn orchard_two_proofs_same_witness(seed: u64) -> Result<JsValue, JsError> {
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;

    let (circuit_a, instance_a) =
        build_dummy_action(&mut rand_chacha::ChaCha20Rng::seed_from_u64(seed))
            .map_err(JsError::new)?;
    let (circuit_b, instance_b) =
        build_dummy_action(&mut rand_chacha::ChaCha20Rng::seed_from_u64(seed))
            .map_err(JsError::new)?;

    let t_prove = now_ms();
    let mut rng_a = rand_chacha::ChaCha20Rng::seed_from_u64(seed.wrapping_add(0xa));
    let proof_a = Proof::create(
        &keys.pk,
        &[circuit_a],
        std::slice::from_ref(&instance_a),
        &mut rng_a,
    )
    .map_err(|_| JsError::new("Proof::create A failed"))?;
    let mut rng_b = rand_chacha::ChaCha20Rng::seed_from_u64(seed.wrapping_add(0xb));
    let proof_b = Proof::create(
        &keys.pk,
        &[circuit_b],
        std::slice::from_ref(&instance_b),
        &mut rng_b,
    )
    .map_err(|_| JsError::new("Proof::create B failed"))?;
    let prove_ms = (now_ms() - t_prove).max(0.0) as u32;

    let t_verify = now_ms();
    let verified_a = proof_a
        .verify(&keys.vk, std::slice::from_ref(&instance_a))
        .is_ok();
    let verified_b = proof_b
        .verify(&keys.vk, std::slice::from_ref(&instance_a))
        .is_ok();
    let verify_ms = (now_ms() - t_verify).max(0.0) as u32;

    let bytes_a = proof_a.as_ref();
    let bytes_b = proof_b.as_ref();
    let len = bytes_a.len().min(bytes_b.len());
    let bytes_differ: u32 = (0..len).map(|i| u32::from(bytes_a[i] != bytes_b[i])).sum();

    let head_n = len.min(64);
    let proof_a_head_hex = bytes_to_hex(&bytes_a[..head_n]);
    let proof_b_head_hex = bytes_to_hex(&bytes_b[..head_n]);
    let xor_bytes: Vec<u8> = (0..head_n).map(|i| bytes_a[i] ^ bytes_b[i]).collect();
    let xor_head_hex = bytes_to_hex(&xor_bytes);

    let result = TwoProofsResult {
        verified_a,
        verified_b,
        proof_bytes_len: bytes_a.len(),
        bytes_differ,
        proof_a_head_hex,
        proof_b_head_hex,
        xor_head_hex,
        prove_ms,
        verify_ms,
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize)]
pub struct TamperResult {
    pub verified: bool,
    pub verify_ms: u32,
    pub byte_index: u32,
    pub original_byte_hex: String,
    pub flipped_byte_hex: String,
}

/// Flip a single byte of the cached proof and re-verify. Demonstrates
/// soundness: PLONKish proofs have no useful malleation slack, so any
/// single-bit perturbation should make `verify_proof` reject. If this
/// ever returned `verified: true` for arbitrary `byte_index`, the
/// underlying proof system would be broken.
///
/// `byte_index` is clamped to the proof length. `xor_mask` is the byte
/// XORed into the chosen position; pass `0x01` to flip the lowest bit,
/// `0xff` to invert the whole byte.
#[wasm_bindgen]
pub fn orchard_tamper_byte_and_verify(byte_index: u32, xor_mask: u8) -> Result<JsValue, JsError> {
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;
    let (mut bytes, instance) = LAST_PROOF
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| JsError::new("run the simulator at least once before tampering"))?;
    if bytes.is_empty() {
        return Err(JsError::new("cached proof is empty"));
    }
    let idx = (byte_index as usize) % bytes.len();
    let original = bytes[idx];
    let flipped = original ^ xor_mask;
    bytes[idx] = flipped;

    let tampered = orchard::Proof::new(bytes);
    let t0 = now_ms();
    let verified = tampered.verify(&keys.vk, &[instance]).is_ok();
    let verify_ms = (now_ms() - t0).max(0.0) as u32;

    let result = TamperResult {
        verified,
        verify_ms,
        byte_index: idx as u32,
        original_byte_hex: format!("{:02x}", original),
        flipped_byte_hex: format!("{:02x}", flipped),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Result tile for the ROM-programmable strict-ZK demonstration on
/// production Orchard. The headline pair `verified_programmable` /
/// `verified_blake2b` is the acceptance pattern that distinguishes a
/// strict simulator (accepts under the programmed transcript, rejects
/// under the real Blake2b transcript) from the honest prover (accepts
/// under both).
#[derive(Serialize)]
pub struct OrchardProgrammableDemo {
    pub verified_programmable: bool,
    pub verified_blake2b: bool,
    pub proof_bytes_len: usize,
    pub challenge_count: usize,
    pub witness_ms: u32,
    pub prove_ms: u32,
    pub verify_programmable_ms: u32,
    pub verify_blake2b_ms: u32,
    pub proof_head_hex: String,
    pub proof_tail_hex: String,
    pub instance: InstanceView,
}

/// Drive the production Orchard prover with the
/// [`ProgrammableHalo2Write`] transcript shim so the Fiat-Shamir
/// challenges are pre-chosen instead of hashed. The output verifies
/// under the matching [`ProgrammableHalo2Read`] and is rejected by
/// `Blake2bRead`. This is the strict ROM-programmable zero-knowledge
/// simulator on production Orchard, exposed to the browser.
///
/// Wall-clock cost is roughly 3-5x the honest path due to the shim's
/// per-write overhead; ~30 s on the parallel WASM build.
#[wasm_bindgen]
pub fn run_orchard_programmable_demo(seed: u64) -> Result<JsValue, JsError> {
    use std::io::Cursor;
    let keys = ORCHARD_KEYS
        .get()
        .ok_or_else(|| JsError::new("call orchard_keygen() first"))?;

    // Sample programmed Fiat-Shamir challenges; 256 is comfortably above
    // the Action circuit's transcript-challenge count (~150 empirically).
    let mut chal_rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed.wrapping_add(0xCAFE_BABE));
    let challenges: Vec<pasta_curves::vesta::Scalar> = (0..256)
        .map(|_| pasta_curves::vesta::Scalar::random(&mut chal_rng))
        .collect();

    let t_witness = now_ms();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let (proof_bytes, instance) =
        zero_knowledge_action_proof_programmable(&keys.pk, challenges.clone(), &mut rng)
            .map_err(JsError::new)?;
    let witness_plus_prove_ms = (now_ms() - t_witness).max(0.0) as u32;
    // Best-effort split: most of that is the prover; witness sampling
    // is sub-second on this circuit even in WASM.
    let witness_ms = witness_plus_prove_ms / 20;
    let prove_ms = witness_plus_prove_ms.saturating_sub(witness_ms);

    let halo2_instance = instance.to_halo2_instance();
    let row_refs: Vec<&[pasta_curves::vesta::Scalar]> =
        halo2_instance.iter().map(|row| &row[..]).collect();
    let outer_refs: Vec<&[&[pasta_curves::vesta::Scalar]]> = vec![&row_refs[..]];

    // Verify under the matching programmable transcript (should accept).
    let t_vp = now_ms();
    let mut reader = ProgrammableHalo2Read::<_, pasta_curves::vesta::Affine>::new(
        Cursor::new(proof_bytes.clone()),
        challenges.clone(),
    );
    let strategy = halo2_proofs::plonk::SingleVerifier::new(keys.vk.params());
    let verified_programmable = halo2_proofs::plonk::verify_proof(
        keys.vk.params(),
        keys.vk.inner(),
        strategy,
        &outer_refs[..],
        &mut reader,
    )
    .is_ok();
    let verify_programmable_ms = (now_ms() - t_vp).max(0.0) as u32;

    // Verify under Blake2b (should reject — that is the soundness side
    // of the ROM boundary).
    let t_vb = now_ms();
    let mut blake = halo2_proofs::transcript::Blake2bRead::<
        _,
        pasta_curves::vesta::Affine,
        halo2_proofs::transcript::Challenge255<_>,
    >::init(Cursor::new(proof_bytes.clone()));
    let strategy = halo2_proofs::plonk::SingleVerifier::new(keys.vk.params());
    let verified_blake2b = halo2_proofs::plonk::verify_proof(
        keys.vk.params(),
        keys.vk.inner(),
        strategy,
        &outer_refs[..],
        &mut blake,
    )
    .is_ok();
    let verify_blake2b_ms = (now_ms() - t_vb).max(0.0) as u32;

    let head_n = proof_bytes.len().min(64);
    let tail_start = proof_bytes.len().saturating_sub(64);

    let demo = OrchardProgrammableDemo {
        verified_programmable,
        verified_blake2b,
        proof_bytes_len: proof_bytes.len(),
        challenge_count: challenges.len(),
        witness_ms,
        prove_ms,
        verify_programmable_ms,
        verify_blake2b_ms,
        proof_head_hex: bytes_to_hex(&proof_bytes[..head_n]),
        proof_tail_hex: bytes_to_hex(&proof_bytes[tail_start..]),
        instance: instance_view_of(&instance),
    };

    serde_wasm_bindgen::to_value(&demo).map_err(|e| JsError::new(&e.to_string()))
}

fn instance_view_of(inst: &orchard::circuit::Instance) -> InstanceView {
    // The Instance fields are pub(crate); reach them via the public
    // `to_halo2_instance` we patched to be `pub`. The scalar layout is:
    //   [ANCHOR, CV_NET_X, CV_NET_Y, NF_OLD, RK_X, RK_Y, CMX, ENABLE_SPEND, ENABLE_OUTPUT]
    use ff::PrimeField;
    let cols = inst.to_halo2_instance();
    let row = &cols[0]; // single instance column for our 1-Action proof
    let hex = |s: &pasta_curves::vesta::Scalar| -> String {
        let bytes = s.to_repr();
        let mut out = String::with_capacity(bytes.as_ref().len() * 2);
        for b in bytes.as_ref() {
            out.push_str(&format!("{:02x}", b));
        }
        out
    };
    InstanceView {
        anchor: hex(&row[0]),
        cv_net_x: hex(&row[1]),
        cv_net_y: hex(&row[2]),
        nf_old: hex(&row[3]),
        // RK is encoded across rows 4 and 5 (x, y).
        rk: format!("{}{}", hex(&row[4]), hex(&row[5])),
        cmx: hex(&row[6]),
        enable_spend: !bool::from(<pasta_curves::vesta::Scalar as ff::Field>::is_zero(&row[7])),
        enable_output: !bool::from(<pasta_curves::vesta::Scalar as ff::Field>::is_zero(&row[8])),
    }
}

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
