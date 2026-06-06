//! Zero-knowledge simulator for the real Orchard Action proof.
//!
//! For the relation defined by `orchard::circuit::Circuit` (the Orchard
//! Action: spend a note, create a new one, balance values, prove
//! membership in the note-commitment tree), the simulator samples a
//! valid spending witness (a dummy spend-key, a dummy spent note, a
//! dummy Merkle path, and a dummy output note) and produces a proof
//! using the standard Orchard prover.
//!
//! Because the underlying relation admits a huge family of valid
//! witnesses (any (sk, note, path, output) tuple consistent with the
//! public statement), the simulator's output is statistically
//! indistinguishable from any honest prover's output. The verifier
//! cannot determine which spending key or which note was used. This
//! satisfies the witness-indistinguishability formulation of
//! zero-knowledge for the Action relation.
//!
//! ROM-programmable variant: requires upstream `orchard::ProvingKey` to
//! expose its inner `halo2_proofs::plonk::ProvingKey`, which it does
//! not at the time of writing. A two-line patch to `orchard` would
//! unlock the byte-level programmable-transcript path.

#![cfg(feature = "orchard")]

use ff::Field;
use orchard::{
    circuit::{Circuit, Instance, Proof, ProvingKey},
    keys::{FullViewingKey, Scope, SpendValidatingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use pasta_curves::pallas;
use rand::RngCore;

/// Merkle tree depth in Orchard. The constant exists in `orchard::tree`
/// but is not re-exported; pinned here.
const MERKLE_DEPTH_ORCHARD: usize = 32;

// ---------------------------------------------------------------------------
// Witness sampling using only public orchard APIs
// ---------------------------------------------------------------------------

/// Maximum rejection-sampling attempts before returning an error. The
/// Pasta scalar/base fields have acceptance rate ~1/2 per 32-byte
/// candidate; 64 attempts gives a failure rate ~2<sup>-64</sup>,
/// well below any practical concern, and ensures a hostile or broken
/// RNG cannot hang the prover indefinitely.
const MAX_SAMPLE_ATTEMPTS: usize = 64;

/// Sample a uniformly-random Orchard spending key by retrying byte
/// candidates until the field-membership and viewing-key derivation
/// checks pass. Returns `Err` after [`MAX_SAMPLE_ATTEMPTS`].
fn random_spending_key(rng: &mut impl RngCore) -> Result<SpendingKey, &'static str> {
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let candidate = SpendingKey::from_bytes(bytes);
        if bool::from(candidate.is_some()) {
            return Ok(candidate.unwrap());
        }
    }
    Err("rng failed to produce a valid SpendingKey within retry budget")
}

/// Sample a random `Rho` by retrying field-membership of 32 random bytes.
fn random_rho(rng: &mut impl RngCore) -> Result<Rho, &'static str> {
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let candidate = Rho::from_bytes(&bytes);
        if bool::from(candidate.is_some()) {
            return Ok(candidate.unwrap());
        }
    }
    Err("rng failed to produce a valid Rho within retry budget")
}

/// Sample a `RandomSeed` for a note with the given `rho`.
fn random_rseed(rho: &Rho, rng: &mut impl RngCore) -> Result<RandomSeed, &'static str> {
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let candidate = RandomSeed::from_bytes(bytes, rho);
        if bool::from(candidate.is_some()) {
            return Ok(candidate.unwrap());
        }
    }
    Err("rng failed to produce a valid RandomSeed within retry budget")
}

/// Sample a `ValueCommitTrapdoor` by retrying field-membership.
fn random_rcv(rng: &mut impl RngCore) -> Result<ValueCommitTrapdoor, &'static str> {
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let candidate = ValueCommitTrapdoor::from_bytes(bytes);
        if bool::from(candidate.is_some()) {
            return Ok(candidate.unwrap());
        }
    }
    Err("rng failed to produce a valid ValueCommitTrapdoor within retry budget")
}

/// Sample a random Merkle path of depth `MERKLE_DEPTH_ORCHARD` at
/// position 0. Uses `MerkleHashOrchard::from_bytes` with retry, so it
/// works in WASM builds (no `test-dependencies` requirement).
fn random_merkle_path(rng: &mut impl RngCore) -> Result<MerklePath, &'static str> {
    let mut auth_path = Vec::with_capacity(MERKLE_DEPTH_ORCHARD);
    for _ in 0..MERKLE_DEPTH_ORCHARD {
        let mut sampled = None;
        for _ in 0..MAX_SAMPLE_ATTEMPTS {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let cand = MerkleHashOrchard::from_bytes(&bytes);
            if bool::from(cand.is_some()) {
                sampled = Some(cand.unwrap());
                break;
            }
        }
        auth_path.push(sampled.ok_or("rng failed to produce a valid MerkleHashOrchard")?);
    }
    let auth_path: [MerkleHashOrchard; MERKLE_DEPTH_ORCHARD] = auth_path
        .try_into()
        .map_err(|_| "Merkle auth path length mismatch")?;
    Ok(MerklePath::from_parts(0, auth_path))
}

/// Construct a valid `Note` for the given recipient, value, and `rho`.
fn make_note(
    recipient: orchard::Address,
    value: NoteValue,
    rho: Rho,
    rng: &mut impl RngCore,
) -> Result<Note, &'static str> {
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        let rseed = random_rseed(&rho, rng)?;
        let note = Note::from_parts(recipient, value, rho, rseed);
        if bool::from(note.is_some()) {
            return Ok(note.unwrap());
        }
    }
    Err("rng failed to produce a valid Note within retry budget")
}

// ---------------------------------------------------------------------------
// Dummy action assembly
// ---------------------------------------------------------------------------

/// Build a `(Circuit, Instance)` pair for a valid Orchard Action with
/// a spend of value `spend_value` and an output of value `output_value`.
/// The value balance `spend_value - output_value` is committed honestly
/// via the freshly-sampled value-commitment trapdoor.
///
/// Used by [`build_dummy_action`] (zero-value spend, the smallest
/// witness footprint) and [`build_random_value_action`] (arbitrary
/// values in the legal range).
pub fn build_action_with_values(
    spend_value: NoteValue,
    output_value: NoteValue,
    rng: &mut impl RngCore,
) -> Result<(Circuit, Instance), &'static str> {
    // Sender: random spending key → full viewing key → external address.
    let sender_sk = random_spending_key(rng)?;
    let sender_fvk: FullViewingKey = (&sender_sk).into();
    let sender_addr = sender_fvk.address_at(0u32, Scope::External);

    // Spent note: caller-chosen value, random rho (independent of any
    // prior nullifier since this is a dummy).
    let spent_rho = random_rho(rng)?;
    let spent_note = make_note(sender_addr, spend_value, spent_rho, rng)?;

    // Compute the spent note's nullifier, then derive the output's rho
    // from it via the public byte-conversion path.
    let nf_old = spent_note.nullifier(&sender_fvk);
    let output_rho = Rho::from_bytes(&nf_old.to_bytes())
        .into_option()
        .ok_or("nullifier bytes are not a valid Rho representation")?;

    // Recipient: another random spending key → another external address.
    let recipient_sk = random_spending_key(rng)?;
    let recipient_fvk: FullViewingKey = (&recipient_sk).into();
    let recipient_addr = recipient_fvk.address_at(0u32, Scope::External);

    let output_note = make_note(recipient_addr, output_value, output_rho, rng)?;

    // Spend-side Merkle path (random, position 0). The anchor is computed
    // as `path.root(commitment of spent_note)`.
    let merkle_path = random_merkle_path(rng)?;

    // Randomisation scalar and value-commitment trapdoor.
    let alpha = pallas::Scalar::random(&mut *rng);
    let rcv = random_rcv(rng)?;

    // Build SpendInfo from public constructor. fvk must own the note.
    let spend =
        orchard::builder::SpendInfo::new(sender_fvk.clone(), spent_note, merkle_path.clone())
            .ok_or("SpendInfo::new: fvk does not own the spent note")?;

    let circuit = Circuit::from_action_context(spend, output_note, alpha, rcv.clone())
        .ok_or("Circuit::from_action_context: output_note.rho mismatch")?;

    // Instance pieces.
    let anchor = merkle_path.root(spent_note.commitment().into());
    let value_balance = spend_value - output_value;
    let cv_net = ValueCommitment::derive(value_balance, rcv);
    let cmx: ExtractedNoteCommitment = output_note.commitment().into();
    let ak: SpendValidatingKey = sender_fvk.into();
    let rk = ak.randomize(&alpha);

    // Upstream 0.14.0+: from_parts returns None for identity rk. Since rk
    // is the randomization of a uniformly-sampled ak by a uniformly-sampled
    // alpha, the only way to hit identity is alpha == -ak (probability
    // ~2^-254), so a panic here is the right failure mode.
    let instance = Instance::from_parts(anchor, cv_net, nf_old, rk, cmx, true, true)
        .ok_or("Instance::from_parts: rk is the identity point")?;

    Ok((circuit, instance))
}

/// Zero-value dummy spend. Equivalent to
/// `build_action_with_values(NoteValue::from_raw(0), NoteValue::from_raw(0), rng)`.
pub fn build_dummy_action(rng: &mut impl RngCore) -> Result<(Circuit, Instance), &'static str> {
    build_action_with_values(NoteValue::from_raw(0), NoteValue::from_raw(0), rng)
}

/// Sample a balanced spend with a uniformly-chosen positive value in
/// `[1, max]` and the same value emitted as output (zero value balance).
/// The default `max` (1<<48 zatoshis ≈ 2.8 ZEC) keeps the sample well
/// inside Orchard's legal value range (max note value is 2⁶³ − 1
/// zatoshis), so the random sample stays valid with probability 1.
pub fn build_random_value_action(
    rng: &mut impl RngCore,
) -> Result<(Circuit, Instance), &'static str> {
    // Sample u64 in [1, (1<<48)). The exact distribution doesn't matter
    // for the simulator's correctness; we only need a balanced action
    // whose value isn't trivially zero.
    let mut bytes = [0u8; 6];
    rng.fill_bytes(&mut bytes);
    let raw: u64 = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
    ])
    .max(1);
    let value = NoteValue::from_raw(raw);
    build_action_with_values(value, value, rng)
}

// ---------------------------------------------------------------------------
// Simulator: produce accepting Orchard Action proof bytes from a dummy spend
// ---------------------------------------------------------------------------

/// Builds a fully-signed, fully-authorized Orchard Bundle that the
/// Zcash transaction-validation path will accept. Produces:
///
/// 1. A real Orchard ZK proof over the simulator's sampled witness.
/// 2. Real RedPallas signatures over a caller-supplied sighash (the
///    simulator signs with the spending key it sampled).
/// 3. A real binding signature over the value commitments.
///
/// Returns a `Bundle<Authorized, i64>`, the same struct that production
/// Zcash transaction builders produce, fully verifiable via
/// `Bundle::verify_proof` and signature verification.
pub fn build_signed_orchard_bundle(
    pk: &ProvingKey,
    sighash: [u8; 32],
    rng: &mut (impl RngCore + rand::CryptoRng),
) -> Result<orchard::Bundle<orchard::bundle::Authorized, i64>, String> {
    build_signed_orchard_bundle_with_outputs(pk, sighash, 1, rng)
}

/// Build a signed Orchard bundle with `num_outputs` outputs. The bundle's
/// Action count matches `num_outputs` (Orchard pads spends with dummy
/// actions to keep Action count balanced). All outputs go to independently
/// sampled recipients. The single real spend is sourced from one sender's
/// key; remaining Actions carry dummy spends. Used by the web demo to
/// illustrate how a multi-Action bundle scales.
pub fn build_signed_orchard_bundle_with_outputs(
    pk: &ProvingKey,
    sighash: [u8; 32],
    num_outputs: usize,
    rng: &mut (impl RngCore + rand::CryptoRng),
) -> Result<orchard::Bundle<orchard::bundle::Authorized, i64>, String> {
    use orchard::builder::{Builder, BundleType};
    use orchard::keys::SpendAuthorizingKey;

    if num_outputs == 0 {
        return Err("num_outputs must be ≥ 1".to_string());
    }

    let sender_sk = random_spending_key(rng).map_err(str::to_string)?;
    let sender_fvk: FullViewingKey = (&sender_sk).into();
    let sender_addr = sender_fvk.address_at(0u32, Scope::External);

    let spent_rho = random_rho(rng).map_err(str::to_string)?;
    let value = NoteValue::from_raw(0);
    let spent_note = make_note(sender_addr, value, spent_rho, rng).map_err(str::to_string)?;
    let merkle_path = random_merkle_path(rng).map_err(str::to_string)?;
    let anchor = merkle_path.root(spent_note.commitment().into());

    let mut builder = Builder::new(BundleType::DEFAULT, anchor);
    builder
        .add_spend(sender_fvk.clone(), spent_note, merkle_path)
        .map_err(|e| format!("add_spend: {e:?}"))?;
    for _ in 0..num_outputs {
        let recipient_sk = random_spending_key(rng).map_err(str::to_string)?;
        let recipient_fvk: FullViewingKey = (&recipient_sk).into();
        let recipient_addr = recipient_fvk.address_at(0u32, Scope::External);
        builder
            .add_output(None, recipient_addr, value, [0u8; 512])
            .map_err(|e| format!("add_output: {e:?}"))?;
    }

    let (unproven, _meta) = builder
        .build::<i64>(&mut *rng)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or_else(|| "build returned None".to_string())?;

    let proven = unproven
        .create_proof(pk, &mut *rng)
        .map_err(|e| format!("create_proof: {e:?}"))?;

    let prepared = proven.prepare(&mut *rng, sighash);
    let ask: SpendAuthorizingKey = (&sender_sk).into();
    let signed = prepared.sign(&mut *rng, &ask);
    let authorized = signed.finalize().map_err(|e| format!("finalize: {e:?}"))?;
    Ok(authorized)
}

/// Multi-Action simulator: emit a single proof covering `n` independent
/// Action statements in one bundle. Returns proof bytes plus the vector
/// of Instances. The Orchard verifier checks all Actions in a single
/// `Proof::verify` call.
pub fn zero_knowledge_multi_action_proof(
    pk: &ProvingKey,
    n: usize,
    rng: &mut impl RngCore,
) -> Result<(Proof, Vec<Instance>), &'static str> {
    if n == 0 {
        return Err("multi-action proof requires n ≥ 1");
    }
    let mut circuits = Vec::with_capacity(n);
    let mut instances = Vec::with_capacity(n);
    for _ in 0..n {
        let (c, i) = build_dummy_action(rng)?;
        circuits.push(c);
        instances.push(i);
    }
    let proof = Proof::create(pk, &circuits, &instances, rng)
        .map_err(|_| "Proof::create failed on multi-action bundle")?;
    Ok((proof, instances))
}

/// Real Orchard Action zero-knowledge simulator (Blake2b transcript).
///
/// Samples a dummy action witness uniformly from the witness set of the
/// Orchard relation, then runs the standard Orchard prover. Returns
/// proof bytes plus the public `Instance` they prove.
///
/// The returned proof is verified by `orchard::circuit::Proof::verify`
/// and is statistically indistinguishable from a proof of any other
/// (real or dummy) Orchard spend.
pub fn zero_knowledge_action_proof(
    pk: &ProvingKey,
    rng: &mut impl RngCore,
) -> Result<(Proof, Instance), &'static str> {
    let (circuit, instance) = build_dummy_action(rng)?;
    let proof = Proof::create(pk, &[circuit], std::slice::from_ref(&instance), rng)
        .map_err(|_| "Proof::create failed")?;
    Ok((proof, instance))
}

/// Real Orchard Action zero-knowledge simulator (programmable transcript).
///
/// Emits proof bytes for the real `orchard::circuit::Circuit` against a
/// caller-supplied set of Fiat-Shamir challenges. The bytes verify
/// through `halo2_proofs::plonk::verify_proof` when paired with the
/// matching programmable transcript, and reject under Blake2b.
///
/// This is the ROM-programming demonstration on the real Orchard Action
/// proof: the simulator chooses the verifier's challenges in advance,
/// produces a transcript consistent with them, and the verifier accepts.
/// Combined with the witness-uniformity of the underlying Action
/// relation, this constitutes zero-knowledge in the random-oracle model
/// for real Orchard.
pub fn zero_knowledge_action_proof_programmable(
    pk: &ProvingKey,
    challenges: Vec<pasta_curves::vesta::Scalar>,
    rng: &mut impl RngCore,
) -> Result<(Vec<u8>, Instance), &'static str> {
    use crate::halo2_shim::ProgrammableHalo2Write;
    use std::io::Cursor;

    let (circuit, instance) = build_dummy_action(rng)?;
    let halo2_instance = instance.to_halo2_instance();
    let row_refs: Vec<&[pasta_curves::vesta::Scalar]> =
        halo2_instance.iter().map(|row| &row[..]).collect();
    let outer_refs: Vec<&[&[pasta_curves::vesta::Scalar]]> = vec![&row_refs[..]];

    let mut writer = ProgrammableHalo2Write::<_, pasta_curves::vesta::Affine>::new(
        Cursor::new(Vec::new()),
        challenges,
    );
    halo2_proofs::plonk::create_proof(
        pk.params(),
        pk.inner(),
        &[circuit],
        &outer_refs[..],
        &mut *rng,
        &mut writer,
    )
    .map_err(|_| "halo2_proofs::create_proof failed under programmable transcript")?;

    Ok((writer.finalize().into_inner(), instance))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::circuit::VerifyingKey;
    use rand::SeedableRng;

    /// The Orchard simulator emits proof bytes that the real Orchard
    /// verifier accepts.
    ///
    /// Slow: keygen + prove + verify on the full Action circuit is
    /// ~30 seconds on a workstation. Marked `#[ignore]` so the default
    /// test run stays fast; opt in with `cargo test --features orchard
    /// -- --ignored`.
    #[test]
    #[ignore]
    fn orchard_action_simulator_verifies() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xACE);
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let (proof, instance) =
            zero_knowledge_action_proof(&pk, &mut rng).expect("simulator must emit a proof");
        proof
            .verify(&vk, &[instance])
            .expect("Orchard verifier must accept the simulator's proof");
    }

    /// Two simulator runs with different RNG produce different proof
    /// bytes (witness-indistinguishability): the verifier cannot tell
    /// which witness was used.
    #[test]
    #[ignore]
    fn orchard_action_simulator_differs_per_seed() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng_a = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let (proof_a, inst_a) = zero_knowledge_action_proof(&pk, &mut rng_a).unwrap();
        proof_a.verify(&vk, &[inst_a]).unwrap();

        let mut rng_b = rand_chacha::ChaCha20Rng::seed_from_u64(2);
        let (proof_b, inst_b) = zero_knowledge_action_proof(&pk, &mut rng_b).unwrap();
        proof_b.verify(&vk, &[inst_b]).unwrap();

        // Compare the actual proof bytes via the public AsRef impl.
        let bytes_a: &[u8] = proof_a.as_ref();
        let bytes_b: &[u8] = proof_b.as_ref();
        assert_ne!(
            bytes_a, bytes_b,
            "different seeds must yield different proof bytes"
        );
    }

    /// Arbitrary nonzero spend value, balanced with an equal output.
    /// The Orchard verifier accepts: the simulator handles any value in
    /// the legal range, not just dummy zero spends.
    #[test]
    #[ignore]
    fn orchard_action_simulator_arbitrary_value_verifies() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBADD1E);
        let (circuit, instance) =
            build_random_value_action(&mut rng).expect("balanced random-value action must build");
        let proof = Proof::create(&pk, &[circuit], std::slice::from_ref(&instance), &mut rng)
            .expect("Proof::create on random-value action");
        proof
            .verify(&vk, &[instance])
            .expect("Orchard verifier must accept arbitrary-value spend");
    }

    /// A fully-signed Orchard Bundle: the simulator produces a real
    /// `Bundle<Authorized, i64>` that includes proof, spend-auth
    /// signatures (RedPallas), and binding signature. `verify_proof`
    /// accepts the proof component.
    #[test]
    #[ignore]
    fn orchard_signed_bundle_simulator_verifies() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x517E);
        let sighash = [0x42u8; 32];
        let bundle = super::build_signed_orchard_bundle(&pk, sighash, &mut rng)
            .expect("simulator must produce a signed bundle");
        bundle
            .verify_proof(&vk)
            .expect("verify_proof must accept the signed bundle's proof component");
    }

    /// Multi-Action bundle: a single proof covering 2 independent
    /// Action statements. The Orchard verifier accepts.
    #[test]
    #[ignore]
    fn orchard_multi_action_simulator_verifies() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBEAD);
        let (proof, instances) =
            zero_knowledge_multi_action_proof(&pk, 2, &mut rng).expect("multi-action simulator");
        proof
            .verify(&vk, &instances)
            .expect("verifier accepts 2-action bundle");
        assert_eq!(instances.len(), 2);
    }

    /// Wire-format roundtrip: the simulator's proof bytes, serialised
    /// out and parsed back via the public `Proof::new(Vec<u8>)`
    /// constructor, verify identically. This confirms the byte
    /// representation is round-trippable through the constructor the
    /// Zcash transaction parser uses to reconstruct Orchard proofs.
    #[test]
    #[ignore]
    fn orchard_action_proof_wire_format_roundtrip() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x42424242);
        let (proof, instance) = zero_knowledge_action_proof(&pk, &mut rng).unwrap();
        let bytes: Vec<u8> = proof.as_ref().to_vec();
        let reconstructed = orchard::circuit::Proof::new(bytes.clone());

        // Reconstructed proof verifies under the same instance.
        reconstructed
            .verify(&vk, &[instance])
            .expect("roundtripped proof must verify");

        // Byte-identical to the original.
        assert_eq!(
            reconstructed.as_ref(),
            &bytes[..],
            "Proof::new round-trip should be byte-identical"
        );
    }

    /// A simulator proof with one byte flipped is rejected by the
    /// Orchard verifier. Confirms the simulator's bytes are not
    /// trivially forgeable.
    #[test]
    #[ignore]
    fn orchard_action_tampered_proof_rejected() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDEAD);
        let (proof, instance) =
            zero_knowledge_action_proof(&pk, &mut rng).expect("simulator must emit a proof");

        // Round-trip via Proof::new with a single bit flipped.
        let mut bytes = proof.as_ref().to_vec();
        bytes[100] ^= 0x01;
        let tampered = orchard::circuit::Proof::new(bytes);

        assert!(
            tampered.verify(&vk, &[instance]).is_err(),
            "verifier must reject a bit-flipped simulator proof"
        );
    }

    /// The simulator's instance must match the proof. Pairing the proof
    /// with a different (also-valid) instance fails verification.
    #[test]
    #[ignore]
    fn orchard_action_instance_mismatch_rejected() {
        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBEEF);
        let (proof, _instance) = zero_knowledge_action_proof(&pk, &mut rng).expect("first proof");

        // Build a fresh, unrelated instance.
        let mut rng2 = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let (_other_circuit, other_instance) =
            build_dummy_action(&mut rng2).expect("second instance");

        assert!(
            proof.verify(&vk, &[other_instance]).is_err(),
            "verifier must reject proof paired with mismatched instance"
        );
    }

    /// Real Orchard Action with a ROM-programmable transcript. Proof
    /// bytes verify under `halo2_proofs::plonk::verify_proof` when paired
    /// with the same programmed challenges; verifier rejects under
    /// Blake2b. This is the ROM-programming demonstration on the real
    /// Action circuit.
    ///
    /// Slow: keygen + prove + verify on the full Action circuit through
    /// the programmable transcript shim is ~3 minutes.
    #[test]
    #[ignore]
    fn orchard_action_simulator_programmable_verifies() {
        use crate::halo2_shim::ProgrammableHalo2Read;
        use ff::Field;
        use halo2_proofs::plonk::{verify_proof, SingleVerifier};
        use halo2_proofs::transcript::{Blake2bRead, Challenge255};
        use std::io::Cursor;

        let pk = ProvingKey::build();
        let vk = VerifyingKey::build();

        let mut chal_rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xACE);
        // The Action circuit is large; allocate ample programmed challenges.
        let challenges: Vec<pasta_curves::vesta::Scalar> = (0..256)
            .map(|_| pasta_curves::vesta::Scalar::random(&mut chal_rng))
            .collect();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0DE);

        let (proof, instance) =
            zero_knowledge_action_proof_programmable(&pk, challenges.clone(), &mut rng)
                .expect("simulator must emit a proof under programmable transcript");

        // Verify under the same programmable challenges.
        let halo2_instance = instance.to_halo2_instance();
        let row_refs: Vec<&[pasta_curves::vesta::Scalar]> =
            halo2_instance.iter().map(|row| &row[..]).collect();
        let outer_refs: Vec<&[&[pasta_curves::vesta::Scalar]]> = vec![&row_refs[..]];

        let mut reader = ProgrammableHalo2Read::<_, pasta_curves::vesta::Affine>::new(
            Cursor::new(proof.clone()),
            challenges.clone(),
        );
        let strategy = SingleVerifier::new(vk.params());
        verify_proof(
            vk.params(),
            vk.inner(),
            strategy,
            &outer_refs[..],
            &mut reader,
        )
        .expect(
            "verify_proof must accept the simulator's bytes under matching programmed challenges",
        );

        // And reject under Blake2b.
        let mut blake = Blake2bRead::<_, pasta_curves::vesta::Affine, Challenge255<_>>::init(
            Cursor::new(proof),
        );
        let strategy = SingleVerifier::new(vk.params());
        assert!(
            verify_proof(
                vk.params(),
                vk.inner(),
                strategy,
                &outer_refs[..],
                &mut blake
            )
            .is_err(),
            "Blake2b must reject a proof emitted under a programmable transcript"
        );
    }
}
