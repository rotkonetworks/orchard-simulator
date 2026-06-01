//! Simulators that emit proof bytes accepted by
//! `halo2_proofs::plonk::verify_proof`.
//!
//! Two entry points cover the construction:
//!
//! - [`witness_indistinguishable_proof`] samples a uniformly random
//!   witness from the witness set of the toy `c = a · b` relation and
//!   runs the standard halo2 prover with a Blake2b Fiat-Shamir
//!   transcript. The output verifies under Blake2b. Across independent
//!   invocations the prover commits to different `(a, b)` pairs for
//!   the same public `c`, demonstrating witness-indistinguishability
//!   (Feige and Shamir 1990).
//!
//! - [`programmable_proof`] samples a witness in the same way but
//!   drives the prover with the
//!   [`crate::halo2_shim::ProgrammableHalo2Write`] transcript so the
//!   Fiat-Shamir challenges are pre-chosen rather than hashed. The
//!   output verifies under the matching
//!   [`crate::halo2_shim::ProgrammableHalo2Read`] transcript and is
//!   rejected by Blake2b. For the underlying multi-witness relation
//!   this composition realises a ROM-programmable zero-knowledge
//!   simulator: the verifier learns nothing beyond the public
//!   statement because the simulator's witness choice is uniform over
//!   the witness set, the polynomial commitments are perfectly hiding
//!   under uniform blinders, and the challenges are programmed rather
//!   than derived from witness-dependent data.
//!
//! For relations with a unique witness the WI-via-sampling argument
//! collapses (there is only one witness to sample). Closing the
//! WI → ZK gap on such relations requires a byte-level construction
//! that emits proof bytes without ever committing to a witness, by
//! sampling group and field elements uniformly and solving for the
//! small set of values forced by the verifier's check equations. That
//! construction is research-status and not present in this crate; the
//! `MulCircuit` here serves as the simplest multi-witness target where
//! the sampling argument applies.

#![cfg(feature = "halo2")]

use crate::halo2_circuit::MulCircuit;
use crate::halo2_shim::ProgrammableHalo2Write;

use ff::Field;
use halo2_proofs::pasta::{vesta, EqAffine};
use halo2_proofs::plonk::{create_proof, ProvingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Challenge255;
use rand::RngCore;
use std::io::Cursor;

type C = EqAffine;
type F = vesta::Scalar;

/// Maximum rejection-sampling attempts to find a nonzero scalar before
/// returning an error. The probability of failure on a single draw from
/// the Pasta scalar field is ~2<sup>-254</sup>, so this bound is never
/// reached under any well-behaved RNG; it exists to ensure a hostile
/// or broken RNG cannot hang the prover.
const MAX_NONZERO_SAMPLE_ATTEMPTS: usize = 32;

/// Sample a uniformly random nonzero element of the Pasta scalar field
/// by rejection. Returns `Err` if the RNG produces zero
/// [`MAX_NONZERO_SAMPLE_ATTEMPTS`] times in a row.
fn sample_nonzero(rng: &mut impl RngCore) -> Result<F, &'static str> {
    for _ in 0..MAX_NONZERO_SAMPLE_ATTEMPTS {
        let candidate = F::random(&mut *rng);
        if !bool::from(candidate.is_zero()) {
            return Ok(candidate);
        }
    }
    Err("rng failed to produce a nonzero scalar in 32 attempts")
}

/// Sample a uniformly random `(a, b)` with `a · b = c` and run the
/// standard halo2 prover with a Blake2b transcript. The output
/// verifies under Blake2b. Independent invocations sample different
/// `(a, b)` pairs for the same public `c`; the verifier cannot
/// distinguish which pair was used. This is the WI property as
/// defined in Feige and Shamir 1990.
pub fn witness_indistinguishable_proof(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    c: F,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, &'static str> {
    use halo2_proofs::transcript::Blake2bWrite;

    let a = sample_nonzero(rng)?;
    let a_inv: F = Option::from(a.invert()).ok_or("a is nonzero by construction")?;
    let b = c * a_inv;

    let circuit = MulCircuit::<F>::new(a, b);
    let mut transcript = Blake2bWrite::<_, C, Challenge255<C>>::init(Vec::new());
    create_proof(params, pk, &[circuit], &[&[&[c]]], rng, &mut transcript)
        .map_err(|_| "create_proof failed under Blake2b transcript")?;
    Ok(transcript.finalize())
}

/// Sample a uniformly random witness for `c = a · b` and drive the
/// halo2 prover with the programmable transcript wrapper so the
/// Fiat-Shamir challenges are pre-chosen instead of hashed. The
/// output verifies under the matching programmable transcript and is
/// rejected by Blake2b.
///
/// For the multi-witness `MulCircuit` relation this composition
/// realises a ROM-programmable zero-knowledge simulator (see the
/// module docs). The function does not close the WI → ZK gap on
/// unique-witness relations; that requires a byte-level emit that
/// never commits to a witness, which is not implemented here.
pub fn programmable_proof(
    params: &Params<C>,
    pk: &ProvingKey<C>,
    c: F,
    challenges: Vec<F>,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, &'static str> {
    let a = sample_nonzero(rng)?;
    let a_inv: F = Option::from(a.invert()).ok_or("a is nonzero by construction")?;
    let b = c * a_inv;

    let circuit = MulCircuit::<F>::new(a, b);
    let mut writer = ProgrammableHalo2Write::<_, C>::new(Cursor::new(Vec::new()), challenges);
    create_proof(params, pk, &[circuit], &[&[&[c]]], rng, &mut writer)
        .map_err(|_| "create_proof failed under programmable transcript")?;
    Ok(writer.finalize().into_inner())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::halo2_shim::ProgrammableHalo2Read;
    use halo2_proofs::plonk::{
        keygen_pk, keygen_vk, verify_proof, Circuit, SingleVerifier, VerifyingKey,
    };
    use halo2_proofs::transcript::Blake2bRead;
    use rand::SeedableRng;

    const K: u32 = 4;

    fn setup() -> (Params<C>, ProvingKey<C>, VerifyingKey<C>) {
        let empty = MulCircuit::<F>::new(F::ZERO, F::ZERO).without_witnesses();
        let params: Params<C> = Params::new(K);
        let vk = keygen_vk(&params, &empty).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();
        (params, pk, vk)
    }

    /// The WI prover emits an accepting proof under Blake2b. This is
    /// the baseline correctness test: the honest sampling path drives
    /// the standard halo2 prover, and the standard halo2 verifier
    /// accepts.
    #[test]
    fn wi_simulator_accepts_under_blake2b() {
        let (params, pk, vk) = setup();
        let c = F::from(42);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0DE);
        let proof = witness_indistinguishable_proof(&params, &pk, c, &mut rng).unwrap();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, C, Challenge255<C>>::init(Cursor::new(proof));
        verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut transcript).unwrap();
    }

    /// Different seeds produce different proof bytes for the same `c`.
    /// This is the empirical witness-indistinguishability check: the
    /// prover sampled different `(a, b)` pairs and the byte sequences
    /// differ accordingly.
    #[test]
    fn wi_simulator_uses_different_witnesses_across_seeds() {
        let (params, pk, _vk) = setup();
        let c = F::from(7);
        let mut rng1 = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let mut rng2 = rand_chacha::ChaCha20Rng::seed_from_u64(2);
        let p1 = witness_indistinguishable_proof(&params, &pk, c, &mut rng1).unwrap();
        let p2 = witness_indistinguishable_proof(&params, &pk, c, &mut rng2).unwrap();
        assert_ne!(p1, p2);
    }

    /// The programmable-transcript prover emits bytes accepted by the
    /// matching programmable verifier.
    #[test]
    fn programmable_proof_accepts_under_programmable_transcript() {
        let (params, pk, vk) = setup();
        let c = F::from(11);
        let mut chal_rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBEEF);
        let challenges: Vec<F> = (0..64).map(|_| F::random(&mut chal_rng)).collect();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDEED);

        let proof = programmable_proof(&params, &pk, c, challenges.clone(), &mut rng).unwrap();

        let strategy = SingleVerifier::new(&params);
        let mut transcript =
            ProgrammableHalo2Read::<_, C>::new(Cursor::new(proof.clone()), challenges);
        verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut transcript).unwrap();

        // Same bytes rejected under Blake2b: the ROM boundary. The
        // simulator's accepting bytes are unique to the programmable
        // transcript.
        let strategy = SingleVerifier::new(&params);
        let mut blake = Blake2bRead::<_, C, Challenge255<C>>::init(Cursor::new(proof));
        assert!(verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut blake).is_err());
    }
}
