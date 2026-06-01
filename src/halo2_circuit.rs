//! Minimal Halo 2 circuit used to exercise the halo2_proofs integration.
//!
//! A single multiplication gate: `q_mul * (a * b - c) = 0`. No lookups, no
//! rotations, one instance column for `c`. Small enough to read; sufficient
//! to drive the entire halo2_proofs prover/verifier pipeline through the
//! programmable transcript shim.

#![cfg(feature = "halo2")]

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Public configuration shared between `configure` and `synthesize`.
#[derive(Clone, Debug)]
pub struct MulConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub instance: Column<Instance>,
    pub s_mul: Selector,
}

/// Multiplication circuit: prove `a * b = c` where `c` is public.
#[derive(Clone, Debug)]
pub struct MulCircuit<F: Field> {
    pub a: Value<F>,
    pub b: Value<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> MulCircuit<F> {
    pub fn new(a: F, b: F) -> Self {
        Self {
            a: Value::known(a),
            b: Value::known(b),
            _marker: PhantomData,
        }
    }
}

/// Zeroize-on-drop wrapper around the `MulCircuit` witness scalars.
///
/// `halo2_proofs::circuit::Value<F>` is `Copy` and exposes no public
/// mutation path, so we can't make the `Value<F>` fields of `MulCircuit`
/// directly zeroize-on-drop. The workaround: store the secret `F`s in
/// our own struct that owns them, implements `Zeroize`/`Drop` with a
/// compiler fence, and materialises a fresh `MulCircuit` only when the
/// prover calls `to_circuit`. The materialised `MulCircuit` borrows no
/// memory from this wrapper, so the wrapper's drop covers the long-lived
/// witness storage.
pub struct ZeroizingMulWitness<F: Field> {
    a: F,
    b: F,
}

impl<F: Field> ZeroizingMulWitness<F> {
    pub fn new(a: F, b: F) -> Self {
        Self { a, b }
    }

    pub fn to_circuit(&self) -> MulCircuit<F> {
        MulCircuit::new(self.a, self.b)
    }

    /// The product `a · b`, which is the value `c` the proof commits to.
    pub fn product(&self) -> F {
        self.a * self.b
    }
}

impl<F: Field> Drop for ZeroizingMulWitness<F> {
    fn drop(&mut self) {
        self.a = F::ZERO;
        self.b = F::ZERO;
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<F: Field> Circuit<F> for MulCircuit<F> {
    type Config = MulConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let instance = meta.instance_column();
        let s_mul = meta.selector();

        meta.enable_equality(c);
        meta.enable_equality(instance);

        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            vec![s * (a * b - c)]
        });

        MulConfig {
            a,
            b,
            c,
            instance,
            s_mul,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let c_cell = layouter.assign_region(
            || "mul",
            |mut region| {
                config.s_mul.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.a, 0, || self.a)?;
                region.assign_advice(|| "b", config.b, 0, || self.b)?;
                region.assign_advice(|| "c = a*b", config.c, 0, || self.a * self.b)
            },
        )?;
        layouter.constrain_instance(c_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}

// =============================================================
// Baseline tests: honest prove + verify through the shim
// =============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::halo2_shim::{ProgrammableHalo2Read, ProgrammableHalo2Write};
    use halo2_proofs::pasta::{vesta, EqAffine};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use rand::SeedableRng;
    use std::io::Cursor;

    type C = EqAffine;
    type F = vesta::Scalar;

    const K: u32 = 4; // 2^K rows in the circuit; minimal for one gate.

    fn honest_proof_via_blake2b() -> (Params<C>, halo2_proofs::plonk::VerifyingKey<C>, Vec<u8>, F) {
        // Tiny statement: prove 3 * 5 = 15.
        let a = F::from(3);
        let b = F::from(5);
        let c = a * b;

        let circuit = MulCircuit::<F>::new(a, b);
        let empty = circuit.without_witnesses();

        let params: Params<C> = Params::new(K);
        let vk = keygen_vk(&params, &empty).expect("keygen_vk failed");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("keygen_pk failed");

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0DE);
        let mut transcript = Blake2bWrite::<_, C, Challenge255<C>>::init(Vec::new());
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&[c]]],
            &mut rng,
            &mut transcript,
        )
        .expect("create_proof failed");
        let proof = transcript.finalize();
        (params, vk, proof, c)
    }

    /// The `ZeroizingMulWitness` wrapper produces a circuit equivalent
    /// to a direct `MulCircuit::new` call, and the wrapper drops cleanly.
    /// (Verifying the underlying memory has actually been zeroed requires
    /// inspecting raw bytes, which is platform-dependent; this test only
    /// confirms the API works.)
    #[test]
    fn zeroizing_witness_produces_equivalent_circuit() {
        let w = ZeroizingMulWitness::<F>::new(F::from(3), F::from(5));
        assert_eq!(w.product(), F::from(15));
        let circuit = w.to_circuit();
        // Drop the wrapper; the circuit holds Value<F> independent copies.
        drop(w);
        // The circuit is still usable.
        let _empty = circuit.without_witnesses();
    }

    #[test]
    fn baseline_honest_prove_verify_blake2b() {
        let (params, vk, proof, c) = honest_proof_via_blake2b();
        let mut transcript = Blake2bRead::<_, C, Challenge255<C>>::init(Cursor::new(proof.clone()));
        let strategy = SingleVerifier::new(&params);
        verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut transcript)
            .expect("verify_proof failed under Blake2b");
    }

    /// The ROM-programming demonstration at the halo2_proofs layer.
    ///
    /// Run `create_proof` with our `ProgrammableHalo2Write` (which returns
    /// pre-chosen challenges instead of Blake2b output). The prover's bytes
    /// then encode commitments and openings consistent with those programmed
    /// challenges. Run `verify_proof` with `ProgrammableHalo2Read` using the
    /// same challenges: ACCEPT. Run `verify_proof` with `Blake2bRead`: REJECT,
    /// because Blake2b derives different challenges from the same bytes and
    /// the math no longer balances.
    #[test]
    fn create_and_verify_proof_under_programmable_transcript() {
        let a = F::from(3);
        let b = F::from(5);
        let c = a * b;

        let circuit = MulCircuit::<F>::new(a, b);
        let empty = circuit.without_witnesses();

        let params: Params<C> = Params::new(K);
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("keygen_pk");

        // Pre-chose enough challenges to cover every `squeeze_challenge` call
        // create_proof + verify_proof will make. ~32 is more than enough for
        // a single-gate circuit at K=4. Use a deterministic RNG for the values.
        let mut chal_rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xCAFE);
        let programmed: Vec<F> = (0..64).map(|_| F::random(&mut chal_rng)).collect();

        // Prove with the programmable transcript.
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0DE);
        let mut writer =
            ProgrammableHalo2Write::<_, C>::new(Cursor::new(Vec::new()), programmed.clone());
        create_proof(&params, &pk, &[circuit], &[&[&[c]]], &mut rng, &mut writer)
            .expect("create_proof failed under programmable transcript");
        let proof = writer.finalize().into_inner();

        // Verify under the SAME programmable transcript: accept.
        let mut reader =
            ProgrammableHalo2Read::<_, C>::new(Cursor::new(proof.clone()), programmed.clone());
        let strategy = SingleVerifier::new(&params);
        verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut reader)
            .expect("verify_proof must accept under same programmed challenges");

        // Verify the SAME proof bytes under Blake2b: reject. The bytes encode
        // evidence consistent with `programmed` challenges; Blake2b derives
        // different ones from the same bytes, so the equation doesn't balance.
        let mut blake = Blake2bRead::<_, C, Challenge255<C>>::init(Cursor::new(proof));
        let strategy = SingleVerifier::new(&params);
        assert!(
            verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut blake).is_err(),
            "proof from programmable transcript must NOT verify under Blake2b"
        );
    }

    #[test]
    fn baseline_honest_proof_rejected_under_programmable_transcript_with_wrong_challenges() {
        // Sanity check that the programmable transcript actually changes behaviour:
        // an honest Blake2b-derived proof should NOT verify when the verifier is
        // given arbitrary programmed challenges instead of the Blake2b-derived ones.
        let (params, vk, proof, c) = honest_proof_via_blake2b();

        // Programme some arbitrary challenges (likely wrong).
        let prog: Vec<F> = (0..32).map(F::from).collect();
        let mut transcript = ProgrammableHalo2Read::<_, C>::new(Cursor::new(proof), prog);
        let strategy = SingleVerifier::new(&params);
        let result = verify_proof(&params, &vk, strategy, &[&[&[c]]], &mut transcript);
        assert!(
            result.is_err(),
            "honest proof must NOT verify under arbitrary programmed challenges"
        );
    }
}
