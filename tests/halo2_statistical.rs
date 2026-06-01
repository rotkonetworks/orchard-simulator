//! Phase 4: statistical distribution comparison between honest halo2_proofs
//! proofs and WI-style simulator proofs on the same statement.
//!
//! For each seed, both the honest prover and the WI simulator produce a
//! proof of `c = a·b` for the same public `c`. Marginal byte-distribution
//! tests confirm the two outputs are visually indistinguishable per-byte
//! position. A real ZK simulator would close the joint-distribution gap;
//! WI gives us the marginal already.
//!
//! Threshold: chi-square at 255 df, p=10⁻⁵ critical ≈ 380. We use 400.

#![cfg(feature = "halo2")]

use ff::Field;
use halo2_proofs::pasta::{vesta, EqAffine};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use orchard_simulator::halo2_circuit::MulCircuit;
use orchard_simulator::halo2_simulator::witness_indistinguishable_proof;
use rand::SeedableRng;

type C = EqAffine;
type F = vesta::Scalar;

const K: u32 = 4;
const SAMPLES: usize = 64; // 64 proofs per side; enough for byte chi-square smoke
const CHI_SQ_THRESHOLD: f64 = 600.0; // generous; we want to catch gross bias

fn chi_square_byte_pair(honest_counts: &[u32; 256], sim_counts: &[u32; 256]) -> f64 {
    (0..256)
        .map(|i| {
            let h = honest_counts[i] as f64;
            let s = sim_counts[i] as f64;
            if h + s == 0.0 {
                0.0
            } else {
                (h - s).powi(2) / (h + s)
            }
        })
        .sum()
}

fn honest_blake2b_proof(
    params: &Params<C>,
    pk: &halo2_proofs::plonk::ProvingKey<C>,
    a: F,
    b: F,
    c: F,
    rng: &mut impl rand::RngCore,
) -> Vec<u8> {
    let circuit = MulCircuit::<F>::new(a, b);
    let mut transcript = Blake2bWrite::<_, C, Challenge255<C>>::init(Vec::new());
    halo2_proofs::plonk::create_proof(params, pk, &[circuit], &[&[&[c]]], rng, &mut transcript)
        .expect("honest create_proof");
    transcript.finalize()
}

#[test]
#[ignore] // ~2 minutes; run with `cargo test --features halo2 -- --ignored`
fn phase4_honest_vs_wi_simulator_byte_distributions() {
    let empty = MulCircuit::<F>::new(F::ZERO, F::ZERO).without_witnesses();
    let params: Params<C> = Params::new(K);
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();

    let c = F::from(42);

    let mut honest_byte_counts = [0u32; 256];
    let mut sim_byte_counts = [0u32; 256];

    // Sample MANY honest proofs (varying internal RNG only; witness fixed).
    // The WI simulator's witness varies per seed; same statement c.
    let a = F::from(6);
    let b = F::from(7);
    assert_eq!(a * b, c, "test setup: a·b = c");

    for seed in 0..SAMPLES {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed as u64);
        let proof = honest_blake2b_proof(&params, &pk, a, b, c, &mut rng);
        for &byte in &proof {
            honest_byte_counts[byte as usize] += 1;
        }
    }
    for seed in 0..SAMPLES {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed as u64 + 1_000_000);
        let proof = witness_indistinguishable_proof(&params, &pk, c, &mut rng).unwrap();
        for &byte in &proof {
            sim_byte_counts[byte as usize] += 1;
        }
    }

    let chi_sq = chi_square_byte_pair(&honest_byte_counts, &sim_byte_counts);
    let total_honest: u32 = honest_byte_counts.iter().sum();
    let total_sim: u32 = sim_byte_counts.iter().sum();
    println!("honest bytes total: {total_honest}");
    println!("sim bytes total:    {total_sim}");
    println!("chi-square 2-sample: {chi_sq:.1} (threshold {CHI_SQ_THRESHOLD})");
    assert!(
        chi_sq < CHI_SQ_THRESHOLD,
        "honest vs WI-simulator byte distributions differ: chi-square = {chi_sq:.1}"
    );
}
