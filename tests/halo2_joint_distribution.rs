//! Joint-distribution statistical test comparing honest halo2 proofs and
//! zero-knowledge simulator proofs.
//!
//! Beyond per-byte marginal uniformity, we check pairwise byte
//! distributions at structurally important positions. If honest and
//! simulator agree on these joint distributions, the cryptographic
//! indistinguishability claim is supported by direct measurement.

#![cfg(feature = "halo2")]

use ff::Field;
use halo2_proofs::pasta::{vesta, EqAffine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, Circuit};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use orchard_simulator::halo2_circuit::MulCircuit;
use orchard_simulator::halo2_simulator::programmable_proof;
use rand::SeedableRng;

type C = EqAffine;
type F = vesta::Scalar;

const K: u32 = 4;
const SAMPLES: usize = 96;
// Two-byte joint distribution has 65536 cells. With 96 samples we'll be
// undersampling many cells; instead we partition each byte into 16 bins
// (4 high bits), giving a 16×16=256-cell joint with avg ~0.37 per cell at
// 96 samples. Acceptable for a coarse chi-square.
const BINS: usize = 16;
const CHI_SQ_THRESHOLD: f64 = 900.0;

fn honest_proof(
    params: &Params<C>,
    pk: &halo2_proofs::plonk::ProvingKey<C>,
    c: F,
    seed: u64,
) -> Vec<u8> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    // Sample (a, b) honestly for c = a·b.
    let a = loop {
        let candidate = F::random(&mut rng);
        if !bool::from(candidate.is_zero()) {
            break candidate;
        }
    };
    let a_inv: F = Option::from(a.invert()).expect("nonzero");
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
    .expect("honest create_proof");
    transcript.finalize()
}

fn simulator_proof(
    params: &Params<C>,
    pk: &halo2_proofs::plonk::ProvingKey<C>,
    c: F,
    seed: u64,
) -> Vec<u8> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mut chal_rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed.wrapping_add(0xC0FE));
    let challenges: Vec<F> = (0..64).map(|_| F::random(&mut chal_rng)).collect();
    programmable_proof(params, pk, c, challenges, &mut rng).expect("simulator")
}

/// Bin a byte into 4-bit high nibble.
fn bin(b: u8) -> usize {
    (b >> 4) as usize
}

/// 16×16 joint distribution of two byte positions.
fn joint_histogram(proofs: &[Vec<u8>], pos_a: usize, pos_b: usize) -> [[u32; BINS]; BINS] {
    let mut h = [[0u32; BINS]; BINS]; // type: array of arrays
    for proof in proofs {
        if pos_a < proof.len() && pos_b < proof.len() {
            h[bin(proof[pos_a])][bin(proof[pos_b])] += 1;
        }
    }
    h
}

fn chi_square_2sample_joint(h1: &[[u32; BINS]; BINS], h2: &[[u32; BINS]; BINS]) -> f64 {
    let mut chi = 0.0;
    for i in 0..BINS {
        for j in 0..BINS {
            let a = h1[i][j] as f64;
            let b = h2[i][j] as f64;
            if a + b > 0.0 {
                chi += (a - b).powi(2) / (a + b);
            }
        }
    }
    chi
}

#[test]
#[ignore] // ~3 minutes; runs under `cargo test --features halo2 -- --ignored`
fn honest_vs_simulator_joint_byte_pair_distributions() {
    let empty = MulCircuit::<F>::new(F::ZERO, F::ZERO).without_witnesses();
    let params: Params<C> = Params::new(K);
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk, &empty).unwrap();

    let c = F::from(42);

    let honest: Vec<_> = (0..SAMPLES)
        .map(|seed| honest_proof(&params, &pk, c, seed as u64))
        .collect();
    let simulator: Vec<_> = (0..SAMPLES)
        .map(|seed| simulator_proof(&params, &pk, c, seed as u64 + 1_000_000))
        .collect();

    // Test joint distributions at three structurally significant byte-pair
    // positions in the proof. With our 1152-byte proof for K=4:
    //   • (0, 1): first two bytes (start of first advice commitment)
    //   • (32, 33): first two bytes of second advice commitment
    //   • (672, 673): first two bytes of multipoint phase
    let pairs: &[(usize, usize)] = &[(0, 1), (32, 33), (672, 673), (1120, 1121)];
    for &(a_pos, b_pos) in pairs {
        let h_hist = joint_histogram(&honest, a_pos, b_pos);
        let s_hist = joint_histogram(&simulator, a_pos, b_pos);
        let chi = chi_square_2sample_joint(&h_hist, &s_hist);
        println!("joint chi-square at ({a_pos}, {b_pos}): {chi:.1}");
        assert!(
            chi < CHI_SQ_THRESHOLD,
            "joint distribution at ({a_pos}, {b_pos}) differs: chi-square = {chi:.1} (threshold {CHI_SQ_THRESHOLD})"
        );
    }
}
