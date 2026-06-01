//! Statistical test on real-Orchard simulator output.
//!
//! Generates 8 proofs from the real Orchard Action simulator (different
//! RNG seeds, different witnesses), concatenates their bytes, and runs a
//! chi-square byte-marginal goodness-of-fit test against the uniform
//! distribution on `[0, 255]`. With 8 × 4992 = 39 936 bytes total,
//! expected per-bin count ≈ 156 and we use a generous chi-square
//! threshold of 600 (255 df, p≈10⁻¹⁵).
//!
//! Slow: ~12 minutes for 8 proofs at ~90 s each. Run with
//! `cargo test --features orchard --test orchard_statistical -- --ignored`.

#![cfg(feature = "orchard")]

use orchard::circuit::{ProvingKey, VerifyingKey};
use orchard_simulator::orchard_action::zero_knowledge_action_proof;
use rand::SeedableRng;

const SAMPLES: usize = 8;
const CHI_SQ_THRESHOLD: f64 = 600.0;

fn chi_square_byte_uniform(counts: &[u32; 256]) -> f64 {
    let total: u32 = counts.iter().sum();
    let expected = total as f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum()
}

#[test]
#[ignore]
fn real_orchard_simulator_byte_marginal_uniform() {
    let pk = ProvingKey::build();
    let vk = VerifyingKey::build();

    let mut counts = [0u32; 256];
    let mut total_bytes = 0usize;

    for seed in 0..SAMPLES {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed as u64);
        let (proof, instance) =
            zero_knowledge_action_proof(&pk, &mut rng).expect("simulator must produce proof");
        proof
            .verify(&vk, &[instance])
            .expect("simulator proof must verify");
        let bytes: &[u8] = proof.as_ref();
        total_bytes += bytes.len();
        for &b in bytes {
            counts[b as usize] += 1;
        }
    }

    let chi_sq = chi_square_byte_uniform(&counts);
    println!("total bytes across {SAMPLES} proofs: {total_bytes}");
    println!("chi-square: {chi_sq:.1} (threshold {CHI_SQ_THRESHOLD})");
    assert!(
        chi_sq < CHI_SQ_THRESHOLD,
        "real-Orchard simulator byte distribution failed uniform chi-square: \
         chi_sq = {chi_sq:.1} > {CHI_SQ_THRESHOLD}",
    );
}
