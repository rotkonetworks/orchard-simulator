//! Measure the exact byte structure of a halo2_proofs proof for our
//! single-gate circuit, so the no-witness simulator emits the same
//! sequence of points and scalars.

#![cfg(feature = "halo2")]

use ff::Field;
use halo2_proofs::pasta::{vesta, EqAffine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, Circuit};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};
use orchard_simulator::halo2_circuit::MulCircuit;
use orchard_simulator::halo2_shim::CountingTranscript;

type C = EqAffine;
type F = vesta::Scalar;

#[test]
fn measure_proof_byte_count() {
    let k: u32 = 4;
    let empty = MulCircuit::<F>::new(F::ZERO, F::ZERO).without_witnesses();
    let params: Params<C> = Params::new(k);
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk, &empty).unwrap();

    let a = F::from(3);
    let b = F::from(5);
    let c = a * b;

    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xC0DE);
    let blake2 = Blake2bWrite::<_, C, Challenge255<C>>::init(Vec::new());
    let mut transcript = CountingTranscript::<_, C>::new(blake2);
    create_proof(
        &params,
        &pk,
        &[MulCircuit::<F>::new(a, b)],
        &[&[&[c]]],
        &mut rng,
        &mut transcript,
    )
    .unwrap();
    println!("transcript op trace: {}", transcript.op_summary());
    let proof = transcript.inner.finalize();

    println!("proof size = {} bytes", proof.len());
    println!(
        "proof size / 32 = {} (count of 32-byte chunks)",
        proof.len() / 32
    );
    println!("proof size mod 32 = {}", proof.len() % 32);

    // For documentation: dump as hex grouped by 32-byte chunks so we can
    // see commits vs scalars.
    for (i, chunk) in proof.chunks(32).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        println!("[{i:3}] {hex}");
    }
}
