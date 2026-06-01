//! Command-line driver for the real-Orchard zero-knowledge simulator.
//!
//! Builds a `ProvingKey` and `VerifyingKey`, samples a uniformly-random
//! Orchard witness from the given seed, drives the production prover
//! to emit a proof, runs the production verifier, and prints a
//! self-describing JSON record to stdout.
//!
//! The JSON shape is the same one the web demo's "Download proof as
//! JSON" button produces, so a CLI-generated proof and a browser-
//! generated proof can be diffed structurally and pasted into either
//! environment for verification.
//!
//! Usage:
//!     cargo run --features orchard --bin orchard-cli -- --seed 42
//!     cargo run --features orchard --bin orchard-cli -- --seed 42 --pretty
//!     cargo run --features orchard --bin orchard-cli -- --help

#![cfg(feature = "orchard")]

use std::env;
use std::process::ExitCode;
use std::time::Instant;

use ff::PrimeField;
use orchard::circuit::{Proof, ProvingKey, VerifyingKey};
use orchard_simulator::orchard_action::build_dummy_action;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut seed: u64 = 0;
    let mut pretty = false;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            "--pretty" => {
                pretty = true;
                i += 1;
            }
            "--seed" | "-s" => {
                if i + 1 >= args.len() {
                    eprintln!("--seed needs a value");
                    return ExitCode::from(2);
                }
                match args[i + 1].parse::<u64>() {
                    Ok(n) => seed = n,
                    Err(e) => {
                        eprintln!("invalid --seed: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            _ => {
                eprintln!("unknown argument: {arg}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    eprintln!("orchard-cli: keygen…");
    let t0 = Instant::now();
    let pk = ProvingKey::build();
    let vk = VerifyingKey::build();
    let keygen_ms = t0.elapsed().as_millis();
    eprintln!("orchard-cli: keygen {keygen_ms} ms");

    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    eprintln!("orchard-cli: sampling witness + building circuit…");
    let t0 = Instant::now();
    let (circuit, instance) = match build_dummy_action(&mut rng) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("build_dummy_action failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let witness_ms = t0.elapsed().as_millis();

    eprintln!("orchard-cli: Proof::create…");
    let t0 = Instant::now();
    let proof = match Proof::create(&pk, &[circuit], std::slice::from_ref(&instance), &mut rng) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Proof::create failed");
            return ExitCode::FAILURE;
        }
    };
    let prove_ms = t0.elapsed().as_millis();

    eprintln!("orchard-cli: Proof::verify…");
    let t0 = Instant::now();
    let verified = proof
        .verify(&vk, std::slice::from_ref(&instance))
        .is_ok();
    let verify_ms = t0.elapsed().as_millis();

    let proof_bytes = proof.as_ref();
    eprintln!(
        "orchard-cli: verified={verified}, prove {prove_ms} ms, verify {verify_ms} ms, {} bytes",
        proof_bytes.len()
    );

    let json = build_json(
        seed,
        verified,
        proof_bytes,
        &instance,
        witness_ms,
        prove_ms,
        verify_ms,
        keygen_ms,
        pretty,
    );
    println!("{json}");

    if verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_usage() {
    eprintln!(
        "usage: orchard-cli [--seed N] [--pretty]\n\
         \n\
         options:\n\
         \x20\x20-s, --seed N     ChaCha20 seed for the witness sample (default 0)\n\
         \x20\x20    --pretty     pretty-print the JSON output\n\
         \x20\x20-h, --help       show this message\n\
         \n\
         emits a JSON record matching the schema the web demo's\n\
         \"Download proof as JSON\" button produces."
    );
}

#[allow(clippy::too_many_arguments)]
fn build_json(
    seed: u64,
    verified: bool,
    proof_bytes: &[u8],
    instance: &orchard::circuit::Instance,
    witness_ms: u128,
    prove_ms: u128,
    verify_ms: u128,
    keygen_ms: u128,
    pretty: bool,
) -> String {
    use ff::Field;

    let cols = instance.to_halo2_instance();
    let row = &cols[0];
    let hex = |s: &pasta_curves::vesta::Scalar| -> String {
        s.to_repr()
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    };
    let bytes_hex: String = proof_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let enable_spend = !bool::from(<pasta_curves::vesta::Scalar as Field>::is_zero(&row[7]));
    let enable_output = !bool::from(<pasta_curves::vesta::Scalar as Field>::is_zero(&row[8]));

    let payload = serde_json::json!({
        "schema": "orchard-simulator/proof/v1",
        "source": "orchard-cli",
        "seed": seed,
        "note":
            "A real-Orchard Action proof produced by the orchard-simulator CLI. \
             Verify with orchard::circuit::Proof::verify against the production \
             VerifyingKey built by VerifyingKey::build().",
        "proof": {
            "bytes_len": proof_bytes.len(),
            "bytes_hex": bytes_hex,
        },
        "instance": {
            "anchor":   hex(&row[0]),
            "cv_net_x": hex(&row[1]),
            "cv_net_y": hex(&row[2]),
            "nf_old":   hex(&row[3]),
            "rk":       format!("{}{}", hex(&row[4]), hex(&row[5])),
            "cmx":      hex(&row[6]),
            "enable_spend":  enable_spend,
            "enable_output": enable_output,
        },
        "verified_locally": verified,
        "timings_ms": {
            "keygen":  keygen_ms,
            "witness": witness_ms,
            "prove":   prove_ms,
            "verify":  verify_ms,
        },
    });

    if pretty {
        serde_json::to_string_pretty(&payload).expect("json serialize")
    } else {
        serde_json::to_string(&payload).expect("json serialize")
    }
}
