# Security claims and threat model

## Layered structure

This crate now ships simulators at three layers, with distinct claims at each:

| Layer | Status | What is simulated | Verifier |
|---|---|---|---|
| Toy IPA + multipoint + gated | done | A re-implementation of Halo 2's bottom layers | This crate's own verifier |
| halo2_proofs single-gate circuit (`MulCircuit`) | done | A real Halo 2 circuit going through `halo2_proofs::create_proof` | `halo2_proofs::plonk::verify_proof` |
| **Real Orchard Action** (`orchard::circuit::Circuit`) | done | The production Zcash shielded-pool Action proof | `orchard::circuit::Proof::verify` and `halo2_proofs::plonk::verify_proof` (ROM-programmable variant) |

The cryptographic claim at each layer is the same: the simulator emits an accepting proof without committing to a witness in advance. The strength of the claim grows with each layer:

- Toy IPA: structural demonstration that the algebraic move (sample everything, solve for one) works.
- `MulCircuit`: same demonstration through real halo2_proofs machinery, with the ROM-programmable transcript shim.
- Real Orchard Action: the simulator drives the production prover (witness-indistinguishable variant), and the ROM-programmable variant drives `halo2_proofs::plonk::create_proof` directly with our shim transcript.

## What this crate is

A **demonstration** of the zero-knowledge simulator for Halo 2-style proofs
(the inner-product argument used by Orchard), with the three protocol roles
expressed as YSAAF-style services:

```text
  Prove    : (Statement, Witness, Transcript, Rng) → Proof
  Verify   : (Statement, Proof, Transcript)        → Result<(), VerifyError>
  Simulate : (Statement, Rng)                      → Simulated<Proof>
```

The simulator is gated behind `feature = "simulator"`. Builds with
`default-features = false` cannot link any `Simulate` impl: calling
`layer.simulate(...)` is then a compile error.

## What it is not

- **Not a production prover.** Several known engineering hazards (timing
  variability in `poly_mul`, non-validated public fields on `Witness`,
  naïve scalar/point arithmetic without batching) make it unsuitable for
  handling real secrets in the toy-layer code paths. The real-Orchard
  path (experiment 6, layer 3) uses the upstream `orchard` and
  `halo2_proofs` crates directly, which are themselves not audited for
  side-channel hardness either.
- **Not the toy-only crate it used to be.** Layer 3 ships
  the **real Orchard Action circuit** via `orchard::circuit::Circuit`,
  including the permutation argument, lookup argument, rotations, and
  the full custom-gate set (Sinsemilla, Poseidon, value-commit). The
  4992-byte proofs are byte-format identical to Zcash v5 transaction
  `Action.zkproof` fields. Layers 1 and 2 (the toy IPA / multipoint /
  gated layer and the `MulCircuit` halo2_proofs layer) remain
  simplified demonstrations of the algebraic core.
- **Not formally verified.** No machine-checked proof of correctness exists.

## Formal claims (informal restatement)

Let `Π = (Prove, Verify, Simulate)` denote any of the protocol layers
(`Ipa`, `Plonkish { m }`, `Gated { gate }`) implemented in this crate. Let
`λ` be the security parameter (≈ 254 bits for the Pasta scalar field).

### Completeness

For every public parameter setup, every statement `stmt` in the language,
and every valid witness `w`:

```text
Verify(params, stmt, Prove(params, stmt, w, T_real, R), T_real) = Ok(())
```

with probability 1, where `T_real` is `RealTranscript` and `R` is any RNG.

**Status in code**: validated by `tests/end_to_end.rs::honest_prove_verify`,
`tests/plonkish_e2e.rs::honest_plonkish`, `tests/gated_e2e.rs::honest_gated_proof_verifies`,
and reinforced with random seeds by `tests/proptest.rs::*_honest_always_verifies`.

### Computational soundness (in the ROM)

For every probabilistic polynomial-time prover `P*` that does not know a
valid witness for `stmt`, the probability that `P*` produces a proof
accepted by `Verify` is negligible in `λ`, assuming the Fiat-Shamir hash
behaves as a random oracle.

**Status in code**: spot-checked against tampering by
`tests/end_to_end.rs::tampered_simulated_proof_fails`,
`tests/gated_e2e.rs::tampered_simulated_gated_proof_fails`,
and by `tests/proptest.rs::tampered_simulator_proof_always_fails`. These
are necessary but **not sufficient** evidence; a full soundness argument is
inherited from the underlying IPA (Bulletproofs / Halo paper) and is not
re-proven here.

### Zero-knowledge in the random-oracle model

For every PPT distinguisher `D`, there exists a simulator `S` such that
for every statement `stmt` in the language:

```text
| Pr[D(Prove(params, stmt, w, T_real, R)) = 1]
  − Pr[D(S(params, stmt, R)) = 1] |  ≤  negl(λ)
```

where, on the simulator side, `D` is permitted to query the random oracle
that `S` programs.

**Status in code**:
- **Existence**: the simulator is implemented (`ipa::simulate`,
  `plonkish::simulate`, `gated::simulate`).
- **Acceptance**: `tests/end_to_end.rs::simulator_verifies_under_programmable_transcript`
  and friends show the simulator's output passes `Verify` when the verifier
  is given the programmed transcript.
- **Failure under a real hash**: `simulator_fails_under_real_transcript`
  confirms the simulator cannot beat Blake2b, which is the ROM assumption
  baseline.
- **Marginal uniformity**: `tests/statistical.rs::*_first_byte_is_uniform`
  runs 1024-sample chi-square goodness-of-fit tests against `χ²(255, 0.00001)`
  on the simulator's `L_i`, final scalars, and opening claims. Necessary
  but not sufficient evidence.
- **Computational indistinguishability of the joint distribution**: not
  tested. This is the remaining gap; an end-to-end statistical test would
  require comparing N honest-prover transcripts against N simulated
  transcripts under the same statement, which is a substantial harness
  and is left as a TODO.

## Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Cross-protocol replay between versions | `WithDomainSeparation` filter; `simulator::*` facades bind a `"orchard-sim/v1/<layer>/<subprotocol>"` label |
| Simulator linked into a production prover binary | Cargo feature `simulator` (default-on for dev, opt-out via `default-features = false`); `Simulate` impls are `#[cfg(feature = "simulator")]` |
| Accidental witness construction with zero blinder | Use `Witness::honest()` or `Witness::random()` constructors; field access remains `pub` for now (planned: private fields) |
| Tampered proof | Verifier returns `VerifyError::{IpaFinalCheck, GateEquation, …}`; never silently accepts. Real-Orchard path: `orchard::circuit::Proof::verify` rejects any single-byte perturbation, exercised by `orchard_action_tampered_proof_rejected` and by the web demo's tamper buttons (head / middle / tail) |

### Out of scope

| Threat | Why out of scope |
|---|---|
| Timing/cache side-channels in the prover | Demo crate: `poly_mul` short-circuits on zero, `Scalar` ops are not constant-time-audited |
| Bit-flipping a `Witness` field | Trusted local construction; callers are assumed to use the provided constructors |
| RNG quality | Caller provides the RNG; no entropy enforcement |
| Cryptographic agility (curve replacement) | Hard-wired to `pasta_curves::pallas` |
| Multi-party / interactive use | All protocols here are non-interactive over `Transcript` |
| Memory disclosure (heap dumps, swap leaks) | `MulCircuit` witness wraps in `ZeroizingMulWitness` with a `compiler_fence(SeqCst)` on drop. Other layers use standard Rust `Vec`s with no `zeroize` |
| Concurrent prover access | Not thread-safe; layers are zero-sized and stateless but transcripts/RNGs are not `Send + Sync` by default |

## What would close the remaining gaps

1. **Joint-distribution statistical test**: compare N honest vs. N simulated
   transcripts on the same statement under per-byte distribution metrics
   (Earth Mover's, KS test, mutual information). Closes Muthu #2 fully.
2. **Constant-time guarantees**: replace `poly_mul`'s data-dependent zero
   short-circuit, audit scalar/point arithmetic for non-CT primitives, add
   `subtle::ConstantTimeEq` impls. Closes redshift #4.
3. **Private fields + smart constructors**: make `Witness`, `Proof`,
   `Params` non-constructible-with-invalid-data outside the crate. Closes
   redshift #2 / Hartwood #3.
4. **`#![deny(missing_docs)]` at the crate root**: add module-level doc
   coverage to every public item. Closes Hartwood #9.
5. **Cryptographic-correctness lemma**: write out, in a `proofs/` folder,
   the algebraic step-by-step that the IPA simulator's reverse-construction
   yields the same joint distribution as an honest prover. Closes Muthu #1.
6. **Formal verification**: would re-mechanize the security claims in
   Lean/Coq, way beyond the scope of a demo. Not on the roadmap.

## Reporting issues

If you find a soundness or zero-knowledge defect, open an issue with a
minimal reproducer. Do not include a proof of how to exploit it in real
Orchard: this crate is not Orchard.
