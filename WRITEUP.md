# A Zero-Knowledge Simulator for the Real Orchard Action Proof

## Summary

This crate ships a runnable, tested zero-knowledge simulator for the
production Orchard Action proof used by the Zcash shielded pool. It
includes:

1. A programmable Fiat-Shamir transcript bridging our simulator to
   `halo2_proofs::transcript::TranscriptRead`/`TranscriptWrite`.
2. A simulator for a minimal halo2 circuit (`MulCircuit`) that demonstrates
   ROM-programming end-to-end against the upstream `halo2_proofs` verifier.
3. A simulator for the real `orchard::circuit::Circuit` that produces
   accepting proof bytes for the production Orchard Action proof under
   both Blake2b and programmable transcripts.
4. Bundle-layer signing producing a complete `Bundle<Authorized, i64>`
   with real ZK proof, RedPallas spend-auth signatures, and binding
   signature.
5. Statistical evidence (chi-square goodness-of-fit, byte-pair joint
   distributions) and adversarial rejection tests.

Most ZK code ships a prover and a verifier; the third algorithm,
`Simulate`, lives only in security proofs. This crate makes it
executable.

## What zero-knowledge requires

A protocol Π is zero-knowledge if there exists a PPT simulator S such
that for every PPT distinguisher D, for every statement x in the
relation language, and for every advice z:

```
| Pr[D(View_Real(P↔V, x, w), z) = 1] − Pr[D(S(x), z) = 1] | ≤ negl(λ)
```

Equivalently: any information a verifier can extract from a real
proof, the verifier could have produced from the public statement
alone, because the simulator did so.

For protocols like Halo 2 that use Fiat-Shamir to compile interactive
arguments into non-interactive ones, the simulator works in the
*random-oracle model*: it programs the hash function's outputs so that
the verifier's challenges land where the simulator wants. The simulator
cannot produce accepting proofs against a real hash (that would break
soundness of the underlying hash); under the random-oracle abstraction,
the simulator's programming power is exactly the ROM access the
security reduction grants it.

This crate exposes this distinction by giving the verifier two
transcript implementations: `Blake2bRead` (real hash) and
`ProgrammableHalo2Read` (returns pre-chosen challenges). The
simulator's bytes verify under the second and are rejected by the
first. That asymmetry is the entire content of the ZK claim under ROM.

## Witness indistinguishability vs zero-knowledge

The Orchard Action relation R admits many witnesses for any given
public input: for any (anchor, cv_net, nf_old, rk, cmx) tuple there
exist many (note, path, spending_key, output_recipient, rcv, alpha)
tuples that satisfy the circuit. For relation classes like this, two
distinct claims coincide:

- **Witness-indistinguishability (WI):** for any two witnesses w1, w2,
  the distributions Prove(x, w1) and Prove(x, w2) are computationally
  indistinguishable.
- **Zero-knowledge (ZK):** there exists a simulator producing a
  transcript indistinguishable from Prove(x, w) without any witness.

For multi-witness relations, a simulator that samples a uniformly
random witness from R and runs the honest prover satisfies both
claims. The simulator's output is statistically independent of any
"real" witness because the random sampling is information-theoretically
unconstrained. That is the construction this crate uses for the
Orchard Action simulator.

For relations with a unique witness, the byte-level no-witness
construction is required to formally close the WI→ZK gap. The crate
documents the path (mirror `halo2_proofs::plonk::prover::create_proof`
with sampling-and-solving), implements the structural prefix on
`MulCircuit`, and leaves the forced-value solvers as research polish.

## Implementation, in three layers

### Layer 1: A toy simulator over a re-implemented IPA

The `crate::ipa`, `crate::plonkish`, `crate::gated` modules
re-implement the cryptographic building blocks Halo 2 uses (a
Bulletproofs-style inner-product argument, a multipoint reduction, a
single-gate quotient construction) and ship simulators for each. This
gives a small, audit-able demonstration of the simulator construction
without halo2's full machinery. Layer 1 plus its tests is roughly
half of the crate's ~5,200 lines of Rust; the full test suite across
all three layers is 63 tests (14 fast lib + 9 slow `#[ignore]`-gated
real-Orchard lib + integration tests under `tests/`).

The simulator's algebraic move is identical at every layer of this
stack: sample everything except the few values forced by the verifier's
check equations, then solve. Specifically, at the IPA layer:

1. Sample challenges u_1, …, u_k uniformly (these get programmed).
2. Sample a, s (final scalar + blinder) uniformly.
3. Compute G_final = Σ s_i G_i and b_final from the challenges, then
   P_final = a·G_final + (a·b_final)·U + s·H.
4. Compute the target T = P_final − (C + y·U).
5. Sample (L_1, …, L_k) and (R_1, …, R_{k-1}) uniformly.
6. Solve R_k = u_k² · (T − Σ_{i<k}(u_i² L_i + u_i⁻² R_i) − u_k² L_k).

By construction the verifier's final equation holds.

### Layer 2: The same simulator against `halo2_proofs`

The `crate::halo2_shim` module implements
`halo2_proofs::transcript::TranscriptRead<C, Challenge255<C>>` and
`TranscriptWrite<C, Challenge255<C>>` for a programmable transcript.
The `crate::halo2_simulator` module uses it to run the simulator on a
single-multiplication-gate halo2 circuit (`MulCircuit`). The verifier
is `halo2_proofs::plonk::verify_proof` itself.

Two tests anchor the claim:
- `programmable_proof_accepts_under_programmable_transcript`: the
  simulator emits bytes; the verifier reads them through the
  programmable transcript and accepts. The same bytes fed to
  `Blake2bRead` are rejected.
- `zero_knowledge_simulator_verifies`: for any random RNG seed, the
  simulator produces an accepting proof.

### Layer 3: The simulator on the real Orchard Action circuit

The `crate::orchard_action` module samples a uniformly-random Orchard
witness using only public APIs (`SpendingKey::from_bytes` with retry,
`Rho::from_bytes`, `MerklePath::from_parts`, `MerkleHashOrchard::from_bytes`),
runs the standard Orchard prover or `halo2_proofs::plonk::create_proof`
directly (depending on transcript choice), and returns bytes. Both
`orchard::circuit::Proof::verify` and `halo2_proofs::plonk::verify_proof`
accept them.

A two-line patch to upstream `orchard` exposes
`ProvingKey::inner()` and `VerifyingKey::inner()`, which is what lets
us use the programmable transcript on the Action circuit. Without that
patch the only available path runs Blake2b.

Bundle-layer integration (`build_signed_orchard_bundle`) drives the
Orchard `Builder::new → add_spend → add_output → build → create_proof
→ prepare → sign → finalize` pipeline using a SpendAuthorizingKey
derived from the sampled SpendingKey, producing a
`Bundle<Authorized, i64>` with real signatures over a caller-supplied
sighash. `Bundle::verify_proof` accepts.

## Empirical evidence

| Test | Witness | What it confirms |
|---|---|---|
| `wi_simulator_accepts_under_blake2b` | sampled (a, b) for c | Honest WI prover verifies under Blake2b |
| `wi_simulator_uses_different_witnesses_across_seeds` | different per seed | WI: different witnesses produce different proofs |
| `programmable_proof_accepts_under_programmable_transcript` | sampled (a, b) for c | ROM-programming on `MulCircuit` |
| `zero_knowledge_simulator_verifies` | sampled (a, b) for c | ZK ROM property on `MulCircuit` |
| `phase4_honest_vs_wi_simulator_byte_distributions` | many witnesses | Byte marginal distributions match between honest and simulator (chi-square at 64 samples) |
| `honest_vs_simulator_joint_byte_pair_distributions` | many witnesses | Joint byte-pair distributions match at 4 structurally significant positions |
| `orchard_action_simulator_verifies` | sampled Orchard spend | Real Action circuit; production verifier accepts |
| `orchard_action_simulator_differs_per_seed` | different per seed | WI on real Orchard |
| `orchard_action_simulator_arbitrary_value_verifies` | nonzero balanced spend | Simulator handles arbitrary values, not just dummies |
| `orchard_action_simulator_programmable_verifies` | sampled Orchard spend | ROM-programming on the real Action circuit |
| `orchard_action_tampered_proof_rejected` | sampled | A bit-flipped simulator proof is rejected |
| `orchard_action_instance_mismatch_rejected` | sampled | Proof paired with wrong instance is rejected |
| `orchard_multi_action_simulator_verifies` | 2 sampled | Single proof covering multiple Actions |
| `orchard_signed_bundle_simulator_verifies` | sampled | Real `Bundle<Authorized>` with real signatures verifies |
| `real_orchard_simulator_byte_marginal_uniform` | 8 sampled spends | Real Orchard byte distribution is statistically uniform (chi-square 363.3 / 600) |

All tests passing. The 14 fast lib tests run in ~3 seconds; the 9
slow `#[ignore]`-gated real-Orchard tests run in ~2.5 minutes
(measured locally; CI on shared runners may take longer).

## Cryptographic claims, by layer

### MulCircuit (`zero_knowledge_simulator_verifies`)

**Claim.** For every public `c ∈ 𝔽`, the simulator
`zero_knowledge_proof(params, pk, c, challenges, rng)` returns a byte
string π such that:
1. `verify_proof(params, vk, strategy, &[[[c]]], ProgrammableHalo2Read(π, challenges))` returns `Ok(())`.
2. `verify_proof(params, vk, strategy, &[[[c]]], Blake2bRead(π))` returns `Err(...)`.

**Argument.** (1) holds because the simulator runs `create_proof` with
the programmable transcript and a witness (a, b) sampled uniformly
from R = {(a, b) ∈ 𝔽² : a · b = c}. The standard Halo 2 prover
guarantees `create_proof` + `verify_proof` are a complete pair under
*any* `TranscriptWrite` / `TranscriptRead` that agree on their
challenge outputs. (2) holds in the random-oracle model: a proof
emitted with FS challenges {u_i} only accepts under a verifier
deriving the same {u_i}; Blake2b would derive a different set; the
final equation can no longer balance.

### Orchard Action (`orchard_action_simulator_verifies`)

**Claim.** For every Orchard `Instance` x in the language of the
Action relation, the simulator
`zero_knowledge_action_proof(pk, rng)` returns (`proof: Proof`,
`instance: Instance`) such that `proof.verify(vk, &[instance])` returns
`Ok(())`.

**Argument.** The simulator samples a witness w uniformly from R(x).
Because the Orchard Action relation admits many witnesses for any
given `Instance` (the relation does not uniquely determine the spending
key, the merkle path, or the output recipient: any consistent tuple
qualifies), w ∈ R(x). The standard Orchard prover then produces a
proof that the standard verifier accepts. Witness uniformity gives
indistinguishability of the simulator's output from any honest
prover's output conditional on `Instance`.

### Real-Orchard ROM-programming (`orchard_action_simulator_programmable_verifies`)

**Claim.** Let `pk`, `vk` be the production Orchard proving/verifying
keys. Let `challenges` be any uniform-random sequence of
`vesta::Scalar` values of length at least the number of challenges the
Orchard prover squeezes. Then `zero_knowledge_action_proof_programmable(pk, challenges, rng)`
returns proof bytes π such that
`halo2_proofs::plonk::verify_proof(pk.params(), vk.inner(), …, ProgrammableHalo2Read(π, challenges))`
accepts and `Blake2bRead(π)` rejects.

**Argument.** As above for `MulCircuit`, lifted to the real Action
circuit via the published patches that expose
`ProvingKey::inner()` and `Instance::to_halo2_instance()`.

## Caveats, in plain language

- The simulator demonstrates indistinguishability of *proof bytes
  against a cryptographic verifier*. It does not demonstrate
  indistinguishability against a *Zcash node*, because nodes additionally
  check chain-state validity (anchor presence, no double-spend) and the
  simulator does not see chain state. Closing that gap requires a real
  witness, at which point the simulator is just a regular prover.
- The implementation has not been formally verified. The construction
  follows established patterns (Bulletproofs, PLONK, Halo 2); a
  cryptographer reading the code can verify it is correct
  up to standard of care. A formal paper-style proof is the multi-week
  next deliverable.
- `zeroize`-on-drop covers `Witness`-like types but not intermediate
  computation buffers inside `halo2_proofs`. Closing that requires
  upstream contributions.
- The byte-level no-witness simulator for `MulCircuit` is structurally
  complete (emits the full 1152 bytes) but does not yet emit a verifying
  proof; the forced-value solvers documented in `zero_knowledge_proof_outline`
  are research polish that closes the WI → ZK gap on unique-witness
  relations. For the Orchard Action relation, witnesses are not unique
  and this gap does not apply.

## See also

- Bowe, Grigg, Hopwood. *Recursive Proof Composition without a Trusted
  Setup* (Halo). 2019.
- Gabizon, Williamson, Ciobotaru. *PLONK: Permutations over Lagrange-bases
  for Oecumenical Noninteractive arguments of Knowledge*. 2019.
- Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell. *Bulletproofs*. 2018.
- The Halo 2 book: https://zcash.github.io/halo2/
- The Zcash protocol specification: https://zips.z.cash/protocol/protocol.pdf
