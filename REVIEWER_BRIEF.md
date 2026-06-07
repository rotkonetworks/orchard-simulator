# Reviewer brief: orchard-simulator

You have halo2 fluency. I want a 30-minute thumbs-up/thumbs-down on the
cryptographic claim below before this is posted to the Zcash forums.

## The claim

This crate ships a working `Simulate` algorithm for two zero-knowledge
relations:

1. The toy multiplication-gate relation `R_mul = { ((a, b), c) : a · b = c }`,
   run through `halo2_proofs 0.3.2` on the Pasta `vesta::Affine` proving
   curve at `K=4`.
2. The production Orchard Action relation, run through `orchard 0.14.0`
   (post-NU6.2) + `halo2_gadgets 0.5.0` at the production `K=11`,
   driving `orchard::circuit::Proof::create` and `Proof::verify` directly.

The simulator on both relations is the **ROM-programmable**
construction:

- Sample a uniform witness `w' ←R R(stmt)` internally.
- Pick Fiat-Shamir challenges `(u_1, …, u_k) ←R F^k` in advance.
- Drive `halo2_proofs::plonk::create_proof` with the
  `ProgrammableHalo2Write` transcript shim
  (`src/halo2_shim.rs`), which writes proof bytes normally but
  consults the pre-chosen challenge queue instead of hashing the
  transcript so far.
- Output the resulting bytes.

The output verifies under the matching `ProgrammableHalo2Read`
transcript and is rejected by `Blake2bRead` (the real protocol's RO).

## The argument I want audited

For a multi-witness relation `R` with `|R(stmt)| ≥ 2^λ` (security
parameter `λ`), I claim the construction above is a strict
zero-knowledge simulator in the random-oracle model. The argument:

1. **Commitment hiding.** All Pasta-Pedersen polynomial commitments in
   the proof use uniform fresh blinders. Each is perfectly hiding, so
   the commitment bytes carry zero information about which witness was
   sampled.
2. **Transcript programmability.** Under the programmable transcript
   shim, every Fiat-Shamir challenge is drawn from the pre-supplied
   queue, never hashed from witness-dependent prior writes. So no
   verifier-derivable randomness depends on `w'`.
3. **Witness-marginal uniformity.** Sampling `w' ←R R(stmt)` makes
   the simulator's witness marginal conditional on `stmt` equal to the
   uniform distribution over `R(stmt)`. The honest prover with a fixed
   real witness `w_0` is, conditional on `stmt`, the point distribution
   `{w_0}` — but because the proof bytes after step (1) and (2) are
   independent of `w'` modulo statement, the *transcript* distribution
   is identical to the simulator's. Equivalently: WI on `R` collapses
   to ZK via the multi-witness sampling argument
   ([Feige-Shamir 1990]).

Composed, `Simulate(stmt) ≈_c Prove(stmt, w_0)` as transcript
distributions, in the random-oracle model. That is the textbook ZK
property.

The construction does NOT work in the standard model (real Blake2b);
that's why `Blake2bRead` rejects the simulator's bytes. Soundness of
the real protocol is therefore preserved — a malicious prover cannot
program Blake2b's output.

## Specifically, the questions

1. **Is (1) really perfectly hiding for halo2's commitments?** halo2's
   Pasta-Pedersen commitments use a blinding factor sampled by the
   `create_proof` RNG. I claim this gives perfect hiding for the
   commitment opening at a single point but only *computational* hiding
   for the full polynomial. For the ZK argument I need
   indistinguishability of the *transcript* — i.e. of finitely many
   evaluations at adversarially-influenced points. Is that enough? Is
   there a published-paper hiding statement I should cite directly?

2. **Is (2) clean for `ProgrammableHalo2Write`?** The shim is in
   `src/halo2_shim.rs:1-361`. It implements the same
   `TranscriptWrite` interface `Blake2bWrite` does, but
   `squeeze_challenge` and `common_*` calls feed the pre-supplied queue
   and ignore writes. I want a second pair of eyes on whether there's
   any side channel where the prover's commitment value re-enters the
   challenge derivation despite the shim.

3. **Is (3) the right witness-marginal argument for Orchard?** Orchard
   Action witnesses are `(SpendingKey, Note, MerklePath, OutputNote,
   α, rcv)` with the on-chain constraints in §4.18.4 of the spec.
   The witness set per public Instance is enormous (any matching FVK,
   any consistent (ρ, ψ, cm) tuple, any α uniformly sampled from the
   scalar field, etc.). I claim `|R(stmt)| ≥ 2^λ` for any
   meaningful `λ`. Is there a more careful statement of the lower
   bound on witness-set size I should make?

4. **Is the WI-to-ZK reduction tight, or is there a hidden gap?**
   Specifically, the reduction
   `WI + multi-witness uniformity → ZK` is folklore; is there a
   recent paper that states it formally for IPA-based PLONKish proof
   systems specifically? Or do I need to write a tighter argument?

## Where to look

The code (~3000 lines of Rust) is small enough to read in a sitting:

```
src/halo2_circuit.rs       # MulCircuit, K=4, single multiplication gate
src/halo2_shim.rs          # ProgrammableHalo2Write/Read transcript shim
src/halo2_simulator.rs     # WI + programmable simulator on MulCircuit
src/orchard_action.rs      # WI + programmable simulator on production Orchard
tests/                     # Statistical / chi-square tests on simulator output
```

The two functions that realize the strict ROM-ZK simulator:

- `halo2_simulator::programmable_proof` (MulCircuit, ~25 LOC)
- `orchard_action::zero_knowledge_action_proof_programmable`
  (Orchard, ~30 LOC, drives the same construction on production keys)

The matching test cases that show the byte-level acceptance pattern
(accepts under matching programmable transcript; rejects under
Blake2b):

- `halo2_simulator::tests::programmable_proof_accepts_under_programmable_transcript`
- `orchard_action::tests::orchard_action_simulator_programmable_verifies`
  (under `#[ignore]`; ~3 minutes wall-clock).

The website at <https://orchard.rotko.net> walks the construction
end-to-end with browser-side WASM runs and a fixed-seed reproducibility
panel.

## What I'm NOT asking

- Soundness of halo2 itself. I'm relying on the published IPA soundness
  argument under the discrete-log assumption on Pasta.
- Production readiness. This crate is a demonstrator, not a wallet.
- The byte-level no-witness construction for unique-witness relations.
  Neither MulCircuit nor Orchard has a unique witness; the multi-witness
  sampling argument covers both. The byte-level path is sketched in the
  Foundations page but not implemented and is not needed here.

## References

- [Feige, Shamir 1990]. *Witness Indistinguishable and Witness Hiding
  Protocols.* The original WI definition; section 4 contains the
  uniform-witness collapse argument I invoke.
- [Halo paper, Bowe-Grigg-Hopwood 2019] eprint 2019/1021. The Halo 2
  proving system.
- Zcash protocol specification, §4.18.4 ("Action Statement (Orchard)")
  for the Orchard relation.
- Halo 2 book, §5.4.10.3 (concrete instantiation).

## Bottom line

If the three steps above hold for the Orchard relation specifically,
this crate is a working strict ROM-ZK simulator on the production
Zcash Orchard Action proof. A counterexample to any of them, or a
gap I haven't seen, kills the headline claim. Either way I'd like to
know before posting.

Reach me at `tommi@rotko.net` or open an issue at
<https://github.com/rotkonetworks/orchard-simulator/issues>.
