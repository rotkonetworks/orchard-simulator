// Parallel-WASM variant of the Orchard simulator Web Worker.
//
// Same message protocol as `orchard-worker.js`; differs in two ways:
//   1. Imports the WASM module from `./pkg-parallel/` (built via
//      `build-wasm-parallel.sh` with rayon + `+atomics` target feature).
//   2. Calls `wasm.initThreadPool(navigator.hardwareConcurrency)` after
//      `init()` so halo2's FFT and MSM steps inside `Proof::create`
//      dispatch across a SharedArrayBuffer-backed pool of inner Workers.
//
// Browsers only enable `SharedArrayBuffer` when the page is served in a
// cross-origin isolated context (both `Cross-Origin-Opener-Policy:
// same-origin` and `Cross-Origin-Embedder-Policy: require-corp` set on
// the response). The bundled `web/serve-parallel.py` sets those.

import init, {
  initThreadPool,
  orchard_keygen,
  orchard_sample_and_build,
  orchard_prove,
  orchard_verify_only,
  orchard_tamper_byte_and_verify,
  orchard_two_proofs_same_witness,
  orchard_signed_bundle_demo,
  orchard_last_proof_full_hex,
  orchard_verify_external_against_last_instance,
  run_orchard_programmable_demo,
} from './pkg-parallel/orchard_simulator.js';

let wasmReady = false;
let threadCount = 0;

async function ensureInit() {
  if (!wasmReady) {
    // Cache-buster on the WASM URL; see orchard-worker.js for rationale.
    await init(new URL('./pkg-parallel/orchard_simulator_bg.wasm?v=' + Date.now(), import.meta.url));
    const n = (self.navigator && self.navigator.hardwareConcurrency) || 4;
    threadCount = Math.max(2, n);
    await initThreadPool(threadCount);
    wasmReady = true;
  }
}

self.onmessage = async (e) => {
  const { type, seed } = e.data || {};
  try {
    if (type === 'init') {
      await ensureInit();
      self.postMessage({ type: 'inited', parallel: true, threads: threadCount });
      return;
    }

    if (type === 'keygen') {
      await ensureInit();
      self.postMessage({
        type: 'keygen-progress',
        phase: `building Orchard ProvingKey + VerifyingKey (rayon, ${threadCount} threads)`,
        t0: performance.now(),
      });
      const t0 = performance.now();
      orchard_keygen();
      const elapsedMs = Math.round(performance.now() - t0);
      self.postMessage({ type: 'keygen-done', elapsedMs });
      return;
    }

    if (type === 'prove') {
      await ensureInit();
      const seedBig = BigInt(seed >>> 0);
      const tStart = performance.now();

      self.postMessage({
        type: 'stage-start', stages: [1, 2],
        label: 'sample witness + build Circuit',
      });
      const sample = orchard_sample_and_build(seedBig);
      self.postMessage({
        type: 'stage-done', stages: [1, 2],
        elapsedMs: sample.witness_ms,
      });

      self.postMessage({
        type: 'stage-start', stages: [3],
        label: `create_proof (rayon, ${threadCount} threads)`,
      });
      const prove = orchard_prove(seedBig);
      self.postMessage({
        type: 'stage-done', stages: [3],
        elapsedMs: prove.prove_ms,
      });

      self.postMessage({
        type: 'stage-start', stages: [4],
        label: 'verify_proof',
      });
      const demo = orchard_verify_only(sample.witness_ms, prove.prove_ms);
      self.postMessage({
        type: 'stage-done', stages: [4],
        elapsedMs: demo.verify_ms,
      });

      const elapsedMs = Math.round(performance.now() - tStart);
      self.postMessage({ type: 'prove-done', demo, elapsedMs });
      return;
    }

    if (type === 'prove-batch') {
      await ensureInit();
      const seeds = (e.data.seeds || []).map(s => BigInt(Number(s) >>> 0));
      for (let i = 0; i < seeds.length; i++) {
        self.postMessage({
          type: 'batch-item-progress',
          index: i,
          total: seeds.length,
          seed: Number(seeds[i]),
        });
        const t0 = performance.now();

        self.postMessage({
          type: 'stage-start', stages: [1, 2],
          label: `seed ${i + 1}/${seeds.length}: sample witness + build Circuit`,
        });
        const sample = orchard_sample_and_build(seeds[i]);
        self.postMessage({
          type: 'stage-done', stages: [1, 2],
          elapsedMs: sample.witness_ms,
        });

        self.postMessage({
          type: 'stage-start', stages: [3],
          label: `seed ${i + 1}/${seeds.length}: create_proof`,
        });
        const prove = orchard_prove(seeds[i]);
        self.postMessage({
          type: 'stage-done', stages: [3],
          elapsedMs: prove.prove_ms,
        });

        self.postMessage({
          type: 'stage-start', stages: [4],
          label: `seed ${i + 1}/${seeds.length}: verify_proof`,
        });
        const demo = orchard_verify_only(sample.witness_ms, prove.prove_ms);
        self.postMessage({
          type: 'stage-done', stages: [4],
          elapsedMs: demo.verify_ms,
        });

        const elapsedMs = Math.round(performance.now() - t0);
        self.postMessage({
          type: 'batch-item-done',
          index: i,
          total: seeds.length,
          seed: Number(seeds[i]),
          demo,
          elapsedMs,
        });
      }
      self.postMessage({ type: 'batch-done', total: seeds.length });
      return;
    }

    if (type === 'tamper') {
      await ensureInit();
      const { byteIndex, xorMask } = e.data;
      const result = orchard_tamper_byte_and_verify(byteIndex >>> 0, xorMask & 0xff);
      self.postMessage({ type: 'tamper-done', result });
      return;
    }

    if (type === 'verify-external') {
      await ensureInit();
      try {
        const result = orchard_verify_external_against_last_instance(String(e.data.hex || ''));
        self.postMessage({ type: 'verify-external-done', result });
      } catch (err) {
        self.postMessage({ type: 'verify-external-error', message: String(err.message || err) });
      }
      return;
    }

    if (type === 'get-full-proof') {
      await ensureInit();
      try {
        const proof_full_hex = orchard_last_proof_full_hex();
        self.postMessage({ type: 'full-proof', proof_full_hex });
      } catch (err) {
        self.postMessage({ type: 'full-proof-error', message: String(err.message || err) });
      }
      return;
    }

    if (type === 'signed-bundle') {
      await ensureInit();
      const seed = Number(e.data.seed) >>> 0;
      const numOutputs = Math.max(1, Math.min(8, Number(e.data.numOutputs) || 1));
      self.postMessage({
        type: 'stage-start', stages: [1, 2, 3, 4],
        label: `build → prove → sign → verify (Bundle<Authorized>, ${numOutputs} outputs)`,
      });
      const t0 = performance.now();
      const view = orchard_signed_bundle_demo(seed, numOutputs);
      const elapsedMs = Math.round(performance.now() - t0);
      self.postMessage({ type: 'stage-done', stages: [1, 2, 3, 4], elapsedMs });
      self.postMessage({ type: 'signed-bundle-done', view, elapsedMs });
      return;
    }

    if (type === 'two-proofs') {
      await ensureInit();
      const seedBig = BigInt(Number(e.data.seed) >>> 0);
      self.postMessage({
        type: 'stage-start', stages: [3],
        label: `two independent create_proof calls (rayon, ${threadCount} threads)`,
      });
      const result = orchard_two_proofs_same_witness(seedBig);
      self.postMessage({
        type: 'stage-done', stages: [3],
        elapsedMs: result.prove_ms,
      });
      self.postMessage({ type: 'two-proofs-done', result });
      return;
    }

    if (type === 'programmable-demo') {
      await ensureInit();
      const seedBig = BigInt(Number(e.data.seed) >>> 0);
      self.postMessage({
        type: 'stage-start', stages: [3],
        label: `strict ROM-programmable simulator (rayon, ${threadCount} threads)`,
      });
      const result = run_orchard_programmable_demo(seedBig);
      self.postMessage({
        type: 'stage-done', stages: [3],
        elapsedMs: result.prove_ms,
      });
      self.postMessage({ type: 'programmable-demo-done', result });
      return;
    }

    self.postMessage({ type: 'error', message: `unknown message type: ${type}` });
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err && err.message ? err.message : err) });
  }
};
