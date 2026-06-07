// halo2-worker.js — runs the halo2 demo off the main thread so the
// UI stays responsive while the three proofs are being produced.
//
// Protocol:
//   main → worker: {type:'init'}            → {type:'inited'}
//   main → worker: {type:'keygen'}          → {type:'keygen-done', elapsedMs}
//   main → worker: {type:'demo', cSeed, wSeed}
//     → {type:'phase', label, n, of}
//     → {type:'demo-done', result, elapsedMs}

import init, { halo2_keygen, halo2_demo } from './pkg/orchard_simulator.js';

let wasmReady = false;

async function ensureInit() {
  if (!wasmReady) {
    // Cache-buster: see orchard-worker.js. Avoids the case where a
    // browser cached a prior `orchard_simulator_bg.wasm` under the old
    // immutable header and uses it forever.
    await init(new URL('./pkg/orchard_simulator_bg.wasm?v=' + Date.now(), import.meta.url));
    wasmReady = true;
  }
}

self.onmessage = async (e) => {
  const { type } = e.data || {};
  try {
    if (type === 'init') {
      await ensureInit();
      self.postMessage({ type: 'inited' });
      return;
    }

    if (type === 'keygen') {
      await ensureInit();
      const t0 = performance.now();
      halo2_keygen();
      self.postMessage({ type: 'keygen-done', elapsedMs: Math.round(performance.now() - t0) });
      return;
    }

    if (type === 'demo') {
      await ensureInit();
      const cSeed = e.data.cSeed >>> 0;
      const wSeed = e.data.wSeed >>> 0;
      // halo2_demo runs three create_proof calls back-to-back inside
      // wasm. We can't interleave progress events around the
      // individual create_proof calls without splitting the wasm
      // entry point, but emitting a single "in flight" event before
      // and after at least confirms to main that the worker is
      // alive and busy.
      self.postMessage({ type: 'phase', label: 'create_proof × 3 (honest + WI + ZK)' });
      const t0 = performance.now();
      const result = halo2_demo(cSeed, wSeed);
      const elapsedMs = Math.round(performance.now() - t0);
      self.postMessage({ type: 'demo-done', result, elapsedMs });
      return;
    }

    self.postMessage({ type: 'error', message: `unknown type ${type}` });
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err && err.message ? err.message : err) });
  }
};
