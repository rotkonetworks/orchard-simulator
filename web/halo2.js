// halo2.js — drives the halo2 demo page.
//
// All halo2_proofs work runs on a Web Worker so the main thread stays
// responsive. The worker calls `halo2_keygen` once (cached) then
// `halo2_demo` per click; the live progress bar updates while the
// worker is busy.

const el = (id) => document.getElementById(id);

const els = {
  run:           el('halo2-run'),
  status:        el('halo2-status'),
  cSeed:         el('halo2-c-seed'),
  wSeed:         el('halo2-w-seed'),
  output:        el('halo2-output'),
  progress:      el('halo2-progress'),
  progressPhase: el('halo2-progress-phase'),
  progressTime:  el('halo2-progress-time'),

  honestVerdict:  el('halo2-honest-verdict'),
  honestHeadline: el('halo2-honest-headline'),
  honestSub:      el('halo2-honest-sub'),
  honestHead:     el('halo2-honest-head'),
  honestTail:     el('halo2-honest-tail'),

  wiVerdict:  el('halo2-wi-verdict'),
  wiHeadline: el('halo2-wi-headline'),
  wiSub:      el('halo2-wi-sub'),
  wiHead:     el('halo2-wi-head'),
  wiTail:     el('halo2-wi-tail'),

  zkVerdict:  el('halo2-zk-verdict'),
  zkHeadline: el('halo2-zk-headline'),
  zkSub:      el('halo2-zk-sub'),
  zkHead:     el('halo2-zk-head'),
  zkTail:     el('halo2-zk-tail'),

  challengesCard: el('halo2-challenges-card'),
};

// ---------- progress ----------

let progressTimer = null;
let progressT0 = 0;

function startProgress(label) {
  progressT0 = performance.now();
  els.progress.hidden = false;
  els.progressPhase.textContent = label;
  els.progressTime.textContent = '0.0 s';
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    const t = (performance.now() - progressT0) / 1000;
    els.progressTime.textContent = `${t.toFixed(2)} s`;
  }, 50);
}

function stopProgress() {
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
  els.progress.hidden = true;
}

function setStatus(text, kind) {
  els.status.textContent = text;
  els.status.className = kind ? `run-status ${kind}` : 'run-status';
}

function setVerdict(tile, ok) {
  tile.classList.remove('accept', 'reject');
  tile.classList.add(ok ? 'accept' : 'reject');
}

// ---------- URL hash seeds ----------

function readHashSeeds() {
  const p = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const c = parseInt(p.get('halo2-c'), 10);
  const w = parseInt(p.get('halo2-w'), 10);
  return {
    c: Number.isFinite(c) && c >= 0 && c <= 0xFFFFFFFF ? c : null,
    w: Number.isFinite(w) && w >= 0 && w <= 0xFFFFFFFF ? w : null,
  };
}

function writeHashSeeds(c, w) {
  const p = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  p.set('halo2-c', String(c));
  p.set('halo2-w', String(w));
  history.replaceState(null, '', `#${p.toString()}`);
}

// ---------- worker ----------

let worker = null;
let keygenDone = false;
let pendingRun = null;

function ensureWorker() {
  if (worker) return worker;
  worker = new Worker('halo2-worker.js', { type: 'module' });
  worker.onmessage = onMessage;
  worker.onerror = (e) => {
    stopProgress();
    setStatus(`worker error: ${e.message || e}`, 'error');
    els.run.disabled = false;
  };
  worker.postMessage({ type: 'init' });
  return worker;
}

function onMessage(e) {
  const m = e.data;
  switch (m.type) {
    case 'inited':
      setStatus('WASM ready. Click Run.', 'ok');
      els.run.disabled = false;
      // Auto-run if URL hash carries seeds.
      const seeds = readHashSeeds();
      if (seeds.c !== null && seeds.w !== null) {
        els.cSeed.value = String(seeds.c);
        els.wSeed.value = String(seeds.w);
        run();
      }
      return;
    case 'keygen-done':
      keygenDone = true;
      // Keygen completed; chain into the demo run we deferred.
      if (pendingRun) {
        const { cSeed, wSeed } = pendingRun;
        pendingRun = null;
        startProgress('three create_proof calls running in worker');
        worker.postMessage({ type: 'demo', cSeed, wSeed });
      } else {
        stopProgress();
        setStatus(`keygen done in ${m.elapsedMs} ms.`, 'ok');
      }
      return;
    case 'phase':
      els.progressPhase.textContent = m.label;
      return;
    case 'demo-done':
      stopProgress();
      render(m.result);
      setStatus(
        `three proofs in ${m.result.elapsed_ms} ms (worker wall ${m.elapsedMs} ms). c=${m.result.c_hex.slice(0, 12)}…`,
        'ok',
      );
      els.run.disabled = false;
      return;
    case 'error':
      stopProgress();
      setStatus(`worker error: ${m.message}`, 'error');
      els.run.disabled = false;
      return;
  }
}

// ---------- run ----------

function run() {
  ensureWorker();
  const cSeed = (parseInt(els.cSeed.value, 10) || 0) >>> 0;
  const wSeed = (parseInt(els.wSeed.value, 10) || 0) >>> 0;
  writeHashSeeds(cSeed, wSeed);
  els.run.disabled = true;

  if (!keygenDone) {
    pendingRun = { cSeed, wSeed };
    startProgress('building MulCircuit ProvingKey');
    worker.postMessage({ type: 'keygen' });
  } else {
    startProgress('three create_proof calls running in worker');
    worker.postMessage({ type: 'demo', cSeed, wSeed });
  }
}

function render(r) {
  els.output.hidden = false;

  setVerdict(els.honestVerdict, r.honest.verified_blake2b);
  els.honestHeadline.textContent = r.honest.verified_blake2b
    ? 'Blake2b verifier accepted the honest proof.'
    : 'Blake2b verifier rejected the honest proof.';
  els.honestSub.textContent = `${r.honest.bytes_len} bytes.`;
  els.honestHead.textContent = r.honest.head_hex;
  els.honestTail.textContent = r.honest.tail_hex;

  setVerdict(els.wiVerdict, r.wi_simulator.verified_blake2b);
  els.wiHeadline.textContent = r.wi_simulator.verified_blake2b
    ? 'Blake2b verifier accepted the WI simulator proof.'
    : 'Blake2b verifier rejected the WI simulator proof.';
  els.wiSub.textContent = `${r.wi_simulator.bytes_len} bytes. Same Blake2b verifier as the honest run, with a different sampled witness.`;
  els.wiHead.textContent = r.wi_simulator.head_hex;
  els.wiTail.textContent = r.wi_simulator.tail_hex;

  const zk = r.zk_simulator;
  const zkPattern = zk.verified_programmable && !zk.verified_blake2b;
  setVerdict(els.zkVerdict, zkPattern);
  els.zkHeadline.textContent = zkPattern
    ? 'ZK simulator: programmable verifier accepted, Blake2b rejected (as required).'
    : `ZK simulator did not match the expected pattern (Blake2b=${zk.verified_blake2b}, programmable=${zk.verified_programmable}).`;
  els.zkSub.textContent = `${zk.bytes_len} bytes. Acceptance under the programmable transcript is the ZK claim in the ROM.`;
  els.zkHead.textContent = zk.head_hex;
  els.zkTail.textContent = zk.tail_hex;

  els.challengesCard.innerHTML = r.programmed_challenges_hex.map((hex, i) => `
    <div class="hex-field">
      <span class="hex-field-name">u<sub>${i}</sub></span>
      <span class="hex-field-value"><code>${hex}</code></span>
      <span></span>
    </div>`).join('');
}

// ---------- copy delegation ----------

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy-target]');
  if (!btn) return;
  const node = document.getElementById(btn.getAttribute('data-copy-target'));
  if (!node || !node.textContent) return;
  const text = node.textContent.trim();
  const flash = () => {
    const orig = btn.dataset.label || btn.textContent;
    if (!btn.dataset.label) btn.dataset.label = orig;
    btn.textContent = '✓ copied';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = btn.dataset.label;
      btn.classList.remove('copied');
    }, 1500);
  };
  try { await navigator.clipboard.writeText(text); flash(); }
  catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'absolute'; ta.style.left = '-9999px';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); flash(); } catch (_) {}
    document.body.removeChild(ta);
  }
});

// ---------- boot ----------

els.run?.addEventListener('click', run);
ensureWorker();
