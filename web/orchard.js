// orchard.js — Orchard page controller.
//
// Drives the production Orchard simulator off a Web Worker. The
// worker selection (single-threaded vs parallel-rayon) is decided
// at boot based on `crossOriginIsolated` and whether the
// `pkg-parallel/` directory was produced by `build-wasm-parallel.sh`.
//
// Message protocol matches `orchard-worker.js` / `orchard-worker-parallel.js`.

// ---------- element lookup ----------

const els = {
  run:           el('orchard-run'),
  runBatch:      el('orchard-run-batch'),
  status:        el('orchard-status'),
  output:        el('orchard-output'),
  verdict:       el('orchard-verdict'),
  headline:      el('orchard-headline'),
  sub:           el('orchard-sub'),
  progress:      el('orchard-progress'),
  progressPhase: el('orch-progress-phase'),
  progressTime:  el('orch-progress-time'),

  tamperHead:    el('orch-tamper-head'),
  tamperMid:     el('orch-tamper-mid'),
  tamperTail:    el('orch-tamper-tail'),
  tamperResult:  el('orch-tamper-result'),
  tamperHeadline:el('orch-tamper-headline'),
  tamperSub:     el('orch-tamper-sub'),

  batchOutput:   el('orchard-batch-output'),
  batchGrid:     el('orch-batch-grid'),

  twoRun:        el('orch-two-proofs-run'),
  twoOutput:     el('orch-two-proofs-output'),
  twoVerdict:    el('orch-two-proofs-verdict'),
  twoHeadline:   el('orch-two-proofs-headline'),
  twoSub:        el('orch-two-proofs-sub'),
  twoStats:      el('orch-two-proofs-stats'),
  twoAHex:       el('orch-two-proofs-a-hex'),
  twoBHex:       el('orch-two-proofs-b-hex'),
  twoXorHex:     el('orch-two-proofs-xor-hex'),

  bundleRun:     el('orch-bundle-run'),
  bundleOutput:  el('orch-bundle-output'),
  bundleVerdict: el('orch-bundle-verdict'),
  bundleHeadline:el('orch-bundle-headline'),
  bundleSub:     el('orch-bundle-sub'),
  bundleActions: el('orch-bundle-actions'),

  downloadProof: el('orch-download-proof'),
  downloadStatus:el('orch-download-status'),
  externalHex:   el('orch-external-hex'),
  externalRun:   el('orch-external-verify-run'),
  externalPaste: el('orch-external-paste-last'),
  externalResult:el('orch-external-result'),
  externalHeadline: el('orch-external-headline'),
  externalSub:   el('orch-external-sub'),

  loadFullProof: el('orch-proof-load-full'),
  fullProofPre:  el('orch-proof-full'),
};

function el(id) { return document.getElementById(id); }

// ---------- worker selection ----------

let workerKind = null;
let orchardWorker = null;
let orchardKeygenDone = false;
let pendingAfterKeygen = null;
let pendingSingleSeed = 0;
let pendingTwoSeed = 0;
let pendingBundleSeed = 0;
let pendingBundleNumOutputs = 1;

async function chooseWorkerKind() {
  if (workerKind !== null) return workerKind;
  const isolated = self.crossOriginIsolated === true
    && typeof SharedArrayBuffer !== 'undefined';
  if (!isolated) { workerKind = 'single'; return workerKind; }
  try {
    const head = await fetch('pkg-parallel/orchard_simulator.js', { method: 'HEAD' });
    workerKind = head.ok ? 'parallel' : 'single';
  } catch (_) {
    workerKind = 'single';
  }
  return workerKind;
}

function ensureWorker() {
  if (orchardWorker) return orchardWorker;
  const url = workerKind === 'parallel' ? 'orchard-worker-parallel.js' : 'orchard-worker.js';
  try {
    orchardWorker = new Worker(url, { type: 'module' });
  } catch (e) {
    setStatus(`worker create failed: ${e.message || e}`, 'error');
    return null;
  }
  orchardWorker.onmessage = onMessage;
  orchardWorker.onerror = (e) => {
    stopProgress();
    setStatus(`worker error: ${e.message || e}`, 'error');
    enableRunButtons(true);
  };
  orchardWorker.postMessage({ type: 'init' });
  return orchardWorker;
}

// ---------- progress bar ----------

let progressT0 = 0;
let progressTimer = null;

function startProgress(phaseLabel) {
  progressT0 = performance.now();
  els.progress.hidden = false;
  els.progressPhase.textContent = phaseLabel;
  els.progressTime.textContent = '0.0 s';
  if (progressTimer) clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    const t = (performance.now() - progressT0) / 1000;
    els.progressTime.textContent = `${t.toFixed(1)} s`;
  }, 100);
}

function stopProgress() {
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
  els.progress.hidden = true;
}

// ---------- stats ----------

const stats = { proofsGenerated: 0, verifiesRun: 0, tampersRejected: 0, proveTimeMs: 0 };

function setText(id, v) {
  const node = document.getElementById(id);
  if (node) node.textContent = v;
}

function updateStats() {
  const strip = document.getElementById('orchard-stats');
  if (strip && strip.hidden) strip.hidden = false;
  setText('stat-proofs-generated', stats.proofsGenerated.toLocaleString('en-US'));
  setText('stat-verifies-run',     stats.verifiesRun.toLocaleString('en-US'));
  setText('stat-tampers-rejected', stats.tampersRejected.toLocaleString('en-US'));
  const t = stats.proveTimeMs;
  setText('stat-prove-time', t < 10000 ? `${t.toLocaleString('en-US')} ms` : `${(t/1000).toFixed(1)} s`);
}

function resetSession() {
  stats.proofsGenerated = stats.verifiesRun = stats.tampersRejected = stats.proveTimeMs = 0;
  updateStats();
  for (const id of ['orchard-output', 'orchard-batch-output',
                    'orch-two-proofs-output', 'orch-bundle-output',
                    'orch-tamper-result', 'orch-external-result']) {
    const n = document.getElementById(id);
    if (n) n.hidden = true;
  }
  lastDemo = null;
  lastSeed = null;
  history.replaceState(null, '', window.location.pathname + window.location.search);
  setStatus('session reset; click Run', '');
}

// ---------- status helpers ----------

function setStatus(text, kind) {
  if (!els.status) return;
  els.status.textContent = text;
  els.status.className = kind ? `run-status ${kind}` : 'run-status';
}

function enableRunButtons(enabled) {
  for (const b of [els.run, els.runBatch, els.twoRun, els.bundleRun, els.externalRun, els.externalPaste]) {
    if (b) b.disabled = !enabled;
  }
}

function enableTamperButtons(enabled) {
  for (const b of [els.tamperHead, els.tamperMid, els.tamperTail]) {
    if (b) b.disabled = !enabled;
  }
}

// ---------- seed sharing ----------

let lastSeed = null;
let lastDemo = null;

function randomSeed() {
  return Math.floor(Math.random() * 0xFFFFFFFF) >>> 0;
}

function readSeedFromHash() {
  const p = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const raw = p.get('orch-seed');
  if (raw === null) return null;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0 || n > 0xFFFFFFFF) return null;
  return n >>> 0;
}

function writeSeedToHash(seed) {
  const p = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  p.set('orch-seed', String(seed));
  history.replaceState(null, '', `#${p.toString()}`);
}

// ---------- flow diagram lighting ----------

function lightStages(stages, klass) {
  for (const s of stages) {
    const node = document.querySelector(`.flow-stage[data-stage="${s}"]`);
    if (!node) continue;
    node.classList.remove('active', 'done');
    node.classList.add(klass);
  }
}

function markStagesDone(stages, ms) {
  for (const s of stages) {
    const node = document.querySelector(`.flow-stage[data-stage="${s}"]`);
    if (!node) continue;
    node.classList.remove('active');
    node.classList.add('done');
    const t = node.querySelector('.flow-stage-timing');
    if (t) t.textContent = `${ms.toLocaleString('en-US')} ms`;
  }
}

function clearStages() {
  document.querySelectorAll('.flow-stage').forEach(n => {
    n.classList.remove('active', 'done');
  });
  document.querySelectorAll('.flow-stage-timing').forEach(n => {
    n.textContent = '';
  });
}

// ---------- worker message router ----------

function onMessage(e) {
  const m = e.data;
  switch (m.type) {
    case 'inited':
      setStatus(m.parallel
        ? `parallel WASM ready (rayon, ${m.threads} threads). click Run.`
        : 'WASM ready (single-threaded). click Run.', 'ok');
      enableRunButtons(true);
      if (els.downloadProof) els.downloadProof.disabled = true;
      return;
    case 'keygen-progress':
      return;
    case 'keygen-done':
      orchardKeygenDone = true;
      if (pendingAfterKeygen === 'batch') {
        pendingAfterKeygen = null;
        startBatchRun();
      } else if (pendingAfterKeygen === 'two-proofs') {
        pendingAfterKeygen = null;
        startProgress(`two proofs same witness (seed=${pendingTwoSeed})`);
        orchardWorker.postMessage({ type: 'two-proofs', seed: pendingTwoSeed });
      } else if (pendingAfterKeygen === 'signed-bundle') {
        pendingAfterKeygen = null;
        startProgress(`build + sign Bundle<Authorized> (seed=${pendingBundleSeed}, outputs=${pendingBundleNumOutputs})`);
        orchardWorker.postMessage({ type: 'signed-bundle', seed: pendingBundleSeed, numOutputs: pendingBundleNumOutputs });
      } else if (pendingAfterKeygen === 'single') {
        pendingAfterKeygen = null;
        startProgress(`create_proof + verify_proof (seed=${pendingSingleSeed})`);
        orchardWorker.postMessage({ type: 'prove', seed: pendingSingleSeed });
      }
      return;
    case 'stage-start':
      if (els.progressPhase) els.progressPhase.textContent = `stage ${m.stages.join('+')}: ${m.label}`;
      lightStages(m.stages, 'active');
      return;
    case 'stage-done':
      markStagesDone(m.stages, m.elapsedMs);
      return;
    case 'prove-done':
      stopProgress();
      renderDemo(m.demo, m.elapsedMs);
      enableRunButtons(true);
      return;
    case 'batch-item-progress':
      startProgress(`seed ${m.index + 1}/${m.total} (${m.seed}): create_proof + verify_proof`);
      markBatchPending(m.index, m.seed);
      clearStages();
      return;
    case 'batch-item-done':
      renderBatchCard(m.index, m.seed, m.demo, m.elapsedMs);
      return;
    case 'batch-done':
      stopProgress();
      enableRunButtons(true);
      setStatus(`batch of ${m.total} complete`, 'ok');
      return;
    case 'tamper-done':
      renderTamper(m.result);
      enableRunButtons(true);
      return;
    case 'two-proofs-done':
      stopProgress();
      renderTwoProofs(m.result);
      enableRunButtons(true);
      return;
    case 'signed-bundle-done':
      stopProgress();
      renderSignedBundle(m.view, m.elapsedMs);
      enableRunButtons(true);
      return;
    case 'verify-external-done':
      renderExternal(m.result);
      enableRunButtons(true);
      return;
    case 'verify-external-error':
      renderExternalError(m.message);
      enableRunButtons(true);
      return;
    case 'full-proof':
      onFullProofReady(m.proof_full_hex);
      return;
    case 'full-proof-error':
      if (els.downloadStatus) els.downloadStatus.textContent = `download failed: ${m.message}`;
      return;
    case 'error':
      stopProgress();
      setStatus(`error: ${m.message}`, 'error');
      enableRunButtons(true);
      return;
  }
}

// ---------- render: single-run demo ----------

function renderDemo(demo, elapsedMs) {
  els.output.hidden = false;
  setVerdict(els.verdict, demo.verified);
  if (demo.verified) {
    els.headline.textContent = "Verifier accepted the simulator's proof.";
    const seedNote = lastSeed !== null
      ? ` Seed ${lastSeed}.`
      : '';
    els.sub.innerHTML = '';
    const span = document.createElement('span');
    span.textContent = `${demo.proof_bytes_len} bytes, prove + verify in ${elapsedMs} ms.` + seedNote;
    els.sub.appendChild(span);
    if (lastSeed !== null) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'copy-btn';
      btn.style.marginLeft = '0.55rem';
      btn.textContent = 'copy share link';
      btn.addEventListener('click', () => copyShareLink(btn));
      els.sub.appendChild(document.createTextNode(' '));
      els.sub.appendChild(btn);
    }
  } else {
    els.headline.textContent = "Verifier rejected the proof.";
    els.sub.textContent = `${elapsedMs} ms elapsed.`;
  }

  if (demo.instance) {
    setText('orch-i-anchor',        demo.instance.anchor);
    setText('orch-i-cv_net_x',      demo.instance.cv_net_x);
    setText('orch-i-cv_net_y',      demo.instance.cv_net_y);
    setText('orch-i-nf_old',        demo.instance.nf_old);
    setText('orch-i-rk',            demo.instance.rk);
    setText('orch-i-cmx',           demo.instance.cmx);
    setText('orch-i-enable-spend',  demo.instance.enable_spend);
    setText('orch-i-enable-output', demo.instance.enable_output);
  }
  if (demo.proof_head_hex) setText('orch-proof-head', demo.proof_head_hex);
  if (demo.proof_tail_hex) setText('orch-proof-tail', demo.proof_tail_hex);

  lastDemo = { demo, elapsedMs };
  if (els.downloadProof) els.downloadProof.disabled = false;
  if (els.loadFullProof) els.loadFullProof.disabled = false;
  enableTamperButtons(true);

  stats.proofsGenerated += 1;
  stats.verifiesRun     += 1;
  stats.proveTimeMs     += Number(demo.prove_ms) || 0;
  updateStats();
}

function setVerdict(tile, ok) {
  if (!tile) return;
  tile.classList.remove('accept', 'reject');
  tile.classList.add(ok ? 'accept' : 'reject');
}

// ---------- render: tamper ----------

function renderTamper(r) {
  els.tamperResult.hidden = false;
  const sound = !r.verified;
  setVerdict(els.tamperResult, sound);
  if (sound) {
    els.tamperHeadline.textContent = 'Verifier rejected the tampered proof.';
    els.tamperSub.textContent =
      `byte ${r.byte_index}: 0x${r.original_byte_hex} → 0x${r.flipped_byte_hex}. verify_proof returned REJECT in ${r.verify_ms} ms.`;
  } else {
    els.tamperHeadline.textContent = 'Verifier ACCEPTED the tampered proof.';
    els.tamperSub.textContent =
      `byte ${r.byte_index}: 0x${r.original_byte_hex} → 0x${r.flipped_byte_hex}. If there are no bugs, this means the proof system is broken.`;
  }
  stats.verifiesRun += 1;
  if (sound) stats.tampersRejected += 1;
  updateStats();
}

// ---------- render: batch ----------

function startBatchRun() {
  const seeds = [randomSeed(), randomSeed(), randomSeed()];
  els.output.hidden = false;
  clearStages();
  els.batchOutput.hidden = false;
  els.batchGrid.innerHTML = '';
  for (let i = 0; i < seeds.length; i++) {
    const card = document.createElement('div');
    card.className = 'card';
    card.dataset.index = String(i);
    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; font-family: var(--font-mono); font-size: 0.78rem; color: var(--fg-dim); margin-bottom: 0.4rem;">
        <span>seed ${i + 1}/${seeds.length}</span>
        <span style="color: var(--accent); font-weight: 600;">${seeds[i]}</span>
      </div>
      <div class="batch-verdict" style="font-weight: 600; font-size: 1rem; color: var(--warn);">queued…</div>
      <div class="batch-detail" style="font-family: var(--font-mono); font-size: 0.74rem; color: var(--fg-dim); margin-top: 0.3rem;"></div>`;
    els.batchGrid.appendChild(card);
  }
  startProgress(`seed 1/${seeds.length} (${seeds[0]}): create_proof + verify_proof`);
  orchardWorker.postMessage({ type: 'prove-batch', seeds });
}

function markBatchPending(index, seed) {
  const card = els.batchGrid.children[index];
  if (!card) return;
  card.querySelector('.batch-verdict').textContent = 'proving…';
  card.querySelector('.batch-verdict').style.color = 'var(--warn)';
  card.querySelector('.batch-detail').textContent = `seed=${seed}`;
}

function renderBatchCard(index, seed, demo, elapsedMs) {
  const card = els.batchGrid.children[index];
  if (!card) return;
  const ok = demo.verified;
  card.style.borderLeft = `3px solid var(${ok ? '--ok' : '--bad'})`;
  card.querySelector('.batch-verdict').textContent = ok ? '✓ ACCEPT' : '✗ REJECT';
  card.querySelector('.batch-verdict').style.color = `var(${ok ? '--ok' : '--bad'})`;
  card.querySelector('.batch-detail').textContent =
    `${demo.proof_bytes_len} bytes; prove ${demo.prove_ms} ms, verify ${demo.verify_ms} ms; total ${elapsedMs} ms`;
  stats.proofsGenerated += 1;
  stats.verifiesRun     += 1;
  stats.proveTimeMs     += Number(demo.prove_ms) || 0;
  updateStats();
}

// ---------- render: two proofs ----------

function renderTwoProofs(r) {
  els.twoOutput.hidden = false;
  const both = r.verified_a && r.verified_b;
  setVerdict(els.twoVerdict, both);
  if (both) {
    els.twoHeadline.textContent = 'Both proofs verify against the same public Instance.';
    const pct = ((r.bytes_differ / r.proof_bytes_len) * 100).toFixed(1);
    els.twoSub.textContent =
      `${r.bytes_differ.toLocaleString('en-US')} of ${r.proof_bytes_len.toLocaleString('en-US')} bytes differ (${pct}%). The witness is identical; the proof bytes carry no information about it.`;
  } else {
    els.twoHeadline.textContent = `Verification: A=${r.verified_a}, B=${r.verified_b}.`;
    els.twoSub.textContent = 'Expected both to verify; inspect console.';
  }
  const stat = (label, value) => `
    <div class="stat"><span class="stat-label">${label}</span><span class="stat-value">${value}</span></div>`;
  const pct = ((r.bytes_differ / r.proof_bytes_len) * 100).toFixed(1);
  els.twoStats.innerHTML = [
    stat('A verifies', r.verified_a ? '✓' : '✗'),
    stat('B verifies', r.verified_b ? '✓' : '✗'),
    stat('bytes differ', `${r.bytes_differ.toLocaleString('en-US')} / ${r.proof_bytes_len.toLocaleString('en-US')}`),
    stat('% differs', `${pct}%`),
    stat('prove (both)', `${r.prove_ms.toLocaleString('en-US')} ms`),
    stat('verify (both)', `${r.verify_ms.toLocaleString('en-US')} ms`),
  ].join('');
  els.twoAHex.textContent   = r.proof_a_head_hex;
  els.twoBHex.textContent   = r.proof_b_head_hex;
  els.twoXorHex.textContent = r.xor_head_hex;
  stats.proofsGenerated += 2;
  stats.verifiesRun     += 2;
  stats.proveTimeMs     += Number(r.prove_ms) || 0;
  updateStats();
}

// ---------- render: signed bundle ----------

function renderSignedBundle(v, elapsedMs) {
  els.bundleOutput.hidden = false;
  const allSpendAuth = v.actions.every(a => a.spend_auth_sig_verified);
  const ok = v.verified && v.binding_signature_verified && allSpendAuth;
  setVerdict(els.bundleVerdict, ok);
  if (ok) {
    els.bundleHeadline.textContent =
      `Bundle<Authorized, ${v.value_balance.toLocaleString('en-US')}> verifies (proof + binding sig + ${v.num_actions} spend-auth sig).`;
    els.bundleSub.textContent =
      `${v.num_actions} action(s); proof ${v.proof_bytes_len.toLocaleString('en-US')} bytes; binding sig 64 bytes; built + signed + verified in ${elapsedMs.toLocaleString('en-US')} ms.`;
  } else {
    const reasons = [];
    if (!v.verified) reasons.push('proof rejected');
    if (!v.binding_signature_verified) reasons.push('binding signature failed');
    if (!allSpendAuth) reasons.push('spend-auth signature failed');
    els.bundleHeadline.textContent = 'Bundle authorizing-data check failed.';
    els.bundleSub.textContent = reasons.join('; ');
  }
  setText('orch-bundle-flags',           v.flags_bits);
  setText('orch-bundle-spends',          String(v.flags_spends_enabled));
  setText('orch-bundle-outputs-enabled', String(v.flags_outputs_enabled));
  setText('orch-bundle-vbal',            v.value_balance.toLocaleString('en-US'));
  setText('orch-bundle-anchor',          v.anchor_hex);
  setText('orch-bundle-nactions',        String(v.num_actions));
  setText('orch-bundle-proof-len',       `${v.proof_bytes_len.toLocaleString('en-US')}`);
  setText('orch-bundle-binding-sig',     v.binding_signature_hex);
  setText('orch-bundle-sighash',         v.sighash_hex);

  els.bundleActions.innerHTML = v.actions.map((a, i) => {
    const fields = [
      ['nullifier', a.nullifier_hex, `b-a${i}-nf`],
      ['cv_net', a.cv_net_hex, `b-a${i}-cv`],
      ['rk', a.rk_hex, `b-a${i}-rk`],
      ['cmx', a.cmx_hex, `b-a${i}-cmx`],
      ['spend_auth_sig', a.spend_auth_sig_hex, `b-a${i}-sig`],
    ];
    const rows = fields.map(([label, hex, id]) => `
      <div class="hex-field">
        <span class="hex-field-name">${label}</span>
        <span class="hex-field-value"><code id="${id}">${hex}</code></span>
        <button class="copy-btn" data-copy-target="${id}" type="button">copy</button>
      </div>`).join('');
    const sigBadge = a.spend_auth_sig_verified
      ? '<span style="color: var(--ok); font-family: var(--font-mono); font-size: 0.78rem;">✓ spend-auth sig verifies</span>'
      : '<span style="color: var(--bad); font-family: var(--font-mono); font-size: 0.78rem;">✗ spend-auth sig invalid</span>';
    return `
      <div class="card" style="margin: 0.5rem 0;">
        <div style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--accent); margin-bottom: 0.5rem; display: flex; justify-content: space-between;">
          <span>ACTION ${i}</span>${sigBadge}
        </div>
        ${rows}
      </div>`;
  }).join('');
  stats.proofsGenerated += 1;
  stats.verifiesRun     += 1 + v.num_actions;
  stats.proveTimeMs     += Number(v.prove_ms) || 0;
  updateStats();
}

// ---------- render: external verify ----------

function renderExternal(r) {
  els.externalResult.hidden = false;
  setVerdict(els.externalResult, r.verified);
  els.externalHeadline.textContent = r.verified
    ? 'verify_proof accepted'
    : 'verify_proof rejected';
  const cmp = r.matches_cached_proof
    ? 'pasted bytes match the cached proof exactly'
    : `pasted bytes differ from cached in ${r.bytes_differ.toLocaleString('en-US')} positions`;
  els.externalSub.textContent =
    `proof length ${r.proof_bytes_len.toLocaleString('en-US')} B; ${cmp}; verify took ${r.verify_ms.toLocaleString('en-US')} ms`;
  stats.verifiesRun += 1;
  updateStats();
}

function renderExternalError(msg) {
  els.externalResult.hidden = false;
  els.externalResult.classList.remove('accept', 'reject');
  els.externalHeadline.textContent = '⚠ error';
  els.externalSub.textContent = msg;
}

// ---------- download / load full proof ----------

let pendingFullProofConsumer = null;

function downloadProof() {
  if (!lastDemo || !orchardWorker) return;
  if (els.downloadStatus) els.downloadStatus.textContent = 'preparing…';
  pendingFullProofConsumer = (hex) => writeProofJsonDownload(hex);
  orchardWorker.postMessage({ type: 'get-full-proof' });
}

function writeProofJsonDownload(proofFullHex) {
  const { demo, elapsedMs } = lastDemo;
  const payload = {
    schema: 'orchard-simulator/proof/v1',
    generated_at: new Date().toISOString(),
    note: 'A real-Orchard Action proof produced by orchard-simulator. Verify with orchard::circuit::Proof::verify against the production VerifyingKey built by VerifyingKey::build().',
    proof: { bytes_len: demo.proof_bytes_len, bytes_hex: proofFullHex },
    instance: { ...demo.instance },
    verified_locally: demo.verified,
    timings_ms: {
      witness: demo.witness_ms,
      prove: demo.prove_ms,
      verify: demo.verify_ms,
      total: elapsedMs,
    },
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const a = document.createElement('a');
  a.href = url;
  a.download = `orchard-simulator-proof-${ts}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 0);
  if (els.downloadStatus) els.downloadStatus.textContent = `saved ${a.download} (~${Math.round(blob.size / 1024)} KB)`;
}

function loadFullProofIntoPanel() {
  if (!orchardWorker) return;
  pendingFullProofConsumer = (hex) => {
    if (els.fullProofPre) els.fullProofPre.textContent = hex;
    if (els.loadFullProof) {
      els.loadFullProof.textContent = '✓ loaded';
      setTimeout(() => { if (els.loadFullProof) els.loadFullProof.textContent = 'reload full hex'; }, 1500);
    }
  };
  orchardWorker.postMessage({ type: 'get-full-proof' });
}

function onFullProofReady(hex) {
  const c = pendingFullProofConsumer;
  pendingFullProofConsumer = null;
  if (c) c(hex);
}

// ---------- external verify ----------

function verifyExternal() {
  if (!orchardWorker || !els.externalHex) return;
  const raw = els.externalHex.value.trim();
  if (!raw) { renderExternalError('paste hex or downloaded JSON first'); return; }
  let hex;
  if (raw.startsWith('{')) {
    try {
      const obj = JSON.parse(raw);
      const c = obj?.proof?.bytes_hex;
      if (typeof c !== 'string') { renderExternalError('JSON parsed, but no proof.bytes_hex string found'); return; }
      hex = c.replace(/\s+/g, '').toLowerCase();
    } catch (err) { renderExternalError(`could not parse JSON: ${err.message}`); return; }
  } else {
    hex = raw.replace(/\s+/g, '').toLowerCase();
  }
  if (!/^[0-9a-f]+$/.test(hex)) { renderExternalError('extracted hex must contain 0-9, a-f only'); return; }
  if (els.externalRun) els.externalRun.disabled = true;
  orchardWorker.postMessage({ type: 'verify-external', hex });
}

function pasteLastProof() {
  if (!orchardWorker) return;
  pendingFullProofConsumer = (hex) => {
    if (els.externalHex) els.externalHex.value = hex;
  };
  orchardWorker.postMessage({ type: 'get-full-proof' });
}

// ---------- copy-to-clipboard delegation ----------

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy-target]');
  if (!btn) return;
  const targetId = btn.getAttribute('data-copy-target');
  const node = document.getElementById(targetId);
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

// ---------- share link ----------

async function copyShareLink(btn) {
  if (lastSeed === null) return;
  const url = new URL(window.location.href);
  const p = new URLSearchParams(url.hash.replace(/^#/, ''));
  p.set('orch-seed', String(lastSeed));
  url.hash = p.toString();
  const text = url.toString();
  try { await navigator.clipboard.writeText(text); }
  catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'absolute'; ta.style.left = '-9999px';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (_) {}
    document.body.removeChild(ta);
  }
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = '✓ link copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1500);
  }
}

// ---------- run buttons ----------

function resetOutput() {
  els.output.hidden = false;
  if (els.verdict) {
    els.verdict.classList.remove('accept', 'reject');
    els.headline.textContent = 'running…';
    els.sub.textContent = '';
  }
  clearStages();
  if (els.tamperResult) els.tamperResult.hidden = true;
  for (const id of ['orch-t-witness', 'orch-t-prove', 'orch-t-verify', 'orch-t-total',
                    'orch-i-anchor', 'orch-i-cv_net_x', 'orch-i-cv_net_y',
                    'orch-i-nf_old', 'orch-i-rk', 'orch-i-cmx',
                    'orch-i-enable-spend', 'orch-i-enable-output',
                    'orch-proof-head', 'orch-proof-tail']) {
    const n = document.getElementById(id);
    if (n) n.textContent = '-';
  }
}

function runOnce() {
  if (!els.run) return;
  enableRunButtons(false);
  resetOutput();
  const w = ensureWorker();
  if (!w) { enableRunButtons(true); return; }
  const seed = readSeedFromHash() ?? randomSeed();
  lastSeed = seed;
  writeSeedToHash(seed);
  if (!orchardKeygenDone) {
    pendingAfterKeygen = 'single';
    pendingSingleSeed = seed;
    startProgress('building Orchard ProvingKey + VerifyingKey');
    w.postMessage({ type: 'keygen' });
  } else {
    startProgress(`create_proof + verify_proof (seed=${seed})`);
    w.postMessage({ type: 'prove', seed });
  }
}

function runBatch() {
  if (!els.runBatch) return;
  enableRunButtons(false);
  const w = ensureWorker();
  if (!w) { enableRunButtons(true); return; }
  clearStages();
  if (!orchardKeygenDone) {
    pendingAfterKeygen = 'batch';
    startProgress('building Orchard ProvingKey + VerifyingKey');
    w.postMessage({ type: 'keygen' });
  } else {
    startBatchRun();
  }
}

function runTwoProofs() {
  if (!els.twoRun) return;
  enableRunButtons(false);
  const w = ensureWorker();
  if (!w) { enableRunButtons(true); return; }
  const seed = randomSeed();
  clearStages();
  if (!orchardKeygenDone) {
    pendingAfterKeygen = 'two-proofs';
    pendingTwoSeed = seed;
    startProgress('building Orchard ProvingKey + VerifyingKey');
    w.postMessage({ type: 'keygen' });
  } else {
    startProgress(`two proofs same witness (seed=${seed})`);
    w.postMessage({ type: 'two-proofs', seed });
  }
}

function runSignedBundle() {
  if (!els.bundleRun) return;
  enableRunButtons(false);
  const w = ensureWorker();
  if (!w) { enableRunButtons(true); return; }
  const seed = randomSeed();
  const numOutputs = (() => {
    const input = document.getElementById('orch-bundle-outputs');
    const n = input ? parseInt(input.value, 10) : 1;
    return Number.isFinite(n) ? Math.max(1, Math.min(8, n)) : 1;
  })();
  clearStages();
  if (!orchardKeygenDone) {
    pendingAfterKeygen = 'signed-bundle';
    pendingBundleSeed = seed;
    pendingBundleNumOutputs = numOutputs;
    startProgress('building Orchard ProvingKey + VerifyingKey');
    w.postMessage({ type: 'keygen' });
  } else {
    startProgress(`build + sign Bundle<Authorized> (seed=${seed}, outputs=${numOutputs})`);
    w.postMessage({ type: 'signed-bundle', seed, numOutputs });
  }
}

function tamperByte(index) {
  if (!orchardWorker) return;
  enableRunButtons(false);
  orchardWorker.postMessage({ type: 'tamper', byteIndex: index, xorMask: 0x01 });
}

// ---------- wiring ----------

els.run?.addEventListener('click', runOnce);
els.runBatch?.addEventListener('click', runBatch);
els.twoRun?.addEventListener('click', runTwoProofs);
els.bundleRun?.addEventListener('click', runSignedBundle);
els.tamperHead?.addEventListener('click', () => tamperByte(0));
els.tamperMid?.addEventListener('click', () => tamperByte(2496));
els.tamperTail?.addEventListener('click', () => tamperByte(4991));
els.downloadProof?.addEventListener('click', downloadProof);
els.loadFullProof?.addEventListener('click', loadFullProofIntoPanel);
els.externalRun?.addEventListener('click', verifyExternal);
els.externalPaste?.addEventListener('click', pasteLastProof);
document.getElementById('stats-reset')?.addEventListener('click', resetSession);

// Boot the worker eagerly.
(async () => {
  await chooseWorkerKind();
  ensureWorker();
  if (readSeedFromHash() !== null) {
    // Auto-run after worker init.
    const tryAuto = () => {
      if (els.run?.disabled) { setTimeout(tryAuto, 200); return; }
      runOnce();
    };
    setTimeout(tryAuto, 300);
  }
})();
