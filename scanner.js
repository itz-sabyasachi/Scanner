/* =========================================================
   SHIELD VERIFY - PROOF SCANNER
   Camera -> jsQR -> decodeQRPayload -> snarkjs.groth16.verify
   ========================================================= */

const CONFIG = {
  verificationKeyPath: "./zkp/verification_key.json",
  jsQRUrls: [
    "./jsQR.min.js",
    "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js",
    "https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js",
    "https://unpkg.com/jsqr@1.4.0/dist/jsQR.js"
  ],
  qrVersion: 1,            // must match QR_VERSION in the wallet's app.js
  scanEveryNthFrame: 2,
  cooldownMs: 2500,        // ignore the same QR for this long after a scan

  /* Optional: name your public signals in circuit order, e.g.
     ["schemeId","useAge","useIncome", ...]. Empty = "Signal 0..n". */
  signalLabels: ["output 0","output 1","schemeId","useAge","useIncome","useGender","useEducation","useMaritalStatus","useEmploymentStatus","usePensionStatus","useGovernmentEmployee","useIncomeTaxPayer","useDisqualifyingHealthCoverage","ageMin","ageMax","incomeMax","requiredGender","requiredEducationMin","requiredMaritalStatus","requiredEmploymentStatus","requiredPensionStatus","requiredGovernmentEmployee","requiredIncomeTaxPayer","requiredDisqualifyingHealthCoverage"]
};

const $ = (id) => document.getElementById(id);
const el = {
  video: $("video"), canvas: $("canvas"), viewport: $("viewport"),
  status: $("scanStatus"), start: $("startBtn"), stop: $("stopBtn"), flip: $("switchBtn"),
  file: $("fileInput"), manualText: $("manualText"), manualBtn: $("manualBtn"),
  vkPill: $("vkPill"), vkText: $("vkText"),
  empty: $("emptyState"), result: $("result"), badge: $("badge"),
  eyebrow: $("resEyebrow"), title: $("resTitle"), text: $("resText"),
  facts: $("facts"), sigCount: $("sigCount"), sigList: $("sigList"),
  again: $("againBtn"), copy: $("copyBtn"), histList: $("histList"), clear: $("clearBtn")
};

const ctx = el.canvas.getContext("2d", { willReadFrequently: true });
const state = {
  decoding: false, stream: null, facing: "environment", raf: 0, frame: 0, busy: false,
  vk: null, jsQR: null, lastText: "", lastAt: 0,
  seen: new Map(), history: [], lastReport: null
};

/* ---------- helpers ---------- */
function setStatus(msg, kind = "") {
  el.status.textContent = msg;
  el.status.className = "status " + kind;
}
function flash(kind) {
  el.viewport.classList.remove("ok", "bad");
  el.viewport.classList.add(kind);
  setTimeout(() => el.viewport.classList.remove(kind), 1400);
}
function loadScript(src) {
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src; s.onload = res; s.onerror = () => rej(new Error("load failed: " + src));
    document.head.appendChild(s);
  });
}
async function sha256Short(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}
const isDec = (v) => typeof v === "string" && /^[0-9]+$/.test(v);

/* ---------- init: verification key + jsQR ---------- */
async function loadVK() {
  try {
    const r = await fetch(CONFIG.verificationKeyPath);
    if (!r.ok) throw new Error("HTTP " + r.status);
    state.vk = await r.json();
    el.vkPill.className = "vk-pill ok";
    el.vkText.textContent = `Key loaded · ${state.vk.nPublic} public signals`;
  } catch (e) {
    el.vkPill.className = "vk-pill err";
    el.vkText.textContent = "Key not loaded";
    setStatus("Could not load verification key. Serve this folder over http(s), not file://", "bad");
    console.error(e);
  }
}
let detector = null;      // native BarcodeDetector (no library needed)
async function loadJsQR() {
  // 1) native engine (Chrome, Edge, Android, recent Safari)
  if (!detector && "BarcodeDetector" in window) {
    try {
      const f = await BarcodeDetector.getSupportedFormats();
      if (f.includes("qr_code")) detector = new BarcodeDetector({ formats: ["qr_code"] });
    } catch (e) { console.warn("BarcodeDetector unavailable:", e.message); }
  }
  // 2) jsQR (local file, then CDNs)
  if (!state.jsQR) {
    if (typeof window.jsQR !== "function") {
      for (const url of CONFIG.jsQRUrls) {
        try { await loadScript(url); if (typeof window.jsQR === "function") break; }
        catch (e) { console.warn(e.message); }
      }
    }
    if (typeof window.jsQR === "function") state.jsQR = window.jsQR;
  }
  if (!detector && !state.jsQR)
    throw new Error("No QR decoder available. Put jsQR.min.js next to index.html (https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js) or check your internet.");
}

/* decode whatever is currently drawn on the canvas -> string | null */
async function decodeCanvas(attemptBoth) {
  if (detector) {
    try {
      const codes = await detector.detect(el.canvas);
      if (codes.length && codes[0].rawValue) return codes[0].rawValue;
    } catch (e) { console.warn("detector error:", e.message); }
  }
  if (state.jsQR) {
    const img = ctx.getImageData(0, 0, el.canvas.width, el.canvas.height);
    const c = state.jsQR(img.data, img.width, img.height,
      { inversionAttempts: attemptBoth ? "attemptBoth" : "dontInvert" });
    if (c && c.data) return c.data;
  }
  return null;
}

/* ---------- payload decode (mirror of the wallet's decodeQRPayload) ---------- */
function decodeQRPayload(text) {
  let d;
  try { d = JSON.parse(text); } catch { throw new Error("QR is not a ShieldVerify proof (not JSON)."); }
  if (!d || d.v !== CONFIG.qrVersion) throw new Error("Unsupported proof version.");
  const okPt = (p) => Array.isArray(p) && p.length === 2 && p.every(isDec);
  const okG2 = (p) => Array.isArray(p) && p.length === 2 && p.every(okPt);
  if (!okPt(d.a) || !okG2(d.b) || !okPt(d.c)) throw new Error("Malformed proof points.");
  if (!Array.isArray(d.n) || !d.n.every(isDec)) throw new Error("Malformed public signals.");
  return {
    schemeId: d.s,
    publicSignals: d.n,
    proof: {
      pi_a: [...d.a, "1"], pi_b: [...d.b, ["1", "0"]], pi_c: [...d.c, "1"],
      protocol: "groth16", curve: "bn128"
    }
  };
}

/* ---------- verification ---------- */
async function verifyText(text, source) {
  if (state.busy) return;
  state.busy = true;
  setStatus("QR detected — verifying proof…", "busy");
  const t0 = performance.now();
  let report;
  try {
    if (!state.vk) await loadVK();
    if (!state.vk) throw new Error("Verification key unavailable.");
    if (!window.snarkjs) throw new Error("snarkjs is not loaded.");

    const { proof, publicSignals, schemeId } = decodeQRPayload(text);
    if (publicSignals.length !== state.vk.nPublic)
      throw Object.assign(new Error(`Expected ${state.vk.nPublic} public signals, got ${publicSignals.length}. Wrong circuit or key.`), { kind: "bad" });

    const valid = await window.snarkjs.groth16.verify(state.vk, publicSignals, proof);
    const id = await sha256Short(text);
    const dup = state.seen.get(id);
    state.seen.set(id, (dup || 0) + 1);

    report = {
      status: valid ? (dup ? "REPLAY" : "VERIFIED") : "INVALID",
      valid, schemeId, publicSignals, proof, receipt: id,
      ms: Math.round(performance.now() - t0), at: new Date().toISOString(), source, seenBefore: !!dup
    };
  } catch (e) {
    report = { status: "ERROR", valid: false, error: e.message, ms: Math.round(performance.now() - t0), at: new Date().toISOString(), source };
  }
  state.busy = false;
  showReport(report);
}

/* ---------- UI: result ---------- */
function showReport(r) {
  state.lastReport = r;
  el.empty.classList.add("hidden");
  el.result.classList.remove("hidden", "bad", "warn");

  const M = {
    VERIFIED: ["✓", "PROOF VERIFIED", "Valid proof",
      "The Groth16 proof is mathematically valid for the public signals shown. The holder meets the scheme criteria without revealing their data.", "ok"],
    REPLAY: ["!", "ALREADY SCANNED", "Valid, but seen before",
      "The proof verifies, but this exact QR was already scanned in this session. Treat it as a possible replay.", "warn"],
    INVALID: ["✕", "PROOF INVALID", "Verification failed",
      "The proof does not verify against the verification key. It may be forged, corrupted, or from a different circuit.", "bad"],
    ERROR: ["✕", "CANNOT VERIFY", "Unreadable proof", r.error || "Unknown error.", "bad"]
  }[r.status];

  el.badge.textContent = M[0]; el.eyebrow.textContent = M[1];
  el.title.textContent = M[2]; el.text.textContent = M[3];
  if (M[4] !== "ok") el.result.classList.add(M[4]);

  const facts = [];
  if (r.schemeId !== undefined) facts.push(["Scheme ID", String(r.schemeId)]);
  if (r.receipt) facts.push(["Receipt", r.receipt]);
  const sg = r.publicSignals || [];
  if (sg.length === 24) {
    facts.push(["Age range", sg[3] === "1" ? `${sg[13]} – ${sg[14]} years` : "not checked"]);
    facts.push(["Income cap", sg[4] === "1" ? "≤ ₹" + Number(sg[15]).toLocaleString("en-IN") : "not checked"]);
  }
  facts.push(["Checked in", r.ms + " ms"], ["Time", new Date(r.at).toLocaleTimeString()]);
  el.facts.innerHTML = facts.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("");

  const sig = r.publicSignals || [];
  el.sigCount.textContent = sig.length;
  el.sigList.innerHTML = sig.map((s, i) =>
    `<li><b>${CONFIG.signalLabels[i] || "signal " + i}</b>${s}</li>`).join("");

  flash(M[4] === "bad" ? "bad" : "ok");
  setStatus(M[2], M[4] === "ok" ? "ok" : M[4] === "bad" ? "bad" : "");
  addHistory(r, M);
  if (navigator.vibrate) navigator.vibrate(M[4] === "ok" ? 60 : [80, 60, 80]);
}

function addHistory(r, M) {
  state.history.unshift({ r, M });
  renderHistory();
}
function renderHistory() {
  if (!state.history.length) { el.histList.innerHTML = '<li class="muted">No scans yet.</li>'; return; }
  el.histList.innerHTML = state.history.slice(0, 30).map(({ r, M }) =>
    `<li><span class="tag ${M[4]}">${r.status}</span>
     <span>${r.schemeId !== undefined ? "Scheme " + r.schemeId : (r.error || "")}</span>
     <span class="hist-meta">${r.receipt ? r.receipt.slice(0, 8) + " · " : ""}${new Date(r.at).toLocaleTimeString()}</span></li>`).join("");
}

/* ---------- camera loop ---------- */
async function startCamera() {
  try {
    setStatus("Starting camera…", "busy");
    stopCamera(true);
    // ask for the camera first (keeps the user-gesture context, needed on Safari)
    state.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: state.facing } }, audio: false
    });
    try { await loadJsQR(); }
    catch (e) { stopCamera(true); throw e; }
    el.video.srcObject = state.stream;
    await el.video.play();
    el.viewport.classList.add("live");
    el.start.hidden = true; el.stop.hidden = false; el.flip.hidden = false;
    setStatus("Scanning… hold the QR inside the frame");
    state.frame = 0;
    state.raf = requestAnimationFrame(tick);
  } catch (e) {
    console.error(e);
    let msg;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia)
      msg = "Camera unavailable: open this page via https:// or http://localhost (not file:// or a plain-http IP).";
    else if (e.name === "NotAllowedError") msg = "Camera permission denied. Allow it in the browser's site settings, or upload an image.";
    else if (e.name === "NotFoundError") msg = "No camera found on this device. Use Upload image instead.";
    else if (e.name === "NotReadableError") msg = "Camera is in use by another app/tab. Close it and retry.";
    else msg = "Camera error: " + e.message;
    setStatus(msg, "bad");
  }
}
function stopCamera(silent) {
  cancelAnimationFrame(state.raf);
  if (state.stream) state.stream.getTracks().forEach((t) => t.stop());
  state.stream = null; el.video.srcObject = null;
  el.viewport.classList.remove("live");
  el.start.hidden = false; el.stop.hidden = true; el.flip.hidden = true;
  if (!silent) setStatus("Camera stopped");
}
async function tick() {
  state.raf = requestAnimationFrame(tick);
  if (state.busy || state.decoding || el.video.readyState < 2) return;
  if (++state.frame % CONFIG.scanEveryNthFrame) return;

  const vw = el.video.videoWidth, vh = el.video.videoHeight;
  if (!vw) return;
  state.decoding = true;
  try {
    const scale = Math.min(1, 800 / Math.max(vw, vh));
    el.canvas.width = Math.round(vw * scale); el.canvas.height = Math.round(vh * scale);
    ctx.drawImage(el.video, 0, 0, el.canvas.width, el.canvas.height);
    const text = await decodeCanvas(false);
    if (!text) return;
    const now = Date.now();
    if (text === state.lastText && now - state.lastAt < CONFIG.cooldownMs) return;
    state.lastText = text; state.lastAt = now;
    verifyText(text, "camera");
  } finally { state.decoding = false; }
}

/* ---------- image upload ---------- */
async function scanFile(file) {
  if (!file) return;
  try {
    setStatus("Reading image…", "busy");
    await loadJsQR();
    const url = URL.createObjectURL(file);
    const img = new Image();
    await new Promise((res, rej) => { img.onload = res; img.onerror = () => rej(new Error("not a valid image")); img.src = url; });
    // try a few sizes: big photos / tiny screenshots both decode better after rescaling
    let text = null;
    for (const max of [1600, 1000, 600]) {
      const s = Math.min(1, max / Math.max(img.naturalWidth, img.naturalHeight));
      el.canvas.width = Math.max(1, Math.round(img.naturalWidth * s));
      el.canvas.height = Math.max(1, Math.round(img.naturalHeight * s));
      ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, el.canvas.width, el.canvas.height);
      ctx.drawImage(img, 0, 0, el.canvas.width, el.canvas.height);
      text = await decodeCanvas(true);
      if (text) break;
    }
    URL.revokeObjectURL(url);
    if (!text) return setStatus("No QR code found in that image. Try a sharper or larger one.", "bad");
    verifyText(text, "image");
  } catch (e) { console.error(e); setStatus("Could not read image: " + e.message, "bad"); }
}

/* ---------- events ---------- */
el.start.onclick = startCamera;
el.stop.onclick = () => stopCamera();
el.flip.onclick = () => { state.facing = state.facing === "environment" ? "user" : "environment"; startCamera(); };
el.file.onchange = (e) => { scanFile(e.target.files[0]); e.target.value = ""; };
el.manualBtn.onclick = () => { const t = el.manualText.value.trim(); if (t) verifyText(t, "manual"); };
el.again.onclick = () => {
  el.result.classList.add("hidden"); el.empty.classList.remove("hidden");
  state.lastText = ""; setStatus(state.stream ? "Scanning…" : "Ready to scan");
  if (!state.stream) startCamera();
};
el.copy.onclick = async () => {
  if (!state.lastReport) return;
  const { proof, ...rest } = state.lastReport;
  try { await navigator.clipboard.writeText(JSON.stringify(rest, null, 2)); el.copy.textContent = "Copied ✓"; }
  catch { el.copy.textContent = "Copy failed"; }
  setTimeout(() => (el.copy.textContent = "Copy JSON"), 1500);
};
el.clear.onclick = () => { state.history = []; state.seen.clear(); renderHistory(); };
document.addEventListener("visibilitychange", () => { if (document.hidden && state.stream) stopCamera(); });

(async () => {
  await loadVK();
  try { await loadJsQR(); } catch (e) { console.warn(e.message); }
  const d = document.getElementById("diag");
  if (!d) return;
  const engines = [detector && "native", state.jsQR && "jsQR"].filter(Boolean);
  d.textContent = engines.length ? "Decoder: " + engines.join(" + ")
    : "Decoder: NONE — place jsQR.min.js next to index.html";
  if (!engines.length) d.style.color = "#c62828";
})();
window.ShieldVerifyScanner = { verifyText, decodeQRPayload };
