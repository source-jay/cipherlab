/* CipherLab — DSA module
 * The Web Crypto API does not implement DSA, so real key generation, signing and verification
 * are performed by the local CipherLab server (server.js) using Node's built-in crypto (OpenSSL).
 * Signatures use SHA-256 and FIPS 186 (L, N) parameter sizes. No ECDSA/RSA substitution is made.
 * Educational walkthrough: tiny toy domain parameters computed with BigInt in the browser.
 */
(() => {
  "use strict";
  const PK = window.CipherLabPK;
  const {$, escapeHTML, toast, hl, op, eqLines, stage} = PK;
  const API = "/api/dsa";

  const el = {
    message: $("#dsaMessage"), count: $("#dsaCount"), inputTag: $("#dsaInputTag"),
    sigField: $("#dsaSignatureField"), sigInput: $("#dsaSignature"),
    pub: $("#dsaPublicKey"), priv: $("#dsaPrivateKey"), status: $("#dsaKeyStatus"), generate: $("#dsaGenerate"),
    run: $("#dsaRun"), error: $("#dsaError"), engine: $("#dsaEngine"),
    placeholder: $("#dsaPlaceholder"), signResult: $("#dsaSignResult"), verifyResult: $("#dsaVerifyResult"),
    sigText: $("#dsaSignatureText"), components: $("#dsaComponents"), stats: $("#dsaResultStats"),
    verdict: $("#dsaVerdict"), verifyDetails: $("#dsaVerifyDetails")
  };
  const log = PK.createLog($("#dsaLog"), "DSA");
  const state = {signature: "", online: null, busy: false};
  const mode = PK.segmented($("#dsaModeGroup"), onModeChange);
  const params = PK.segmented($("#dsaParamGroup"));

  /* ---------- Engine connection ---------- */
  async function api(path, body) {
    let res;
    try {
      res = await fetch(`${API}${path}`, body ? {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
      } : {cache: "no-store"});
    } catch {
      setEngine(false);
      throw new Error("DSA engine offline. Start CipherLab with `npm start` and open http://localhost:3000.");
    }
    let data = {};
    try { data = await res.json(); } catch { /* non-JSON response */ }
    if (!res.ok) {
      if (res.status === 404 && !data.error) { setEngine(false); throw new Error("DSA engine not found. Serve CipherLab with `npm start` (server.js), not a plain static server."); }
      throw new Error(data.error || `DSA engine error (HTTP ${res.status}).`);
    }
    return data;
  }
  function setEngine(online, detail = "") {
    state.online = online;
    el.engine.classList.toggle("offline", !online);
    el.engine.innerHTML = `<span class="status-dot"></span> ENGINE: ${online ? `OPENSSL ${escapeHTML(detail)} · ONLINE` : "OFFLINE — RUN npm start"}`;
  }
  async function checkEngine() {
    if (location.protocol === "file:") {
      setEngine(false);
      log("Opened from file://. DSA needs the local engine: run `npm start`, then open http://localhost:3000.", "error");
      return;
    }
    try {
      const info = await api("/status");
      setEngine(true, info.openssl);
      log(`DSA engine online: Node ${info.node} / OpenSSL ${info.openssl}.`, "success");
    } catch (err) { log(err.message, "error"); }
  }

  /* ---------- UI state ---------- */
  function updateCount() { el.count.textContent = `${PK.byteLength(el.message.value)} BYTES`; }
  function resetOutput() {
    el.placeholder.classList.remove("hidden");
    el.signResult.classList.add("hidden");
    el.verifyResult.classList.add("hidden");
    el.error.textContent = "";
  }
  function onModeChange(value) {
    const sign = value === "sign";
    el.sigField.classList.toggle("hidden", sign);
    el.inputTag.textContent = sign ? "DATA TO SIGN" : "DATA TO VERIFY";
    el.run.innerHTML = `<span>▶</span> ${sign ? "SIGN WITH PRIVATE KEY" : "VERIFY WITH PUBLIC KEY"}`;
    resetOutput();
    log(`Operation mode: ${value.toUpperCase()}.`);
  }
  function fail(message) { el.error.textContent = message; log(message, "error"); }
  function busy(on, button, label) {
    state.busy = on; button.disabled = on;
    if (label) button.textContent = label;
  }
  const row = (k, v) => `<div class="sig-row"><span>${escapeHTML(k)}</span><span>${escapeHTML(v)}</span></div>`;
  const clip = (v, n = 64) => v.length > n ? `${v.slice(0, n)}…` : v;

  async function keyStatus(L, N) {
    const pem = el.pub.value.trim();
    let fp = "";
    try { fp = await PK.fingerprint(PK.fromPem(pem, "PUBLIC KEY")); } catch { /* status only */ }
    el.status.textContent = `DSA L=${L} N=${N} · SHA-256${fp ? ` · FP ${fp}` : ""}`;
  }

  /* ---------- Operations ---------- */
  async function generateKeys() {
    if (state.busy) return;
    el.error.textContent = "";
    const set = params.value, [L, N] = set.split("-");
    busy(true, el.generate, `✎ GENERATING DSA ${L}/${N} PARAMETERS…`);
    log(`Generating DSA domain parameters (L=${L}, N=${N}) and key pair...`);
    try {
      const data = await api("/generate", {parameters: set});
      el.pub.value = data.publicKey.trim();
      el.priv.value = data.privateKey.trim();
      PK.maskPrivate(el.priv);
      await keyStatus(data.L, data.N);
      resetOutput();
      log(`DSA key pair ready in ${data.ms} ms (p: ${data.L} bits, q: ${data.N} bits).`, "success");
      toast(`DSA ${L}/${N} key pair generated.`);
    } catch (err) { fail(err.message); }
    finally { busy(false, el.generate, "✎ GENERATE KEY PAIR"); }
  }

  async function execute() {
    if (state.busy) return;
    el.error.textContent = "";
    const message = el.message.value;
    if (!message.length) { fail(`Enter the message to ${mode.value}.`); return; }
    if (mode.value === "sign") {
      const privateKey = el.priv.value.trim();
      if (!privateKey) { fail("No private key loaded. Generate a DSA key pair or paste a PEM private key."); return; }
      if (!/^-----BEGIN PRIVATE KEY-----/.test(privateKey)) { fail('Private key must be a PKCS#8 PEM block ("-----BEGIN PRIVATE KEY-----").'); return; }
      busy(true, el.run, "▶ SIGNING…");
      try {
        const data = await api("/sign", {message, privateKey});
        state.signature = data.signature;
        el.placeholder.classList.add("hidden"); el.verifyResult.classList.add("hidden"); el.signResult.classList.remove("hidden");
        el.sigText.textContent = data.signature;
        el.components.innerHTML = row("SHA-256", data.hash) + row("r", data.r) + row("s", data.s);
        el.stats.textContent = `${PK.base64ToBuf(data.signature).byteLength} BYTES · L=${data.L} N=${data.N}`;
        log(`Message digest SHA-256: ${PK.shortHex(data.hash, 8)}.`);
        log("Fresh secret nonce k drawn by OpenSSL for this signature.");
        log(`Signature (r, s) produced with ${data.N}-bit q.`, "success");
        PK.addHistoryEntry(`DSA · SHA-256 · ${data.L}/${data.N}`, "SIGN", message, clip(data.signature));
      } catch (err) { fail(err.message); }
      finally { busy(false, el.run); onModeLabel(); }
    } else {
      const signature = el.sigInput.value.trim(), publicKey = el.pub.value.trim();
      if (!signature) { fail("Paste the signature to verify."); return; }
      if (!publicKey) { fail("No public key loaded. Generate a DSA key pair or paste the signer's PEM public key."); return; }
      if (!/^-----BEGIN PUBLIC KEY-----/.test(publicKey)) { fail('Public key must be an SPKI PEM block ("-----BEGIN PUBLIC KEY-----").'); return; }
      busy(true, el.run, "▶ VERIFYING…");
      try {
        const data = await api("/verify", {message, signature, publicKey});
        el.placeholder.classList.add("hidden"); el.signResult.classList.add("hidden"); el.verifyResult.classList.remove("hidden");
        el.verdict.className = `verdict ${data.valid ? "valid" : "invalid"}`;
        el.verdict.innerHTML = `<span class="verdict-icon">${data.valid ? "✓" : "✕"}</span><span>${data.valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"}<small>${escapeHTML(data.reason)}</small></span>`;
        el.verifyDetails.innerHTML = (data.hash ? row("SHA-256", data.hash) : "") + (data.L ? row("KEY", `DSA L=${data.L} N=${data.N}`) : "");
        log(data.valid ? "Verification passed: v = r." : `Verification failed: ${data.reason}`, data.valid ? "success" : "error");
        PK.addHistoryEntry("DSA · SHA-256", "VERIFY", message, data.valid ? "VALID SIGNATURE" : "INVALID SIGNATURE");
      } catch (err) { fail(err.message); }
      finally { busy(false, el.run); onModeLabel(); }
    }
  }
  function onModeLabel() { el.run.innerHTML = `<span>▶</span> ${mode.value === "sign" ? "SIGN WITH PRIVATE KEY" : "VERIFY WITH PUBLIC KEY"}`; }

  function resetModule() {
    el.pub.value = ""; el.priv.value = ""; el.sigInput.value = ""; PK.maskPrivate(el.priv);
    state.signature = "";
    el.status.textContent = "NO KEY LOADED";
    el.message.value = ""; updateCount();
    if (mode.value !== "sign") mode.set("sign"); else resetOutput();
    log("Module reset. Keys and signature cleared.");
    toast("DSA module reset.");
  }

  el.generate.addEventListener("click", generateKeys);
  el.run.addEventListener("click", execute);
  el.message.addEventListener("input", updateCount);
  $("#dsaClearInput").addEventListener("click", () => { el.message.value = ""; updateCount(); resetOutput(); });
  $("#dsaReset").addEventListener("click", resetModule);
  $("#dsaCopySignature").addEventListener("click", () => PK.copyText(state.signature, "Signature"));
  $("#dsaUseSignature").addEventListener("click", () => {
    const sig = state.signature;
    mode.set("verify"); el.sigInput.value = sig;
    toast("Signature moved to verification. Edit the message to simulate tampering.");
  });
  [el.pub, el.priv].forEach(box => box.addEventListener("change", resetOutput));
  PK.onModuleChange(name => { if (name === "dsa" && state.online !== true) checkEngine(); });

  /* ================= Educational walkthrough (toy numbers only) ================= */
  const TOY = {p: 607n, q: 101n, h: 2n, N: 7};
  TOY.g = PK.modPow(TOY.h, (TOY.p - 1n) / TOY.q, TOY.p); // 64
  const toyMsg = $("#dsaToyMessage"), toyVerify = $("#dsaToyVerify"), toyError = $("#dsaToyError");
  const stepper = PK.createStepper($("#dsaWalkthrough"));
  let toyMsgPrev = toyMsg.value;
  toyMsg.addEventListener("input", () => { if (toyVerify.value === toyMsgPrev) toyVerify.value = toyMsg.value; toyMsgPrev = toyMsg.value; });

  async function toyHash(text) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    const hex = PK.toHex(digest);
    // FIPS 186: z = leftmost min(N, outlen) bits of the hash. Here N = bitlen(q) = 7.
    const z = BigInt(digest[0] >> (8 - TOY.N));
    return {hex, z};
  }

  async function buildWalkthrough() {
    toyError.textContent = "";
    const msg = toyMsg.value, received = toyVerify.value;
    if (!msg.length) { toyError.textContent = "Enter a message to sign."; return; }
    if (!(window.crypto && crypto.subtle)) { toyError.textContent = "SHA-256 (Web Crypto) unavailable — open CipherLab via http://localhost."; return; }
    const {p, q, g, h} = TOY;
    const x = BigInt(PK.secureRandomInt(1, Number(q) - 1));
    const y = PK.modPow(g, x, p);
    const H = await toyHash(msg), H2 = await toyHash(received);
    let k, kInv, gk, r, s;
    do {
      k = BigInt(PK.secureRandomInt(1, Number(q) - 1));
      gk = PK.modPow(g, k, p); r = gk % q;
      kInv = PK.modInverse(k, q);
      s = kInv * (H.z + x * r) % q;
    } while (r === 0n || s === 0n);
    const w = PK.modInverse(s, q), u1 = H2.z * w % q, u2 = r * w % q;
    const gu1 = PK.modPow(g, u1, p), yu2 = PK.modPow(y, u2, p), v = gu1 * yu2 % p % q;
    const valid = v === r, tampered = received !== msg;
    const bin = z => z.toString(2).padStart(TOY.N, "0");

    const steps = [
      {description: "DSA first fixes public domain parameters: a prime p, a prime q dividing p − 1, and a generator g of the order-q subgroup. Real DSA uses p of 2048–3072 bits and q of 224–256 bits.",
        html: stage(1, "GENERATE DOMAIN PARAMETERS (p, q, g)", eqLines([
          {label: "PRIME q", eq: `q = ${hl(q)}`, note: `N = ${TOY.N} bits (real: 224 / 256)`},
          {label: "PRIME p", eq: `p = ${hl(p)}`, note: `p − 1 = ${p - 1n} = ${(p - 1n) / q} ${"×"} q ✓`},
          {label: "GENERATOR g", eq: `g = h${op("^")}((p−1)/q) mod p = ${h}${op("^")}${(p - 1n) / q} mod ${p}`, result: `= ${g}`},
          {label: "ORDER CHECK", eq: `g${op("^")}q mod p = ${g}${op("^")}${q} mod ${p}`, result: `= ${PK.modPow(g, q, p)} ✓`}]))},
      {description: "The signer's private key x is a uniformly random integer in [1, q − 1]. Here it is drawn with crypto.getRandomValues, never Math.random().",
        html: stage(2, "GENERATE PRIVATE KEY x", eqLines([
          {label: "RANGE", eq: `1 ≤ x ≤ q − 1 = ${q - 1n}`},
          {label: "PRIVATE KEY", eq: `x = ${hl(x)}`, cls: "warn", note: "secret — never shared"}]))},
      {description: "The public key y is g raised to x modulo p. Recovering x from y is the discrete logarithm problem.",
        html: stage(3, "CALCULATE PUBLIC KEY y = gˣ mod p", eqLines([
          {label: "PUBLIC KEY", eq: `y = g${op("^")}x mod p = ${g}${op("^")}${x} mod ${p}`, result: `= ${y}`},
          {label: "PUBLISHED", eq: `(p, q, g, y) = (${p}, ${q}, ${g}, ${hl(y)})`}]))},
      {description: "DSA signs the hash of the message, not the message itself. SHA-256 is computed for real; FIPS 186 then keeps the leftmost N bits of the digest as the integer z.",
        html: stage(4, "CALCULATE THE MESSAGE HASH", eqLines([
          {label: "MESSAGE", eq: hl(msg)},
          {label: "SHA-256", eq: `<span style="word-break:break-all">${H.hex}</span>`},
          {label: `LEFTMOST ${TOY.N} BITS`, eq: `${bin(H.z)}₂`, result: `z = ${H.z}`}]))},
      {description: "Every signature needs a fresh, secret, unpredictable nonce k in [1, q − 1]. If k is ever reused or leaked, anyone can solve for the private key x.",
        html: stage(5, "GENERATE PER-MESSAGE NONCE k", eqLines([
          {label: "NONCE", eq: `k = ${hl(k)}`, note: "fresh crypto.getRandomValues draw"},
          {label: "INVERSE", eq: `k⁻¹ mod q = ${k}⁻¹ mod ${q}`, result: `= ${kInv}`},
          {label: "DANGER", eq: "x = (s·k − z) · r⁻¹ mod q", cls: "warn", note: "a known or repeated k leaks x"}]))},
      {description: "r depends only on k; s binds together the nonce, the message hash and the private key. If either value comes out as 0, a new k is chosen.",
        html: stage(6, "CALCULATE SIGNATURE COMPONENTS r AND s", eqLines([
          {label: "gᵏ mod p", eq: `${g}${op("^")}${k} mod ${p}`, result: `= ${gk}`},
          {label: "r", eq: `r = (gᵏ mod p) mod q = ${gk} mod ${q}`, result: `= ${r}`},
          {label: "s", eq: `s = k⁻¹ (z + x·r) mod q = ${kInv} ${op("×")} (${H.z} + ${x}${op("×")}${r}) mod ${q}`, result: `= ${s}`}]))},
      {description: "The signature is the pair (r, s). It is sent alongside the message; the private key x and the nonce k are discarded or kept secret.",
        html: stage(7, "PRODUCE THE DIGITAL SIGNATURE (r, s)", eqLines([
          {label: "SIGNATURE", eq: `(r, s) = (${hl(r)}, ${hl(s)})`},
          {label: "TRANSMITTED", eq: `message + (r, s)`, note: "anyone with y can check it"}]))},
      {description: "The verifier receives a message, the signature (r, s) and the signer's public key y. First it checks the ranges, then hashes the message it actually received.",
        html: stage(8, "BEGIN SIGNATURE VERIFICATION", eqLines([
          {label: "RECEIVED", eq: hl(received), cls: tampered ? "warn" : "", note: tampered ? "differs from the signed message" : "identical to the signed message"},
          {label: "RANGE CHECK", eq: `0 < r = ${r} < ${q}, 0 < s = ${s} < ${q}`, result: "✓"},
          {label: "HASH z′", eq: `leftmost ${TOY.N} bits of SHA-256 = ${bin(H2.z)}₂`, result: `z′ = ${H2.z}`}]))},
      {description: "Using only public values, the verifier computes w, u₁, u₂ and finally v. Algebraically v reproduces gᵏ mod p mod q whenever the message and key are genuine.",
        html: stage(9, "CALCULATE VERIFICATION VALUES", eqLines([
          {label: "w", eq: `w = s⁻¹ mod q = ${s}⁻¹ mod ${q}`, result: `= ${w}`},
          {label: "u₁", eq: `u₁ = z′·w mod q = ${H2.z}${op("×")}${w} mod ${q}`, result: `= ${u1}`},
          {label: "u₂", eq: `u₂ = r·w mod q = ${r}${op("×")}${w} mod ${q}`, result: `= ${u2}`},
          {label: "v", eq: `v = (g${op("^")}u₁ · y${op("^")}u₂ mod p) mod q = (${gu1} ${op("×")} ${yu2} mod ${p}) mod ${q}`, result: `= ${v}`}]))},
      {description: valid ? "v equals r, so the signature is accepted: the message is authentic and unmodified." :
          "v does not equal r, so the signature is rejected: the message was altered or the wrong key was used.",
        html: stage(10, "VERIFY WHETHER THE SIGNATURE IS VALID", eqLines([
          {label: "COMPARE", eq: `v = ${hl(v)} ${op(valid ? "=" : "≠")} r = ${hl(r)}`, cls: valid ? "" : "bad", result: valid ? "MATCH" : "MISMATCH"}]) +
          (valid && tampered ? eqLines([{label: "TOY COLLISION", eq: `both messages share the same ${TOY.N}-bit z`, cls: "warn", note: "real DSA keeps 224–256 hash bits, making this infeasible"}]) : "") +
          `<div class="final-state ${valid ? "" : "fail"}">${valid ? "✓ VALID SIGNATURE" : "✕ INVALID SIGNATURE"}</div>`)}
    ];
    stepper.load(steps);
  }
  $("#dsaToyBuild").addEventListener("click", buildWalkthrough);
  [toyMsg, toyVerify].forEach(i => i.addEventListener("keydown", e => { if (e.key === "Enter") buildWalkthrough(); }));

  updateCount();
  onModeChange("sign");
  buildWalkthrough().catch(err => { toyError.textContent = err.message; });
})();
