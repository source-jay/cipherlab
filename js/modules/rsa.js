/* CipherLab — RSA module
 * Real operations: Web Crypto RSA-OAEP with SHA-256, 2048/3072-bit keys, public exponent 65537.
 * Educational walkthrough: textbook RSA with tiny primes, kept completely separate.
 */
(() => {
  "use strict";
  const PK = window.CipherLabPK;
  const {$, escapeHTML, toast, hl, op, eqLines, cells, stage} = PK;
  const ALGO = {name: "RSA-OAEP", hash: "SHA-256"};
  const HASH_BYTES = 32;
  const MIN_BITS = 2048;

  const el = {
    input: $("#rsaInput"), inputLabel: $("#rsaInputLabel"), inputTag: $("#rsaInputTag"), count: $("#rsaCount"),
    pub: $("#rsaPublicKey"), priv: $("#rsaPrivateKey"), status: $("#rsaKeyStatus"), generate: $("#rsaGenerate"),
    run: $("#rsaRun"), error: $("#rsaError"), placeholder: $("#rsaPlaceholder"), result: $("#rsaResult"),
    resultLabel: $("#rsaResultLabel"), resultText: $("#rsaResultText"), stats: $("#rsaResultStats"),
    useOutput: $("#rsaUseOutput")
  };
  const log = PK.createLog($("#rsaLog"), "RSA");
  const state = {output: "", cache: {pub: null, priv: null}, busy: false};
  const mode = PK.segmented($("#rsaModeGroup"), onModeChange);
  const size = PK.segmented($("#rsaSizeGroup"));
  const supported = Boolean(window.crypto && crypto.subtle);

  const maxPlaintextBytes = bits => bits / 8 - 2 * HASH_BYTES - 2;

  function updateCount() {
    const text = el.input.value;
    el.count.textContent = mode.value === "encrypt" ? `${PK.byteLength(text)} BYTES` :
      `${text.replace(/\s+/g, "").length} BASE64 CHARACTERS`;
  }
  function resetOutput() {
    state.output = "";
    el.placeholder.classList.remove("hidden");
    el.result.classList.add("hidden");
    el.error.textContent = "";
  }
  function onModeChange(value) {
    const encrypt = value === "encrypt";
    el.inputLabel.textContent = encrypt ? "PLAINTEXT (UTF-8)" : "CIPHERTEXT (BASE64)";
    el.inputTag.textContent = encrypt ? "PLAINTEXT" : "CIPHERTEXT";
    el.input.placeholder = encrypt ? "Enter your message here..." : "Paste the Base64 ciphertext produced by RSA-OAEP...";
    el.run.innerHTML = `<span>▶</span> ${encrypt ? "ENCRYPT WITH PUBLIC KEY" : "DECRYPT WITH PRIVATE KEY"}`;
    resetOutput(); updateCount();
    log(`Operation mode: ${value.toUpperCase()}.`);
  }
  function fail(message) { el.error.textContent = message; log(message, "error"); }

  /* ---------- Key handling ---------- */
  async function describeKey(key, spki) {
    const fp = spki ? await PK.fingerprint(spki) : "";
    return `RSA-${key.algorithm.modulusLength} · e=65537 · OAEP/SHA-256${fp ? ` · FP ${fp}` : ""}`;
  }
  async function importPublic() {
    const pem = el.pub.value.trim();
    if (!pem) throw new Error("No public key loaded. Generate a key pair or paste a PEM public key.");
    if (state.cache.pub && state.cache.pub.pem === pem) return state.cache.pub.key;
    let key;
    try { key = await crypto.subtle.importKey("spki", PK.fromPem(pem, "PUBLIC KEY"), ALGO, false, ["encrypt"]); }
    catch (err) { throw new Error(err.message.includes("PEM") || err.message.includes("Base64") ? err.message : "Public key could not be imported — it is not a valid RSA SubjectPublicKeyInfo key."); }
    if (key.algorithm.modulusLength < MIN_BITS) throw new Error(`Public key is ${key.algorithm.modulusLength}-bit. CipherLab requires at least ${MIN_BITS}-bit RSA.`);
    state.cache.pub = {pem, key};
    return key;
  }
  async function importPrivate() {
    const pem = el.priv.value.trim();
    if (!pem) throw new Error("No private key loaded. Generate a key pair or paste a PEM private key.");
    if (state.cache.priv && state.cache.priv.pem === pem) return state.cache.priv.key;
    let key;
    try { key = await crypto.subtle.importKey("pkcs8", PK.fromPem(pem, "PRIVATE KEY"), ALGO, false, ["decrypt"]); }
    catch (err) { throw new Error(err.message.includes("PEM") || err.message.includes("Base64") ? err.message : "Private key could not be imported — it is not a valid RSA PKCS#8 key."); }
    if (key.algorithm.modulusLength < MIN_BITS) throw new Error(`Private key is ${key.algorithm.modulusLength}-bit. CipherLab requires at least ${MIN_BITS}-bit RSA.`);
    state.cache.priv = {pem, key};
    return key;
  }

  async function generateKeys() {
    if (state.busy) return;
    if (!supported) { fail("Web Crypto API is unavailable. Open CipherLab over http://localhost or https://."); return; }
    const bits = Number(size.value);
    state.busy = true; el.generate.disabled = true; el.generate.textContent = `⚿ GENERATING ${bits}-BIT KEY PAIR…`;
    el.error.textContent = "";
    log(`Generating RSA-${bits} key pair with secure randomness...`);
    const started = performance.now();
    try {
      const pair = await crypto.subtle.generateKey(
        {...ALGO, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1])}, true, ["encrypt", "decrypt"]);
      const [spki, pkcs8] = await Promise.all([
        crypto.subtle.exportKey("spki", pair.publicKey), crypto.subtle.exportKey("pkcs8", pair.privateKey)]);
      el.pub.value = PK.toPem(spki, "PUBLIC KEY");
      el.priv.value = PK.toPem(pkcs8, "PRIVATE KEY");
      PK.maskPrivate(el.priv);
      state.cache = {pub: {pem: el.pub.value.trim(), key: pair.publicKey}, priv: {pem: el.priv.value.trim(), key: pair.privateKey}};
      el.status.textContent = await describeKey(pair.publicKey, spki);
      resetOutput();
      log(`RSA-${bits} key pair ready in ${Math.round(performance.now() - started)} ms.`, "success");
      log(`Max plaintext per OAEP block: ${maxPlaintextBytes(bits)} bytes.`);
      toast(`RSA-${bits} key pair generated.`);
    } catch {
      fail("Key generation failed in this browser.");
    } finally {
      state.busy = false; el.generate.disabled = false; el.generate.textContent = "⚿ GENERATE KEY PAIR";
    }
  }

  async function refreshKeyStatus() {
    const hasPub = el.pub.value.trim(), hasPriv = el.priv.value.trim();
    if (!hasPub && !hasPriv) { el.status.textContent = "NO KEY LOADED"; return; }
    try {
      if (hasPub) {
        const key = await importPublic();
        el.status.textContent = await describeKey(key, PK.fromPem(el.pub.value, "PUBLIC KEY"));
      } else {
        const key = await importPrivate();
        el.status.textContent = `${await describeKey(key)} · PRIVATE ONLY`;
      }
    } catch (err) { el.status.textContent = `KEY ERROR: ${err.message.toUpperCase()}`; }
  }

  /* ---------- Encrypt / decrypt ---------- */
  async function execute() {
    el.error.textContent = "";
    if (!supported) { fail("Web Crypto API is unavailable. Open CipherLab over http://localhost or https://."); return; }
    const text = el.input.value;
    if (!text.trim()) { fail(mode.value === "encrypt" ? "Enter a message to encrypt." : "Paste a ciphertext to decrypt."); return; }
    try {
      if (mode.value === "encrypt") {
        const key = await importPublic();
        const bits = key.algorithm.modulusLength, limit = maxPlaintextBytes(bits), bytes = new TextEncoder().encode(text);
        if (bytes.length > limit) { fail(`Message is ${bytes.length} bytes; RSA-${bits} OAEP/SHA-256 can encrypt at most ${limit} bytes. Shorten it (real systems use hybrid RSA + AES).`); return; }
        const cipher = await crypto.subtle.encrypt({name: "RSA-OAEP"}, key, bytes);
        show(PK.bufToBase64(cipher), "ENCRYPTED OUTPUT · BASE64", `${cipher.byteLength} BYTES CIPHERTEXT`);
        el.useOutput.classList.remove("hidden");
        log(`Encrypted ${bytes.length} bytes with RSA-${bits} public key (OAEP, SHA-256).`, "success");
        log("OAEP adds fresh randomness: encrypting again yields a different ciphertext.");
        PK.addHistoryEntry(`RSA-OAEP · ${bits} BIT`, "ENCRYPT", text, clip(state.output));
      } else {
        const key = await importPrivate();
        const bits = key.algorithm.modulusLength;
        let cipher;
        try { cipher = PK.base64ToBuf(text); }
        catch { fail("Ciphertext is not valid Base64. Paste the exact output of the encryption step."); return; }
        if (cipher.byteLength !== bits / 8) { fail(`Ciphertext is ${cipher.byteLength} bytes but this RSA-${bits} key expects exactly ${bits / 8} bytes. Wrong key size or truncated ciphertext.`); return; }
        let plain;
        try { plain = await crypto.subtle.decrypt({name: "RSA-OAEP"}, key, cipher); }
        catch { fail("Decryption failed — the private key does not match this ciphertext, or the ciphertext was modified."); return; }
        const decoded = new TextDecoder("utf-8", {fatal: true}).decode(plain);
        show(decoded, "DECRYPTED OUTPUT · PLAINTEXT", `${plain.byteLength} BYTES RECOVERED`);
        el.useOutput.classList.add("hidden");
        log(`Decrypted ${plain.byteLength} bytes with RSA-${bits} private key. OAEP padding verified.`, "success");
        PK.addHistoryEntry(`RSA-OAEP · ${bits} BIT`, "DECRYPT", clip(text), decoded);
      }
    } catch (err) {
      fail(err.message || "RSA operation failed.");
    }
  }
  const clip = (v, n = 64) => v.length > n ? `${v.slice(0, n)}…` : v;
  function show(output, label, stats) {
    state.output = output;
    el.placeholder.classList.add("hidden");
    el.result.classList.remove("hidden");
    el.resultLabel.textContent = label;
    el.resultText.textContent = output;
    el.stats.textContent = stats;
  }

  function resetModule() {
    el.pub.value = ""; el.priv.value = ""; PK.maskPrivate(el.priv);
    state.cache = {pub: null, priv: null};
    el.status.textContent = "NO KEY LOADED";
    el.input.value = ""; updateCount(); resetOutput();
    log("Module reset. Keys cleared from memory.");
    toast("RSA module reset.");
  }

  el.generate.addEventListener("click", generateKeys);
  el.run.addEventListener("click", execute);
  el.input.addEventListener("input", updateCount);
  $("#rsaClearInput").addEventListener("click", () => { el.input.value = ""; updateCount(); resetOutput(); });
  $("#rsaReset").addEventListener("click", resetModule);
  $("#rsaCopyOutput").addEventListener("click", () => PK.copyText(state.output, "Output"));
  el.useOutput.addEventListener("click", () => {
    const cipher = state.output;
    mode.set("decrypt"); el.input.value = cipher; updateCount();
    toast("Ciphertext moved to the decryption input.");
  });
  [el.pub, el.priv].forEach(box => box.addEventListener("change", () => { resetOutput(); refreshKeyStatus(); }));

  /* ================= Educational walkthrough (toy numbers only) ================= */
  const PRIMES = [53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113];
  const toyP = $("#rsaToyP"), toyQ = $("#rsaToyQ"), toyMsg = $("#rsaToyMessage"), toyError = $("#rsaToyError");
  [toyP, toyQ].forEach((select, i) => {
    select.innerHTML = PRIMES.map(p => `<option value="${p}">${p}</option>`).join("");
    select.value = i === 0 ? "61" : "53";
  });
  const stepper = PK.createStepper($("#rsaWalkthrough"));

  function chooseE(phi) {
    for (const e of [17n, 3n, 5n, 7n, 11n, 13n, 19n, 23n, 29n, 31n, 37n]) if (e < phi && PK.gcd(e, phi) === 1n) return e;
    for (let e = 41n; e < phi; e += 2n) if (PK.gcd(e, phi) === 1n) return e;
    throw new Error("No valid e found.");
  }
  const show_ = ch => ch === " " ? "␠" : ch;

  function buildWalkthrough() {
    toyError.textContent = "";
    const p = BigInt(toyP.value), q = BigInt(toyQ.value), msg = toyMsg.value;
    if (p === q) { toyError.textContent = "p and q must be different primes."; return; }
    if (!msg.length) { toyError.textContent = "Enter a short message (1–12 characters)."; return; }
    if (!/^[\x20-\x7E]+$/.test(msg)) { toyError.textContent = "Use printable ASCII characters only for the walkthrough."; return; }
    const n = p * q, phi = (p - 1n) * (q - 1n), e = chooseE(phi), d = PK.modInverse(e, phi);
    const ms = [...msg].map(ch => BigInt(ch.charCodeAt(0)));
    const cs = ms.map(m => PK.modPow(m, e, n));
    const back = cs.map(c => PK.modPow(c, d, n));
    const recovered = back.map(m => String.fromCharCode(Number(m))).join("");
    const nBits = n.toString(2).length;
    const steps = [
      {description: "RSA begins with two distinct secret primes p and q. Real keys use random primes of 1024–1536 bits each; these tiny primes keep every number readable.",
        html: stage(1, "PRIME NUMBER SELECTION", eqLines([
          {label: "PRIME p", eq: `p = ${hl(p)}`, result: "PRIME ✓", note: `no divisor between 2 and √${p}`},
          {label: "PRIME q", eq: `q = ${hl(q)}`, result: "PRIME ✓", note: `no divisor between 2 and √${q}`},
          {label: "SECRECY", eq: "p and q are never published", cls: "warn", note: "anyone who learns them can rebuild the private key"}]))},
      {description: "Multiply the primes to obtain the modulus n. It is public and its bit length is the 'key size'. Recovering p and q from a 2048-bit n is the factoring problem RSA depends on.",
        html: stage(2, "CALCULATE n = p × q", eqLines([
          {label: "MODULUS", eq: `n = p ${op("×")} q = ${p} ${op("×")} ${q}`, result: `= ${n}`},
          {label: "KEY SIZE", eq: `bits(n) = ${hl(nBits)}`, note: "real RSA: 2048 or 3072 bits"}]))},
      {description: "Euler's totient φ(n) counts the integers below n that are coprime to n. For n = p·q it is (p−1)(q−1). Knowing φ(n) is equivalent to knowing the factors, so it stays secret.",
        html: stage(3, "CALCULATE EULER'S TOTIENT φ(n)", eqLines([
          {label: "TOTIENT", eq: `φ(n) = (p ${op("−")} 1)(q ${op("−")} 1) = ${p - 1n} ${op("×")} ${q - 1n}`, result: `= ${phi}`},
          {label: "SECRECY", eq: "φ(n) stays private", cls: "warn", note: "it is needed to derive d"}]))},
      {description: "Choose the public exponent e with 1 < e < φ(n) and gcd(e, φ(n)) = 1, so that an inverse exists. Production RSA almost always uses e = 65537.",
        html: stage(4, "SELECT PUBLIC EXPONENT e", eqLines([
          {label: "CANDIDATE", eq: `e = ${hl(e)}`, note: `1 < ${e} < ${phi}`},
          {label: "COPRIME TEST", eq: `gcd(e, φ(n)) = gcd(${e}, ${phi})`, result: `= ${PK.gcd(e, phi)} ✓`},
          {label: "REAL WORLD", eq: "e = 65537 = 2¹⁶ + 1", note: "fast to compute, avoids small-exponent attacks"}]))},
      {description: "The private exponent d is the modular inverse of e modulo φ(n), found with the extended Euclidean algorithm. It undoes the effect of e.",
        html: stage(5, "CALCULATE PRIVATE EXPONENT d", eqLines([
          {label: "DEFINITION", eq: `d ${op("≡")} e⁻¹ (mod φ(n)) = ${e}⁻¹ mod ${phi}`, result: `= ${d}`},
          {label: "CHECK", eq: `e ${op("×")} d mod φ(n) = ${e} ${op("×")} ${d} mod ${phi}`, result: `= ${(e * d) % phi} ✓`}]))},
      {description: "The key pair is complete. Publish (e, n) so anyone can encrypt to you; keep (d, n) — and p, q, φ(n) — secret.",
        html: stage(6, "GENERATE PUBLIC AND PRIVATE KEYS", eqLines([
          {label: "PUBLIC KEY", eq: `(e, n) = (${hl(e)}, ${hl(n)})`, note: "share freely"},
          {label: "PRIVATE KEY", eq: `(d, n) = (${hl(d)}, ${hl(n)})`, cls: "warn", note: "never share"}]))},
      {description: "RSA works on numbers smaller than n, so the text is converted to integers. Here each character becomes its ASCII code. Real RSA instead encodes the whole message with randomized OAEP padding.",
        html: stage(7, "CONVERT PLAINTEXT TO NUMBERS", eqLines([
          {label: "PLAINTEXT", eq: hl(msg)},
          {label: "RULE", eq: `m = ASCII(char), ${op("0 ≤ m < n")}`, note: `every value is below n = ${n}`}]) +
          cells([...msg].map((ch, i) => ({from: show_(ch), to: `m=${ms[i]}`}))) )},
      {description: "Each number is raised to the public exponent e modulo n. Without d, reversing this is infeasible for large n. Notice that identical letters encrypt identically — exactly why real RSA needs OAEP padding.",
        html: stage(8, "RSA ENCRYPTION  c = mᵉ mod n", eqLines([
          {label: "FORMULA", eq: `c = m${op("^")}e mod n`},
          {label: "EXAMPLE", eq: `c₁ = ${ms[0]}${op("^")}${e} mod ${n}`, result: `= ${cs[0]}`}]) +
          cells(ms.map((m, i) => ({from: `m=${m}`, mid: "→", to: `c=${cs[i]}`}))) )},
      {description: "The receiver raises each ciphertext number to the private exponent d modulo n. Because e·d ≡ 1 (mod φ(n)), (mᵉ)ᵈ ≡ m (mod n).",
        html: stage(9, "RSA DECRYPTION  m = cᵈ mod n", eqLines([
          {label: "FORMULA", eq: `m = c${op("^")}d mod n`},
          {label: "EXAMPLE", eq: `m₁ = ${cs[0]}${op("^")}${d} mod ${n}`, result: `= ${back[0]}`},
          {label: "WHY", eq: `(mᵉ)ᵈ = m${op("^")}(e·d) ${op("≡")} m (mod n)`}]) +
          cells(cs.map((c, i) => ({from: `c=${c}`, mid: "→", to: `m=${back[i]}`}))) )},
      {description: "Convert the recovered integers back to characters. The plaintext matches the original — the round trip is complete.",
        html: stage(10, "RECOVER THE ORIGINAL PLAINTEXT", cells(back.map(m => ({from: `m=${m}`, to: show_(String.fromCharCode(Number(m)))}))) +
          eqLines([{label: "RECOVERED", eq: hl(recovered)}, {label: "ORIGINAL", eq: hl(msg)}]) +
          (recovered === msg ? `<div class="final-state">✓ DECRYPTION SUCCESSFUL — PLAINTEXT RECOVERED EXACTLY</div>` :
            `<div class="final-state fail">✕ MISMATCH — RECOVERED TEXT DIFFERS</div>`))}
    ];
    stepper.load(steps);
  }
  $("#rsaToyBuild").addEventListener("click", buildWalkthrough);
  toyMsg.addEventListener("keydown", e => { if (e.key === "Enter") buildWalkthrough(); });

  onModeChange("encrypt");
  buildWalkthrough();
  if (!supported) fail("Web Crypto API unavailable — open CipherLab from a local file, http://localhost or https.");
})();
