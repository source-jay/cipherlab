/* CipherLab — shared helpers for the public-key modules (RSA / DSA) */
(() => {
  "use strict";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const core = window.CipherLab || {};
  const escapeHTML = core.escapeHTML || (v => String(v).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])));
  const toast = core.toast || (() => {});
  const addHistoryEntry = core.addHistoryEntry || (() => {});

  /* ---------- Module switching (algorithm tabs) ---------- */
  const titleEl = $("#simTitle"), subtitleEl = $("#simSubtitle");
  const original = {title: titleEl.innerHTML, subtitle: subtitleEl.textContent};
  const headings = {
    rsa: {title: "RSA <span>ENCRYPTION</span> LAB", subtitle: "Encrypt with the public key. Decrypt with the private key. See the mathematics underneath."},
    dsa: {title: "DSA <span>SIGNATURE</span> LAB", subtitle: "Sign with the private key. Verify with the public key. Prove who wrote the message."}
  };
  const modules = {rsa: $("#rsaModule"), dsa: $("#dsaModule")};
  const listeners = [];

  function showModule(name) {
    $("#classicalWorkspace").classList.toggle("hidden", Boolean(name));
    Object.entries(modules).forEach(([key, el]) => el.classList.toggle("hidden", key !== name));
    titleEl.innerHTML = name ? headings[name].title : original.title;
    subtitleEl.textContent = name ? headings[name].subtitle : original.subtitle;
    listeners.forEach(fn => fn(name));
  }
  $$(".algorithm-tab[data-module]").forEach(button => button.addEventListener("click", () => {
    $$(".algorithm-tab").forEach(b => b.classList.toggle("active", b === button));
    showModule(button.dataset.module);
  }));
  // Classical tabs are handled by script.js; we only restore the classical workspace.
  $$(".algorithm-tab[data-algorithm]").forEach(button => button.addEventListener("click", () => showModule(null)));

  /* ---------- UI helpers ---------- */
  function segmented(groupEl, onChange) {
    const buttons = $$(".mode-button", groupEl);
    const api = {
      get value() { return buttons.find(b => b.classList.contains("active")).dataset.value; },
      set(value) {
        buttons.forEach(b => b.classList.toggle("active", b.dataset.value === value));
        onChange && onChange(value);
      },
      setDisabled(disabled) { buttons.forEach(b => { b.disabled = disabled; }); }
    };
    buttons.forEach(b => b.addEventListener("click", () => { if (!b.classList.contains("active")) api.set(b.dataset.value); }));
    return api;
  }

  function createLog(container, tag) {
    return function log(message, type = "normal") {
      const p = document.createElement("p");
      const prefix = type === "error" ? '<span class="log-error">[ERROR]</span>' :
        type === "success" ? '<span class="log-muted">[SUCCESS]</span>' :
        `<span class="log-muted">[${tag}]</span>`;
      p.innerHTML = `${prefix} ${escapeHTML(message)}`;
      container.appendChild(p);
      while (container.children.length > 8) container.removeChild(container.firstChild);
      container.scrollTop = container.scrollHeight;
    };
  }

  async function copyText(text, label) {
    if (!text) { toast(`Nothing to copy — ${label.toLowerCase()} is empty.`); return; }
    try { await navigator.clipboard.writeText(text); toast(`${label} copied to clipboard.`); }
    catch { toast("Clipboard unavailable. Select and copy manually."); }
  }

  // [ COPY ] and [ REVEAL ] buttons declared in markup via data attributes.
  $$("[data-copy]").forEach(btn => btn.addEventListener("click", () => {
    const target = document.getElementById(btn.dataset.copy);
    const label = target.id.toLowerCase().includes("private") ? "Private key" : "Public key";
    copyText(target.value.trim(), label);
  }));
  $$("[data-reveal]").forEach(btn => btn.addEventListener("click", () => {
    const target = document.getElementById(btn.dataset.reveal);
    const masked = target.classList.toggle("masked");
    btn.textContent = masked ? "[ REVEAL ]" : "[ HIDE ]";
  }));
  function maskPrivate(textarea) {
    textarea.classList.add("masked");
    const btn = $(`[data-reveal="${textarea.id}"]`);
    if (btn) btn.textContent = "[ REVEAL ]";
  }

  const utf8 = new TextEncoder();
  const byteLength = text => utf8.encode(text).length;

  /* ---------- Encoding ---------- */
  function bufToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  }
  function base64ToBuf(b64) {
    const clean = b64.replace(/\s+/g, "");
    if (!clean || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean) || clean.length % 4 !== 0) throw new Error("Input is not valid Base64.");
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
  function toPem(buffer, label) {
    const body = bufToBase64(buffer).match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
  }
  function fromPem(pem, label) {
    const text = pem.trim();
    const match = text.match(/^-----BEGIN ([A-Z0-9 ]+)-----([\s\S]+?)-----END \1-----$/);
    if (!match) throw new Error(`Key must be PEM text beginning with "-----BEGIN ${label}-----".`);
    if (match[1] !== label) throw new Error(`Expected a "${label}" PEM block but found "${match[1]}".`);
    return base64ToBuf(match[2]);
  }
  const toHex = buffer => [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
  const shortHex = (hex, size = 16) => hex.length > size * 2 ? `${hex.slice(0, size)}…${hex.slice(-size)}` : hex;
  async function fingerprint(buffer) { return shortHex(toHex(await crypto.subtle.digest("SHA-256", buffer)), 8).toUpperCase(); }

  /* ---------- Small-number maths for the educational walkthroughs (BigInt) ---------- */
  function modPow(base, exp, mod) {
    let result = 1n; base %= mod;
    while (exp > 0n) { if (exp & 1n) result = result * base % mod; base = base * base % mod; exp >>= 1n; }
    return result;
  }
  function gcd(a, b) { while (b) [a, b] = [b, a % b]; return a < 0n ? -a : a; }
  function modInverse(a, m) {
    let [oldR, r] = [((a % m) + m) % m, m], [oldS, s] = [1n, 0n];
    while (r) { const q = oldR / r; [oldR, r] = [r, oldR - q * r]; [oldS, s] = [s, oldS - q * s]; }
    if (oldR !== 1n) throw new Error("No modular inverse exists.");
    return ((oldS % m) + m) % m;
  }
  function isPrime(n) {
    if (n < 2) return false;
    for (let i = 2; i * i <= n; i++) if (n % i === 0) return false;
    return true;
  }
  // Uniform random integer in [min, max] from crypto.getRandomValues (rejection sampling).
  function secureRandomInt(min, max) {
    const range = max - min + 1;
    const limit = Math.floor(0x100000000 / range) * range;
    const buf = new Uint32Array(1);
    do crypto.getRandomValues(buf); while (buf[0] >= limit);
    return min + (buf[0] % range);
  }

  /* ---------- Walkthrough markup helpers ---------- */
  const hl = v => `<span class="hl">${escapeHTML(v)}</span>`;
  const op = v => `<span class="op">${v}</span>`;
  function eqLines(lines) {
    return lines.map((l, i) => `<div class="eq-line ${l.cls || ""}" style="animation-delay:${(i * 0.14).toFixed(2)}s">` +
      `<span class="eq-label">${escapeHTML(l.label)}</span><span class="eq">${l.eq || ""}</span>` +
      (l.result !== undefined ? `<span class="eq-result">${l.result}</span>` : "") +
      (l.note ? `<span class="eq-note">${escapeHTML(l.note)}</span>` : "") + "</div>").join("");
  }
  function cells(items) {
    return `<div class="math-table">${items.map((c, i) => `<div class="math-cell" style="animation-delay:${(0.1 + i * 0.06).toFixed(2)}s">` +
      `<span class="from">${escapeHTML(c.from)}</span>${c.mid !== undefined ? `<span class="mid">${escapeHTML(c.mid)}</span>` : ""}<span class="to">${escapeHTML(c.to)}</span></div>`).join("")}</div>`;
  }
  function stage(index, title, body) {
    return `<div class="math-title"><span>${String(index).padStart(2, "0")}</span>${escapeHTML(title)}</div>${body}`;
  }

  /* ---------- Step-by-step player (mirrors the classical visualization controls) ---------- */
  function createStepper(root) {
    const q = role => $(`[data-role="${role}"]`, root);
    const els = {counter: q("counter"), reset: q("reset"), number: q("number"), desc: q("desc"), stage: q("stage"),
      prev: q("prev"), next: q("next"), play: q("play"), fill: q("fill"), text: q("text")};
    let steps = [], index = 0, timer = null;
    function stop() { if (timer) clearInterval(timer); timer = null; els.play.textContent = "▶ AUTO PLAY"; }
    function render() {
      const step = steps[index];
      if (!step) return;
      const total = steps.length;
      els.counter.textContent = `TRACE ${String(index + 1).padStart(2, "0")} / ${String(total).padStart(2, "0")}`;
      els.number.textContent = `STEP ${String(index + 1).padStart(2, "0")}`;
      els.desc.textContent = step.description;
      els.stage.innerHTML = step.html;
      els.fill.style.width = `${((index + 1) / total) * 100}%`;
      els.text.textContent = `${index + 1} / ${total}`;
      els.prev.disabled = index === 0;
      els.next.disabled = index === total - 1;
      els.reset.disabled = false;
    }
    function move(delta) {
      index = Math.max(0, Math.min(steps.length - 1, index + delta)); render();
      if (index === steps.length - 1) stop();
    }
    els.prev.addEventListener("click", () => { stop(); move(-1); });
    els.next.addEventListener("click", () => { stop(); move(1); });
    els.reset.addEventListener("click", () => { stop(); index = 0; render(); });
    els.play.addEventListener("click", () => {
      if (timer) { stop(); return; }
      if (!steps.length) return;
      if (index === steps.length - 1) index = 0;
      els.play.textContent = "Ⅱ PAUSE"; render();
      timer = setInterval(() => move(1), 2600);
    });
    return {load(newSteps) { stop(); steps = newSteps; index = 0; render(); }, stop};
  }

  window.CipherLabPK = {
    $, $$, escapeHTML, toast, addHistoryEntry, segmented, createLog, copyText, maskPrivate, byteLength,
    bufToBase64, base64ToBuf, toPem, fromPem, toHex, shortHex, fingerprint,
    modPow, gcd, modInverse, isPrime, secureRandomInt,
    hl, op, eqLines, cells, stage, createStepper,
    onModuleChange(fn) { listeners.push(fn); }
  };
})();
