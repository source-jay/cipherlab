/* CipherLab — classical cipher logic and interactive traces */
(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const state = {
    algorithm: "rail", mode: "encrypt", output: "", trace: [], step: 0,
    history: [], autoplay: null
  };

  const input = $("#messageInput");
  const railCount = $("#railCount");
  const subKey = $("#subKey");

  function log(message, type = "normal") {
    const p = document.createElement("p");
    const prefix = type === "error" ? '<span class="log-error">[ERROR]</span>' :
      type === "success" ? '<span class="log-muted">[SUCCESS]</span>' :
      '<span class="log-muted">[CIPHER]</span>';
    p.innerHTML = `${prefix} ${escapeHTML(message)}`;
    const container = $("#terminalLog");
    container.appendChild(p);
    while (container.children.length > 8) container.removeChild(container.firstChild);
    container.scrollTop = container.scrollHeight;
  }
  function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }
  function toast(message) {
    const el = $("#toast"); el.textContent = message; el.classList.add("show");
    clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.remove("show"), 2300);
  }
  function updateCount() {
    $("#charCount").textContent = `${input.value.length} CHARACTERS`;
  }
  function stopAutoplay() {
    if (state.autoplay) clearInterval(state.autoplay);
    state.autoplay = null; $("#playSteps").textContent = "▶ AUTO PLAY";
  }
  function setAlgorithm(algorithm) {
    state.algorithm = algorithm;
    $$(".algorithm-tab").forEach(b => b.classList.toggle("active", b.dataset.algorithm === algorithm));
    $("#railControls").classList.toggle("hidden", algorithm !== "rail");
    $("#subControls").classList.toggle("hidden", algorithm !== "substitution");
    $("#keyTitle").textContent = algorithm === "rail" ? "CIPHER CONFIGURATION" : "SUBSTITUTION KEY";
    log(`Algorithm selected: ${algorithm === "rail" ? "Rail Fence" : "Monoalphabetic Substitution"}.`);
    resetOutput();
  }
  function resetOutput() {
    state.output = ""; state.trace = []; state.step = 0; stopAutoplay();
    $("#outputPlaceholder").classList.remove("hidden");
    $("#outputResult").classList.add("hidden");
    $("#visualEmpty").classList.remove("hidden");
    $("#visualContent").classList.add("hidden");
    $("#stepCounter").textContent = "NO ACTIVE TRACE";
    $("#resetSteps").disabled = true;
    $("#errorMessage").textContent = "";
  }
  function validateSubKey(key) {
    const normalized = key.toUpperCase();
    if (!/^[A-Z]{26}$/.test(normalized)) return "Key must contain exactly 26 English letters.";
    if (new Set(normalized).size !== 26) return "Key must contain each letter exactly once (no duplicates).";
    return null;
  }

  // Rail Fence encryption: preserves spaces and punctuation as characters.
  function railEncrypt(text, rails) {
    const rows = Array.from({length: rails}, () => []);
    let rail = 0, direction = 1;
    const trace = [{description: `Prepare ${rails} rails. Characters will travel down and up in a zigzag pattern.`, rows: rows.map(r => [...r]), current: -1, output: ""}];
    for (let i = 0; i < text.length; i++) {
      rows[rail][i] = text[i];
      trace.push({description: `Place character "${text[i] === " " ? "SPACE" : text[i]}" (position ${i + 1}) on rail ${rail + 1}.`, rows: rows.map(r => [...r]), current: i, placedChar: text[i], output: ""});
      if (rail === 0) direction = 1;
      else if (rail === rails - 1) direction = -1;
      rail += direction;
    }
    const result = rows.map(row => row.filter(v => v !== undefined).join("")).join("");
    trace.push({description: "Read each rail from left to right, top to bottom. Concatenate the rows to produce the ciphertext.", rows: rows.map(r => [...r]), current: -1, output: result, final: true});
    return {result, trace};
  }

  function railDecrypt(cipher, rails) {
    const pattern = Array.from({length: cipher.length}, () => 0);
    let rail = 0, direction = 1;
    for (let i = 0; i < cipher.length; i++) {
      pattern[i] = rail;
      if (rail === 0) direction = 1;
      else if (rail === rails - 1) direction = -1;
      rail += direction;
    }
    const counts = Array.from({length: rails}, (_, r) => pattern.filter(x => x === r).length);
    const rows = []; let offset = 0;
    for (let r = 0; r < rails; r++) {
      rows[r] = cipher.slice(offset, offset + counts[r]).split("");
      offset += counts[r];
    }
    const trace = [{description: `Reconstruct the zigzag route for ${cipher.length} character positions across ${rails} rails.`, rows: rows.map(r => [...r]), current: -1, output: ""}];
    const cursors = Array(rails).fill(0), result = [];
    for (let i = 0; i < cipher.length; i++) {
      const r = pattern[i], ch = rows[r][cursors[r]++];
      result.push(ch);
      trace.push({description: `Read "${ch === " " ? "SPACE" : ch}" from rail ${r + 1} and place it at plaintext position ${i + 1}.`, rows: rows.map(row => [...row]), current: i, output: result.join("")});
    }
    const plain = result.join("");
    trace.push({description: "All characters have been read along the zigzag path. The original plaintext is reconstructed.", rows: rows.map(r => [...r]), current: -1, output: plain, final: true});
    return {result: plain, trace};
  }

  // Monoalphabetic substitution: non A-Z characters pass through unchanged.
  function substitution(text, key, mode) {
    const map = mode === "encrypt" ? key : alphabet;
    const source = mode === "encrypt" ? alphabet : key;
    let result = "";
    const trace = [{description: `Use the ${mode === "encrypt" ? "plaintext-to-key" : "key-to-plaintext"} mapping. Non-letter characters remain unchanged.`, text, current: -1, output: ""}];
    for (let i = 0; i < text.length; i++) {
      const ch = text[i], upper = ch.toUpperCase(), index = alphabet.indexOf(upper);
      let converted = ch;
      if (index !== -1) {
        const mapped = mode === "encrypt" ? map[index] : source.indexOf(upper) >= 0 ? alphabet[source.indexOf(upper)] : upper;
        converted = ch === upper ? mapped : mapped.toLowerCase();
      }
      result += converted;
      trace.push({description: index === -1 ? `Character "${ch === " " ? "SPACE" : ch}" is not an English letter, so it passes through unchanged.` : `Replace "${ch}" with "${converted}" using the substitution key (position ${index + 1}).`, text, current: i, output: result});
    }
    trace.push({description: "Every character has been processed. The output is ready.", text, current: -1, output: result, final: true});
    return {result, trace};
  }

  function execute() {
    const text = input.value;
    const error = $("#errorMessage");
    error.textContent = "";
    if (!text.length) { error.textContent = "Enter a message before executing the cipher."; return; }
    let operation;
    if (state.algorithm === "rail") {
      const rails = Number(railCount.value);
      if (rails < 2 || rails > 8) { error.textContent = "Choose between 2 and 8 rails."; return; }
      operation = state.mode === "encrypt" ? railEncrypt(text, rails) : railDecrypt(text, rails);
    } else {
      const key = subKey.value.toUpperCase();
      const keyError = validateSubKey(key);
      if (keyError) { error.textContent = keyError; log(keyError, "error"); return; }
      operation = substitution(text, key, state.mode);
    }
    state.output = operation.result; state.trace = operation.trace; state.step = 0;
    $("#outputPlaceholder").classList.add("hidden");
    $("#outputResult").classList.remove("hidden");
    $("#resultLabel").textContent = state.mode === "encrypt" ? "ENCRYPTED OUTPUT" : "DECRYPTED OUTPUT";
    $("#resultText").textContent = state.output;
    $("#resultStats").textContent = `${state.output.length} CHARACTERS`;
    $("#visualEmpty").classList.add("hidden");
    $("#visualContent").classList.remove("hidden");
    $("#resetSteps").disabled = false;
    renderStep();
    addHistory(text, state.output);
    log(`${state.mode.toUpperCase()} completed using ${state.algorithm === "rail" ? `Rail Fence (${railCount.value} rails)` : "Substitution cipher"}.`, "success");
    log(`Processed ${text.length} characters; output length ${state.output.length}.`);
  }

  function renderRailStage(step) {
    const rows = step.rows || [];
    const max = Math.max(1, ...rows.map(r => r.length));
    let html = '<div class="rail-grid">';
    rows.forEach((row, r) => {
      html += `<div class="rail-row"><span class="rail-label">RAIL ${r + 1}</span>`;
      for (let c = 0; c < max; c++) {
        const value = row[c];
        const active = value !== undefined && step.current >= 0 && value === state.trace[stepIndex()].placedChar;
        html += `<span class="rail-cell ${value === undefined ? "empty-cell" : ""} ${active ? "active-cell" : ""}">${value === undefined ? "·" : escapeHTML(value === " " ? "␠" : value)}</span>`;
      }
      html += '</div>';
    });
    html += '</div>';
    if (step.output) html += `<div class="rail-output">OUTPUT BUFFER<br><b>${escapeHTML(step.output)}</b></div>`;
    $("#visualStage").innerHTML = html;
  }
  function stepIndex() { return state.step; }
  function renderSubStage(step) {
    const key = subKey.value.toUpperCase();
    const current = step.current;
    let html = '<div class="mapping-table">';
    for (let i = 0; i < 26; i++) {
      const active = current >= 0 && alphabet.indexOf((step.text || "")[current]?.toUpperCase()) === i;
      html += `<div class="mapping-cell ${active ? "current" : ""}"><span class="from">${alphabet[i]}</span><span class="to">${key[i]}</span></div>`;
    }
    html += '</div>';
    html += `<div class="trace-string">INPUT&nbsp;&nbsp; ${renderTraceChars(step.text || "", current)}<br>OUTPUT ${escapeHTML(step.output || "…")}</div>`;
    $("#visualStage").innerHTML = html;
  }
  function renderTraceChars(text, current) {
    return [...text].map((ch, i) => `<span class="trace-char ${i === current ? "current" : ""}">${escapeHTML(ch === " " ? "␠" : ch)}</span>`).join("");
  }
  function renderStep() {
    const step = state.trace[state.step];
    if (!step) return;
    const total = state.trace.length;
    $("#stepCounter").textContent = `TRACE ${String(state.step + 1).padStart(2, "0")} / ${String(total).padStart(2, "0")}`;
    $("#stepNumber").textContent = `STEP ${String(state.step + 1).padStart(2, "0")}`;
    $("#stepDescription").textContent = step.description;
    $("#progressFill").style.width = `${((state.step + 1) / total) * 100}%`;
    $("#progressText").textContent = `${state.step + 1} / ${total}`;
    $("#prevStep").disabled = state.step === 0;
    $("#nextStep").disabled = state.step === total - 1;
    if (state.algorithm === "rail") renderRailStage(step); else renderSubStage(step);
  }
  function moveStep(delta) {
    const next = Math.max(0, Math.min(state.trace.length - 1, state.step + delta));
    state.step = next; renderStep();
    if (state.step === state.trace.length - 1) stopAutoplay();
  }
  function addHistory(source, result) {
    state.history.unshift({
      algorithm: state.algorithm === "rail" ? `RAIL FENCE · ${railCount.value} RAILS` : "SUBSTITUTION",
      mode: state.mode.toUpperCase(), source, result,
      time: new Date().toLocaleTimeString()
    });
    state.history = state.history.slice(0, 20);
    renderHistory();
  }
  function renderHistory() {
    const container = $("#historyList");
    if (!state.history.length) {
      container.innerHTML = '<div class="visual-empty"><span>◷</span><b>NO OPERATIONS YET</b><p>Your completed operations will be listed here.</p></div>'; return;
    }
    container.innerHTML = state.history.map(item => `<div class="history-entry"><div class="history-type">${item.mode}<br><span style="color:#718878">${escapeHTML(item.algorithm)}</span></div><div class="history-content">${escapeHTML(item.source)}<br><span style="color:var(--green)">→ ${escapeHTML(item.result)}</span></div><div class="history-time">${item.time}</div></div>`).join("");
  }
  function updateAlphabetPreview() {
    const key = subKey.value.toUpperCase();
    $("#alphabetPreview").innerHTML = alphabet.split("").map((ch, i) => `<span class="alpha-cell" title="${ch} maps to ${key[i] || "?"}">${ch}<br>${key[i] || "?"}</span>`).join("");
  }
  function randomSubKey() {
    const chars = alphabet.split("");
    for (let i = chars.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    subKey.value = chars.join(""); updateAlphabetPreview(); resetOutput(); toast("Random substitution key generated.");
    log("A new random substitution alphabet was generated.");
  }
  function analyzeFrequency() {
    const text = $("#frequencyInput").value;
    const letters = text.toUpperCase().match(/[A-Z]/g) || [];
    if (!letters.length) {
      $("#frequencyResults").innerHTML = '<div class="visual-empty"><span>!</span><b>NO LETTERS FOUND</b><p>Enter a message containing English letters.</p></div>'; return;
    }
    const counts = Object.fromEntries(alphabet.split("").map(c => [c, 0]));
    letters.forEach(c => counts[c]++);
    const max = Math.max(...Object.values(counts));
    const sorted = alphabet.split("").sort((a, b) => counts[b] - counts[a]);
    const html = `<div class="frequency-summary">ANALYZED ${letters.length} LETTERS · ${text.length} TOTAL CHARACTERS · ${new Set(letters).size} UNIQUE LETTERS</div><div class="frequency-bars">${sorted.map(ch => {
      const pct = counts[ch] / letters.length * 100;
      return `<div class="frequency-item"><div class="frequency-letter">${ch}</div><div class="frequency-count">${counts[ch]}</div><div class="frequency-track"><span style="width:${max ? counts[ch] / max * 100 : 0}%"></span></div><div class="frequency-percent">${pct.toFixed(1)}%</div></div>`;
    }).join("")}</div>`;
    $("#frequencyResults").innerHTML = html;
  }

  // Navigation
  $$(".nav-item").forEach(button => button.addEventListener("click", () => {
    const view = button.dataset.view;
    $$(".nav-item").forEach(b => b.classList.toggle("active", b === button));
    $$(".page-view").forEach(v => v.classList.toggle("active", v.id === `${view}-view`));
    $("#breadcrumb-current").textContent = view.toUpperCase();
  }));
  $$(".algorithm-tab[data-algorithm]").forEach(button => button.addEventListener("click", () => setAlgorithm(button.dataset.algorithm)));
  $$(".mode-button[data-mode]").forEach(button => button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    $$(".mode-button[data-mode]").forEach(b => b.classList.toggle("active", b === button));
    $("#resultLabel").textContent = state.mode === "encrypt" ? "ENCRYPTED OUTPUT" : "DECRYPTED OUTPUT";
    resetOutput();
  }));
  input.addEventListener("input", updateCount);
  railCount.addEventListener("input", () => $("#railValue").textContent = railCount.value);
  subKey.addEventListener("input", () => { subKey.value = subKey.value.toUpperCase().replace(/[^A-Z]/g, ""); updateAlphabetPreview(); });
  $("#randomKey").addEventListener("click", randomSubKey);
  $("#runCipher").addEventListener("click", execute);
  $("#clearInput").addEventListener("click", () => { input.value = ""; updateCount(); resetOutput(); });
  $("#copyOutput").addEventListener("click", async () => {
    if (!state.output) return;
    try { await navigator.clipboard.writeText(state.output); toast("Output copied to clipboard."); }
    catch { toast("Clipboard unavailable. Select and copy the output manually."); }
  });
  $("#prevStep").addEventListener("click", () => { stopAutoplay(); moveStep(-1); });
  $("#nextStep").addEventListener("click", () => { stopAutoplay(); moveStep(1); });
  $("#resetSteps").addEventListener("click", () => { stopAutoplay(); state.step = 0; renderStep(); });
  $("#playSteps").addEventListener("click", () => {
    if (state.autoplay) { stopAutoplay(); return; }
    if (state.step === state.trace.length - 1) state.step = 0;
    $("#playSteps").textContent = "Ⅱ PAUSE";
    renderStep();
    state.autoplay = setInterval(() => moveStep(1), 850);
  });
  $("#analyzeFrequency").addEventListener("click", analyzeFrequency);
  $("#clearHistory").addEventListener("click", () => { state.history = []; renderHistory(); toast("Session history cleared."); });

  // Shared UI helpers for the public-key modules (RSA / DSA).
  window.CipherLab = {
    escapeHTML, toast,
    addHistoryEntry(algorithm, mode, source, result) {
      state.history.unshift({algorithm, mode, source, result, time: new Date().toLocaleTimeString()});
      state.history = state.history.slice(0, 20);
      renderHistory();
    }
  };

  updateCount(); updateAlphabetPreview(); renderHistory();
  log("CipherLab engine initialized.");
  log("All processing takes place locally in this browser.");
})();