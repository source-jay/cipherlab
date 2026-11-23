/* CipherLab — local static server + DSA engine
 *
 * Browsers' Web Crypto API does not implement DSA, so DSA key generation,
 * signing and verification run here using Node's built-in `crypto` module
 * (OpenSSL). No third-party dependencies are required.
 *
 * The server binds to 127.0.0.1 only. Key material is never logged or stored.
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const MAX_BODY = 64 * 1024;

// FIPS 186-4 approved (L, N) pairs. (1024, 160) is legacy-only and excluded.
const DSA_PARAMETER_SETS = {
  "2048-224": { modulusLength: 2048, divisorLength: 224 },
  "2048-256": { modulusLength: 2048, divisorLength: 256 },
  "3072-256": { modulusLength: 3072, divisorLength: 256 }
};

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".md": "text/plain; charset=utf-8"
};
// Only these top-level paths are served as static files.
const STATIC_ALLOW = [/^\/index\.html$/, /^\/css\/[\w.-]+\.css$/, /^\/js\/[\w./-]+\.js$/];

class ClientError extends Error {}

function sendJSON(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(body);
}

function readJSON(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", chunk => {
      size += chunk.length;
      if (size > MAX_BODY) { reject(new ClientError("Request body too large.")); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); }
      catch { reject(new ClientError("Request body must be valid JSON.")); }
    });
    req.on("error", reject);
  });
}

function requireString(value, name, { allowEmpty = false } = {}) {
  if (typeof value !== "string") throw new ClientError(`${name} must be a string.`);
  if (!allowEmpty && !value.trim()) throw new ClientError(`${name} is required.`);
  return value;
}

function loadDsaKey(pem, kind) {
  let key;
  try {
    key = kind === "private" ? crypto.createPrivateKey(pem) : crypto.createPublicKey(pem);
  } catch {
    throw new ClientError(`Could not parse the ${kind} key. Paste a PEM-encoded DSA ${kind} key.`);
  }
  // Never silently accept RSA/EC keys while labelling the operation DSA.
  if (key.asymmetricKeyType !== "dsa") {
    throw new ClientError(`The supplied ${kind} key is ${String(key.asymmetricKeyType).toUpperCase()}, not DSA.`);
  }
  return key;
}

function keyDetails(key) {
  const d = key.asymmetricKeyDetails || {};
  return { L: d.modulusLength, N: d.divisorLength };
}

// Decode a DER `SEQUENCE { INTEGER r, INTEGER s }` DSA signature.
function decodeDerSignature(der) {
  let i = 0;
  const readLen = () => {
    let len = der[i++];
    if (len & 0x80) {
      const bytes = len & 0x7f;
      if (bytes < 1 || bytes > 2) throw new Error("bad length");
      len = 0;
      for (let b = 0; b < bytes; b++) len = (len << 8) | der[i++];
    }
    return len;
  };
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error("expected INTEGER");
    const len = readLen();
    if (len < 1 || i + len > der.length) throw new Error("bad INTEGER");
    const value = der.subarray(i, i + len);
    i += len;
    return BigInt("0x" + (Buffer.from(value).toString("hex") || "0"));
  };
  if (der[i++] !== 0x30) throw new Error("expected SEQUENCE");
  const seqLen = readLen();
  if (i + seqLen !== der.length) throw new Error("trailing data");
  const r = readInt(), s = readInt();
  if (i !== der.length) throw new Error("trailing data");
  return { r, s };
}

const api = {
  "GET /api/dsa/status": async () => ({
    online: true,
    engine: "Node.js crypto (OpenSSL)",
    node: process.versions.node,
    openssl: process.versions.openssl,
    parameterSets: Object.keys(DSA_PARAMETER_SETS)
  }),

  "POST /api/dsa/generate": async body => {
    const set = DSA_PARAMETER_SETS[body.parameters];
    if (!set) throw new ClientError("Unsupported DSA parameter set. Choose 2048-224, 2048-256 or 3072-256.");
    const started = Date.now();
    const { publicKey, privateKey } = await new Promise((resolve, reject) =>
      crypto.generateKeyPair("dsa", {
        ...set,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" }
      }, (err, pub, priv) => err ? reject(err) : resolve({ publicKey: pub, privateKey: priv }))
    );
    return { publicKey, privateKey, L: set.modulusLength, N: set.divisorLength, ms: Date.now() - started };
  },

  "POST /api/dsa/sign": async body => {
    const message = requireString(body.message, "Message");
    const key = loadDsaKey(requireString(body.privateKey, "Private key"), "private");
    const data = Buffer.from(message, "utf8");
    // OpenSSL draws a fresh, secret per-message nonce k for every signature.
    const signature = crypto.sign("sha256", data, { key, dsaEncoding: "der" });
    const { r, s } = decodeDerSignature(signature);
    return {
      signature: signature.toString("base64"),
      r: r.toString(16),
      s: s.toString(16),
      hash: crypto.createHash("sha256").update(data).digest("hex"),
      ...keyDetails(key)
    };
  },

  "POST /api/dsa/verify": async body => {
    const message = requireString(body.message, "Message", { allowEmpty: true });
    const signatureB64 = requireString(body.signature, "Signature").replace(/\s+/g, "");
    const key = loadDsaKey(requireString(body.publicKey, "Public key"), "public");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureB64) || signatureB64.length % 4 !== 0) {
      return { valid: false, reason: "Signature is not valid Base64." };
    }
    const signature = Buffer.from(signatureB64, "base64");
    try { decodeDerSignature(signature); }
    catch { return { valid: false, reason: "Signature is not a well-formed DER (r, s) structure." }; }
    let valid = false;
    try { valid = crypto.verify("sha256", Buffer.from(message, "utf8"), { key, dsaEncoding: "der" }, signature); }
    catch { valid = false; }
    return {
      valid,
      reason: valid ? "Signature matches the message and public key." :
        "Signature does not match this message and public key.",
      hash: crypto.createHash("sha256").update(message, "utf8").digest("hex"),
      ...keyDetails(key)
    };
  }
};

function serveStatic(req, res, pathname) {
  if (pathname === "/") pathname = "/index.html";
  if (!STATIC_ALLOW.some(rx => rx.test(pathname)) || pathname.includes("..")) {
    res.writeHead(404, { "Content-Type": "text/plain" }); res.end("Not found"); return;
  }
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT + path.sep)) { res.writeHead(403); res.end(); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain" }); res.end("Not found"); return; }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-cache"
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname); }
  catch { res.writeHead(400); res.end(); return; }

  if (pathname.startsWith("/api/")) {
    const handler = api[`${req.method} ${pathname}`];
    if (!handler) { sendJSON(res, 404, { error: "Unknown endpoint." }); return; }
    if (req.method === "POST" && !/^application\/json/i.test(req.headers["content-type"] || "")) {
      sendJSON(res, 415, { error: "Content-Type must be application/json." }); return;
    }
    try {
      const body = req.method === "POST" ? await readJSON(req) : {};
      sendJSON(res, 200, await handler(body || {}));
    } catch (err) {
      // Never echo request bodies (which may contain private keys) into logs.
      if (err instanceof ClientError) sendJSON(res, 400, { error: err.message });
      else { console.error(`[DSA] ${req.method} ${pathname} failed: ${err.code || err.name}`); sendJSON(res, 500, { error: "Internal cryptographic engine error." }); }
    }
    return;
  }
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405); res.end(); return; }
  serveStatic(req, res, pathname);
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`CipherLab running at http://${HOST === "127.0.0.1" ? "localhost" : HOST}:${PORT}`);
    console.log(`DSA engine: Node ${process.versions.node} / OpenSSL ${process.versions.openssl}`);
  });
}

module.exports = { server, decodeDerSignature };
