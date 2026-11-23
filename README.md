# CipherLab

An interactive cryptography simulator: Rail Fence, Monoalphabetic Substitution, RSA and DSA.

## Run locally

Requires Node.js 18 or newer. No `npm install` step: there are no dependencies.

```
npm start
```

Then open http://localhost:3000.

You can still open `index.html` straight from disk (`file://`). Rail Fence, Substitution and RSA all work that way. DSA does not, because it needs the local engine started by `npm start`. Without it, the DSA module shows **ENGINE: OFFLINE**.

## Modules

| Algorithm | Engine | Notes |
|---|---|---|
| Rail Fence | Browser JS | Unchanged |
| Substitution | Browser JS | Unchanged |
| RSA | Web Crypto API (browser) | RSA-OAEP, SHA-256, 2048/3072-bit, e = 65537 |
| DSA | Node `crypto` / OpenSSL via `server.js` | FIPS 186 (L, N) = 2048/224, 2048/256, 3072/256, SHA-256 |

Browsers' Web Crypto API does not implement DSA, so the DSA work runs on a small local server built on Node's built-in OpenSSL bindings. ECDSA and RSA are never used as substitutes. The server listens only on 127.0.0.1 and never logs or stores key material.

Both step-by-step walkthroughs use small textbook numbers so you can follow the maths. They are kept separate from the secure engines and are never used to protect real data.
