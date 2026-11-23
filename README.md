# CipherLab

An interactive cryptography simulator: Rail Fence, Monoalphabetic Substitution and RSA.

## Run locally

CipherLab is a static site with no dependencies and no build step. Open `index.html` in a modern browser.

You can also serve the folder from a local static server, for example `npx serve` or `python -m http.server`, and open the `http://localhost` address it prints.

RSA uses the browser's Web Crypto API, which only works in a secure context: `https://`, `http://localhost` or a local `file://` page.

## Modules

| Algorithm | Engine | Notes |
|---|---|---|
| Rail Fence | Browser JS | Transposition cipher |
| Substitution | Browser JS | Monoalphabetic cipher |
| RSA | Web Crypto API (browser) | RSA-OAEP, SHA-256, 2048/3072-bit, e = 65537 |

The RSA step-by-step walkthrough uses small textbook numbers so you can follow the maths. It is kept separate from the secure RSA-OAEP engine and is never used to protect real data.
