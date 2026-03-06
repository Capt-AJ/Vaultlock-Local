# VaultLock Local

A fully client-side, encrypted password vault designed for Chromium-based browsers (Chrome, Edge, Brave). All data is stored locally in the browser's extension storage and protected using the Web Crypto API. No server or cloud sync is involved; the vault is accessible only after unlocking with a master password.

## Features

- **Master password & lock screen**
  - First-time setup or unlock on subsequent uses.
  - Master password is never stored, lost passwords cannot be recovered.
  - Lock button clears memory and returns to unlock view.

- **Vault entries**
  - Each entry: unique ID, site, username, password, optional notes, timestamps.
  - Add, edit, delete entries. Search by site/username in popup.

- **Password generator**
  - Customizable options (length, lowercase, uppercase, digits, symbols).
  - Generated password can be inserted into entry form or copied.

- **Strength indicator**
  - Real-time feedback while typing a password.
  - Bar and label show Very Weak → Very Strong.

- **Clipboard management**
  - Copy password to clipboard with visual confirmation.
  - Clipboard auto-clears after 10 seconds.

- **Autofill support**
  - Content script fills compatible login forms when requested from the popup.
  - Dispatches native input/change events for compatibility.

## Security & Crypto

- Uses PBKDF2 (SHA-256, 310k iterations, 16-byte salt stored in base64).
- The master password is converted into a `CryptoKey`; the raw string is wiped immediately.
- AES-GCM 256-bit encryption of the vault JSON (IV concatenated and encoded).
- Cryptographic helpers expose both password‑based and key‑based APIs to minimise
  exposure of secrets.
- Salt is persisted once; all key derivation uses the same random salt.
- Clipboard contents are cleared automatically after 10 seconds.
- Content Security Policy restricts the popup to `self` and disallows inline scripts.
- Host permissions and content script patterns are limited to HTTP/S origins.
- Auto‑lock timer logs the user out after 5 minutes of inactivity or when the
  popup loses focus or visibility.
- All cryptographic operations use `crypto.subtle` in the Web Crypto API.
- Master password only resides in memory briefly; it is never stored or sent
  anywhere.
- Security limitations are documented in comments within the source.

## Project Structure
```
password-manager-extension/
├── manifest.json          # Chromium extension manifest
├── service-worker.js      # Background/service worker logic
├── panel.html             # Popup UI (renamed from "popup")
├── panel-controller.js    # UI & vault interaction logic
├── page-autofill.js       # Content script for autofill
├── vault-crypto.js        # Web Crypto helper functions (KDF, AES-GCM)
├── vault-repository.js    # Storage wrapper (vault + salt management)
├── panel.css              # Styles for the popup UI
└── icons/
    ├── vault-16.png
    ├── vault-48.png
    └── vault-128.png
```

## Installation
1. Open `chrome://extensions` (or equivalent in Edge/Brave).
2. Enable "Developer mode".
3. Click "Load unpacked" and select this `password-manager-extension` folder.
4. Click the toolbar icon to open the vault.

## Development Notes
- The extension avoids external dependencies; all code is vanilla JavaScript.
- To modify styles, edit `panel.css` and reload the extension.
- JS logic is modular; cryptography is in `vault-crypto.js` and storage in `vault-repository.js`.
- The manifest declares minimal permissions: `storage`, `activeTab`, `scripting`, `clipboardWrite`.

## Limitations
- No synchronization across devices; vault remains local to the browser profile.
- If the master password is forgotten or the vault file becomes corrupted, data is lost.
- Security relies on the integrity of the browser and device; malware/keyloggers can compromise secrets.

## License
Licensed under MIT. Use at your own risk.
