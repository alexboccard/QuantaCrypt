# QuantaCrypt

Post-quantum file encryption for macOS using ML-KEM (Kyber-768) + AES-256-GCM, with optional Shamir secret sharing.

---

## Features

- **Post-quantum encryption** — ML-KEM / Kyber-768 key encapsulation + Argon2id password hashing
- **AES-256-GCM streaming** — constant-memory encryption for files of any size (up to 50 GB)
- **Shamir secret sharing** — split encryption keys across multiple people (k-of-n threshold)
- **Self-executing archives** — embed the decryptor inside the `.qcx` file so recipients need no extra software
- **BIP-39 mnemonic shares** — Shamir shares encoded as 50-word phrases for safe offline storage
- **Dark native UI** — Tkinter-based interface with drag-and-drop support

---

## Project Structure

| File | Purpose |
|------|---------|
| `quantacrypt.py` | Entry point — handles all three launch modes |
| `crypto_core.py` | Cryptographic primitives (KEM, AES-GCM, Argon2id, Shamir) |
| `encryptor.py` | Encryption GUI |
| `decryptor.py` | Decryption GUI |
| `shared_ui.py` | Design system and shared widgets |
| `launcher.py` | Home screen |
| `build.py` | PyInstaller build script — produces a `.app` bundle |
| `test_quantacrypt.py` | Test suite (crypto + integration) |

---

## Prerequisites

Python 3.10+ and the required packages:

```bash
pip install -r requirements.txt
```

> `tkinterdnd2` is optional — enables drag-and-drop. Everything works without it.
> `zxcvbn` is optional — enables the password strength estimator. A built-in fallback is used without it.

---

## Running from Source

```bash
python quantacrypt.py
```

**Launch modes:**

| Command | Result |
|---------|--------|
| `python quantacrypt.py` | Home screen (Encrypt or Decrypt) |
| `python quantacrypt.py myfile.qcx` | Opens that file directly in the decryptor |
| `./myfile.qcx` *(after build + embed)* | Self-executing — opens its own decryptor |

---

## Building the App

```bash
python build.py
```

Produces `dist/quantacrypt.app` — a fully self-contained macOS app bundle. No Python installation or companion files required.

> **First launch:** macOS Gatekeeper will block unsigned apps. Right-click the `.app` → **Open**, or run:
> ```bash
> xattr -d com.apple.quarantine dist/quantacrypt.app
> ```

---

## Running Tests

```bash
python -m pytest test_quantacrypt.py -v
```

---

## .qcx File Format

```
[ optional: embedded decryptor binary     ]  ← only when "Embed decryptor" is ticked
[ encrypted payload chunks (AES-256-GCM)  ]  ← 4 MB chunks, each independently authenticated
[ MAGIC (8 bytes) + length (4 bytes) + JSON metadata tail ]
```

**Unencrypted metadata** (safe to inspect without credentials): format version, encryption mode, Argon2id salt or KEM public key, payload offset.

**Encrypted metadata** (inside payload): original filename, file size, encryption timestamp.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+E` | Open Encryptor |
| `Ctrl+D` | Open Decryptor |
| `Ctrl+I` | Inspect a .qcx file |
| `Ctrl+O` | Browse for source file (Encryptor) |
| `Ctrl+Return` | Start encryption / decryption |
| `Escape` | Close window |

---

## License

MIT
