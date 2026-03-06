# QuantaCrypt

Post-quantum file encryption for macOS. Protect files with a password or split the key across multiple people — built on quantum-resistant cryptography so your data stays safe even as computing advances.

---

## Features

- **Quantum-resistant encryption** — ML-KEM (Kyber-768) key encapsulation + AES-256-GCM streaming for files of any size
- **Password or split-key protection** — encrypt with a single password, or split the key across multiple people so no one person can unlock the file alone (k-of-n threshold)
- **Plain-language interface** — no cryptographic jargon; progress messages, errors, and labels are written for everyday users
- **50-word recovery phrases** — split-key shares encoded as memorable word phrases for safe offline storage
- **Self-opening archives** — optionally embed the decryptor inside the `.qcx` file so recipients need no extra software
- **File inspector** — view encryption details (mode, format version, fingerprint) without needing the password
- **Password strength meter** — real-time feedback while typing, powered by zxcvbn pattern matching
- **Drag-and-drop** — drop files onto any window to encrypt or decrypt them instantly
- **macOS integration** — double-click `.qcx` files in Finder, custom document icon, DMG installer
- **Dark native UI** — Tkinter-based interface with keyboard shortcuts and a guided wizard flow
- **Cross-platform foundations** — core crypto works on macOS, Windows, and Linux; the UI is macOS-primary with platform-aware fallbacks

---

## Quick Start

```bash
# Install from source
pip install -e ".[dev]"

# Launch the app
python -m quantacrypt
```

> `tkinterdnd2` is optional — enables drag-and-drop. Everything works without it.
> `zxcvbn` is optional — enables the password strength estimator. A built-in fallback is used without it.

---

## How It Works

**Encrypting a file:**
1. Pick a file (or folder, or multiple files)
2. Choose **Single Password** or **Split Between People**
3. Set your password or configure how many people hold shares
4. Click **Encrypt File →** — the output is a `.qcx` file

**Decrypting a file:**
1. Open a `.qcx` file (or drag it onto the window)
2. Enter your password or paste the required number of shares
3. Click **Decrypt File →** — the original file is restored

**Split-key mode** works like a vault with multiple keys: you give each person a unique share, and only when enough people combine their shares can the file be unlocked. Quick presets (2-of-3, 3-of-5, 3-of-7) make configuration easy.

---

## Launch Modes

| Command | Result |
|---------|--------|
| `python -m quantacrypt` | Home screen (Encrypt or Decrypt) |
| `python -m quantacrypt myfile.qcx` | Opens that file directly in the decryptor |
| Double-click `myfile.qcx` in Finder | Opens in QuantaCrypt (after build + install) |
| `./myfile.qcx` *(after build + embed)* | Self-opening — runs its own decryptor |

---

## Project Structure

```
quantacrypt/
├── pyproject.toml
├── README.md
├── RELEASING.md                    # Release process and version management
├── .github/
│   └── workflows/
│       └── release.yml             # CI: test → build (arm64 + x86_64) → GitHub Release
├── src/
│   └── quantacrypt/
│       ├── __init__.py             # Package root, version, entry point
│       ├── __main__.py             # CLI entry point — launch mode detection
│       ├── core/
│       │   ├── __init__.py         # Re-exports key constants
│       │   └── crypto.py           # Cryptographic primitives (KEM, AES-GCM, Argon2id, Shamir)
│       ├── ui/
│       │   ├── __init__.py
│       │   ├── shared.py           # Design system and shared widgets
│       │   ├── launcher.py         # Home screen with recent files
│       │   ├── encryptor.py        # Encryption wizard
│       │   └── decryptor.py        # Decryption wizard with file inspector
│       └── assets/
│           ├── icon.png            # App icon
│           └── doc_icon.png        # .qcx document icon (Finder)
├── requirements.txt
├── tests/
│   ├── conftest.py                 # Shared fixtures and helpers
│   ├── test_crypto.py              # Crypto primitive tests
│   ├── test_gui_logic.py           # GUI validation / logic tests
│   └── test_integration.py         # Streaming, folder, batch tests
└── scripts/
    └── build.py                    # PyInstaller build + DMG creation
```

---

## Building the App

```bash
# Build for the current machine's architecture
python scripts/build.py

# Build for a specific architecture
python scripts/build.py --arch arm64
python scripts/build.py --arch x86_64

# Skip tests (if already run separately)
python scripts/build.py --arch arm64 --skip-tests
```

The build script runs the full test suite with coverage **before** compiling (unless `--skip-tests` is passed). If any test fails or coverage drops below the 90% threshold, the build aborts.

On success it produces two artifacts in `dist/`:

- **`quantacrypt.app`** — a self-contained macOS app bundle with `.qcx` file association and custom document icon
- **`quantacrypt-{arch}.dmg`** — a distributable disk image with drag-to-Applications layout (e.g. `quantacrypt-arm64.dmg`)

> **First launch:** macOS Gatekeeper will block unsigned apps. Right-click the `.app` → **Open**, or run:
> ```bash
> xattr -d com.apple.quarantine dist/quantacrypt.app
> ```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Coverage reports are generated automatically — a summary prints to the terminal and a detailed HTML report is written to `htmlcov/`.

```bash
open htmlcov/index.html
```

> Tests that import the Tkinter UI modules require a display environment. On headless systems, crypto and logic tests will still pass while UI-dependent tests are skipped.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+E` | Open Encryptor |
| `Ctrl+D` | Open Decryptor |
| `Ctrl+I` | Inspect a .qcx file |
| `Ctrl+O` | Browse for a file |
| `Ctrl+Return` | Start encryption / decryption |
| `Escape` | Close window |

---

## .qcx File Format

```
[ optional: embedded decryptor binary     ]  ← only when "self-opening" is ticked
[ encrypted payload chunks (AES-256-GCM)  ]  ← 4 MB chunks, each independently authenticated
[ MAGIC (6 bytes) + length (4 bytes) + JSON metadata tail ]
```

**Public metadata** (viewable via Inspect, no password needed): format version, encryption mode, password-hardening salt or public key, payload offset, file fingerprint.

**Encrypted metadata** (revealed only after decryption): original filename, file size, encryption timestamp, content SHA-256 hash (verified after decryption to confirm the output matches the original byte-for-byte).

---

## Security Overview

- **Key encapsulation:** ML-KEM / Kyber-768 (NIST post-quantum standard)
- **Symmetric encryption:** AES-256-GCM with 4 MB streaming chunks
- **Password hardening:** Argon2id with high memory/time cost
- **Split-key scheme:** Shamir secret sharing over the Mersenne prime M521
- **Share encoding:** BIP-39 compatible 50-word mnemonic phrases
- **Clipboard protection:** Auto-clears copied shares after 60 seconds

---

## License

MIT
