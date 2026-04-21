# Design Doc: Encrypted Volumes (.qcv)

**Status:** Implemented (Phase 4 complete)
**Date:** 2026-03-17
**Author:** Alex + Claude

## Problem

QuantaCrypt encrypts individual files as `.qcx` containers, but users need a way to work with multiple files transparently — editing, adding, and removing files without manually encrypting/decrypting each one. The goal is a virtual encrypted drive that mounts as a real folder on macOS/Linux.

## Options Considered

### Option A: Monolithic encrypted disk image
Encrypt a single large blob (like a `.dmg` or LUKS volume). Simple, but: no file-level granularity, entire image must be re-encrypted on any change, no partial sync possible.

### Option B: File-level encryption inside a container (Cryptomator-style)
Each file encrypted independently within a structured container. Random-access reads/writes. Only changed files need re-encryption. Directory index tracks the tree structure.

### Option C: Overlay filesystem with encrypted backing store
Use OverlayFS or similar with an encrypted lower layer. Complex kernel dependencies, poor portability.

## Decision

**Option B** — file-level encryption inside a `.qcv` container, mounted via FUSE.

Rationale:
- Per-file encryption means small edits don't re-encrypt the whole volume
- FUSE provides real filesystem semantics without kernel modules (FUSE-T on macOS is kext-free)
- Container format is portable (single file, self-contained)
- Aligns with existing AES-256-GCM + ML-KEM crypto stack

## Container Format

```
[Header — 512 bytes]           MAGIC "QCVOL\x01" + FORMAT_VERSION + VOLUME_ID + nonces
[Auth Params — cleartext JSON] Mode, Argon2 salt, KEM ciphertext (needed to derive key)
[Encrypted Metadata — AES-GCM] Mode, chunk_size, created_at, argon2 params
[Encrypted Directory Index]    JSON tree: { "/path": { inode, size, mode, mtime, nonce, hash } }
[File Data Section]            Per-file chunked AES-GCM (64KB chunks)
```

### Key decisions within the format:
- **Auth params are unencrypted** — they contain only public-key-like fields (Argon2 salt, KEM ciphertext) needed to derive the key. No secrets exposed.
- **64KB chunk size** (vs 4MB for .qcx) — optimized for random-access FUSE reads. Smaller chunks = less wasted I/O for small reads.
- **Per-file nonces** — each file gets a random `base_nonce`; chunks use `nonce XOR chunk_index` to avoid nonce reuse.
- **LRU cache** (default 100MB) for decrypted file data in FUSE layer.

## Architecture

Three new core modules:

| Module | Responsibility |
|--------|---------------|
| `core/volume.py` | Volume container: create, open, read/write files, directory index, metadata, atomic saves |
| `core/fuse_ops.py` | FUSE filesystem operations (`QuantaCryptFUSE`), mount/unmount API, cache management |
| `ui/volume_manager.py` | Volume creation wizard + mount/unmount panel in Tkinter |

### Safety mechanisms:
- **Double-mount prevention** — checks if volume is already mounted before allowing mount
- **Hash verification** — SHA-256 hash per file for integrity checking
- **Corrupt volume handling** — graceful errors instead of crashes on malformed containers
- **Disk-full safe saves** — atomic write to `.tmp` then `os.replace()` for crash safety
- **Graceful shutdown** — `atexit` + signal handlers unmount all volumes on app exit

## Trade-offs

| Trade-off | Decision | Rationale |
|-----------|----------|-----------|
| Chunk size | 64KB (not 4MB like .qcx) | FUSE random-access performance matters more than throughput |
| Cache size | 100MB LRU default | Balance between memory use and read performance |
| FUSE dependency | Required for mount, optional install | Can't avoid external dep for filesystem mounting; app detects and guides user |
| Auth params in cleartext | Yes | Required to derive key without already having key; contains no secrets |

## Testing

- 283 tests passing (volume crypto, FUSE ops, auth params, graceful shutdown, edge cases)
- Coverage: 97% on `core/` modules
- All crypto uses `secrets.token_bytes()` per project convention
