"""QuantaCrypt Encrypted Volume (.qcv) — file-level encrypted container.

A .qcv file stores an encrypted virtual filesystem that can be mounted
as a macOS volume via FUSE.  Files inside the volume are individually
encrypted with chunked AES-256-GCM using the same key derivation as .qcx
(Argon2id + Kyber-768 → 512-bit final key).

Container layout:
  [Header 512B] [Auth Params (cleartext JSON)] [Encrypted Metadata]
  [Encrypted Directory Index] [File Data ...]

Auth Params are stored unencrypted so that the key can be derived from
a password or Shamir shares without already having the key.  They contain
only public-key-like fields (Argon2 salt, KEM ciphertext, encrypted SK)
that do not reveal the plaintext key.

File data uses the same chunked wire format as .qcx:
  [seq:4B][ct_len:4B][ciphertext+16B_tag] per chunk

The directory index maps virtual paths to their encrypted data offsets,
nonces, sizes, and content hashes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import time
import uuid
from typing import IO, Any, Callable

from quantacrypt.core.crypto import (
    KEY_BYTES,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    CHUNK_SIZE,
    SHAMIR_PRIME,
    argon2id_derive,
    kyber_keygen,
    kyber_encaps,
    kyber_decaps,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    expand_kem_ss,
    xor_bytes,
    derive_aes_key,
    shamir_split,
    shamir_recover,
    encode_share,
    decode_share,
    _meta_hmac,
    _verify_meta_hmac,
    _chunk_nonce,
    _chunk_aad,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Volume constants ────────────────────────────────────────────────────────

VOLUME_MAGIC = b"QCVOL\x01"
VOLUME_FORMAT_VERSION = 1
HEADER_SIZE = 512

# Volume uses smaller chunks than .qcx for better random-access performance.
# 64 KB balances GCM overhead (~0.025%) against seek granularity.
VOLUME_CHUNK_SIZE = 64 * 1024  # 64 KB

# Offsets within the 512-byte header
_OFF_MAGIC     = 0    # 6 bytes
_OFF_VERSION   = 6    # 4 bytes (uint32 BE)
_OFF_VOL_ID    = 10   # 16 bytes (UUID)
_OFF_META_NONCE = 26  # 12 bytes
_OFF_DIR_NONCE  = 38  # 12 bytes
_OFF_RESERVED   = 50  # 462 bytes padding


# ── Header I/O ──────────────────────────────────────────────────────────────

def write_header(
    f: IO[bytes],
    volume_id: bytes,
    meta_nonce: bytes,
    dir_nonce: bytes,
) -> None:
    """Write a 512-byte .qcv header at the current file position."""
    header = bytearray(HEADER_SIZE)
    header[_OFF_MAGIC:_OFF_MAGIC + 6] = VOLUME_MAGIC
    struct.pack_into(">I", header, _OFF_VERSION, VOLUME_FORMAT_VERSION)
    header[_OFF_VOL_ID:_OFF_VOL_ID + 16] = volume_id
    header[_OFF_META_NONCE:_OFF_META_NONCE + 12] = meta_nonce
    header[_OFF_DIR_NONCE:_OFF_DIR_NONCE + 12] = dir_nonce
    f.write(bytes(header))


def read_header(f: IO[bytes]) -> dict:
    """Read and validate a 512-byte .qcv header. Returns parsed fields."""
    raw = f.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise ValueError("File too small to be a valid .qcv volume")

    magic = raw[_OFF_MAGIC:_OFF_MAGIC + 6]
    if magic != VOLUME_MAGIC:
        raise ValueError(
            f"Not a QuantaCrypt volume (bad magic: {magic!r})"
        )

    version = struct.unpack_from(">I", raw, _OFF_VERSION)[0]
    if version < 1 or version > VOLUME_FORMAT_VERSION:
        raise ValueError(
            f"Unsupported volume format version {version} "
            f"(this app supports up to {VOLUME_FORMAT_VERSION})"
        )

    return {
        "version": version,
        "volume_id": raw[_OFF_VOL_ID:_OFF_VOL_ID + 16],
        "meta_nonce": raw[_OFF_META_NONCE:_OFF_META_NONCE + 12],
        "dir_nonce": raw[_OFF_DIR_NONCE:_OFF_DIR_NONCE + 12],
    }


# ── Auth params (unencrypted) ──────────────────────────────────────────────
# Stored as [len:4B][JSON] immediately after the header.  This block holds
# the parameters needed to derive the final key from a password or shares.

def _write_auth_params(f: IO[bytes], auth_params: dict) -> int:
    """Write cleartext auth params block.  Returns bytes written."""
    payload = json.dumps(auth_params, sort_keys=True, separators=(",", ":")).encode()
    f.write(struct.pack(">I", len(payload)))
    f.write(payload)
    return 4 + len(payload)


def _read_auth_params(f: IO[bytes]) -> dict:
    """Read cleartext auth params block from current position."""
    raw_len = f.read(4)
    if len(raw_len) < 4:
        raise ValueError("Unexpected end of volume file reading auth params length")
    payload_len = struct.unpack(">I", raw_len)[0]
    payload = f.read(payload_len)
    if len(payload) < payload_len:
        raise ValueError("Unexpected end of volume file reading auth params data")
    return json.loads(payload)


def read_volume_auth_params(path: str) -> tuple[dict, dict]:
    """Read header and auth params from a .qcv file without needing the key.

    Returns (header_dict, auth_params_dict).
    This is the entry point for mounting: read auth params → derive key → open.
    """
    with open(path, "rb") as f:
        header = read_header(f)
        auth_params = _read_auth_params(f)
    return header, auth_params


# ── Metadata block ──────────────────────────────────────────────────────────

def _write_encrypted_block(f: IO[bytes], ciphertext: bytes) -> int:
    """Write [ct_len:4B][ciphertext] and return bytes written."""
    f.write(struct.pack(">I", len(ciphertext)))
    f.write(ciphertext)
    return 4 + len(ciphertext)


def _read_encrypted_block(f: IO[bytes]) -> bytes:
    """Read [ct_len:4B][ciphertext] from current position."""
    raw_len = f.read(4)
    if len(raw_len) < 4:
        raise ValueError("Unexpected end of volume file reading block length")
    ct_len = struct.unpack(">I", raw_len)[0]
    ct = f.read(ct_len)
    if len(ct) < ct_len:
        raise ValueError("Unexpected end of volume file reading block data")
    return ct


def encrypt_metadata(final_key: bytes, metadata: dict) -> tuple[bytes, bytes]:
    """Encrypt volume metadata dict. Returns (nonce, ciphertext_with_tag)."""
    plaintext = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return aes_gcm_encrypt(final_key, plaintext)


def decrypt_metadata(final_key: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    """Decrypt volume metadata. Returns dict."""
    plaintext = aes_gcm_decrypt(final_key, nonce, ciphertext)
    return json.loads(plaintext)


# ── Directory index ─────────────────────────────────────────────────────────

def encrypt_directory(final_key: bytes, dir_index: dict) -> tuple[bytes, bytes]:
    """Encrypt the directory index. Returns (nonce, ciphertext_with_tag)."""
    plaintext = json.dumps(dir_index, sort_keys=True, separators=(",", ":")).encode()
    return aes_gcm_encrypt(final_key, plaintext)


def decrypt_directory(final_key: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    """Decrypt the directory index. Returns dict."""
    plaintext = aes_gcm_decrypt(final_key, nonce, ciphertext)
    return json.loads(plaintext)


# ── Per-file chunk encryption (for volume data section) ─────────────────────

def encrypt_file_data(
    data: bytes,
    final_key: bytes,
    chunk_size: int = VOLUME_CHUNK_SIZE,
) -> tuple[bytes, bytes, int, str]:
    """Encrypt file data into chunked AES-GCM format (in memory).

    Returns (base_nonce, encrypted_blob, chunk_count, sha256_hex).
    The blob uses the same wire format as .qcx streaming:
      [seq:4B][ct_len:4B][ct+tag] per chunk.
    """
    base_nonce = secrets.token_bytes(12)
    aes_key = derive_aes_key(final_key)
    cipher = AESGCM(aes_key)
    content_hash = hashlib.sha256(data)
    chunks = []
    chunk_count = 0
    offset = 0

    while offset < len(data) or chunk_count == 0:
        chunk_data = data[offset:offset + chunk_size]
        is_last = (offset + chunk_size >= len(data))
        nonce = _chunk_nonce(base_nonce, chunk_count)
        aad = _chunk_aad(chunk_count, is_last)
        ct = cipher.encrypt(nonce, chunk_data, aad)
        chunks.append(
            struct.pack(">I", chunk_count)
            + struct.pack(">I", len(ct))
            + ct
        )
        chunk_count += 1
        offset += chunk_size
        if is_last:
            break

    blob = b"".join(chunks)
    return base_nonce, blob, chunk_count, content_hash.hexdigest()


def decrypt_file_data(
    blob: bytes,
    final_key: bytes,
    base_nonce: bytes,
    chunk_count: int,
) -> bytes:
    """Decrypt chunked AES-GCM file data from a blob.

    Returns the plaintext bytes.
    """
    aes_key = derive_aes_key(final_key)
    cipher = AESGCM(aes_key)
    plaintext_parts = []
    pos = 0

    for i in range(chunk_count):
        is_last = (i == chunk_count - 1)
        if pos + 8 > len(blob):
            raise ValueError("File data truncated — missing chunk header")
        seq = struct.unpack_from(">I", blob, pos)[0]
        if seq != i:
            raise ValueError(f"Chunk sequence mismatch at {i} (got {seq})")
        ct_len = struct.unpack_from(">I", blob, pos + 4)[0]
        pos += 8
        if pos + ct_len > len(blob):
            raise ValueError("File data truncated — incomplete chunk")
        ct = blob[pos:pos + ct_len]
        pos += ct_len

        nonce = _chunk_nonce(base_nonce, i)
        aad = _chunk_aad(i, is_last)
        try:
            plain = cipher.decrypt(nonce, ct, aad)
        except Exception:
            raise ValueError(
                f"Authentication failed on chunk {i} — "
                "data may be corrupt or the wrong key was used"
            )
        plaintext_parts.append(plain)

    return b"".join(plaintext_parts)


# ── Key derivation for volumes ──────────────────────────────────────────────
# Reuses the exact same scheme as .qcx files.

def derive_volume_key_single(password: str, meta: dict) -> bytes:
    """Derive the final key for a password-protected volume.

    Expects meta to contain: argon_salt, kyber_kem_ct, kyber_sk_enc_nonce,
    kyber_sk_enc (all base64-encoded).
    """
    def d64(k): return base64.b64decode(meta[k])

    argon_key = argon2id_derive(password.encode(), d64("argon_salt"))
    sk = aes_gcm_decrypt(argon_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
    kem_ss = kyber_decaps(sk, d64("kyber_kem_ct"))
    return xor_bytes(argon_key, kem_ss)


def derive_volume_key_shamir(share_strings: list[str], meta: dict) -> bytes:
    """Derive the final key for a Shamir-protected volume.

    Expects meta to contain: kyber_kem_ct, kyber_sk_enc_nonce, kyber_sk_enc
    (all base64-encoded).
    """
    def d64(k): return base64.b64decode(meta[k])

    share_dicts = [decode_share(s) for s in share_strings]
    master_key = shamir_recover(share_dicts)
    sk = aes_gcm_decrypt(master_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
    kem_ss = kyber_decaps(sk, d64("kyber_kem_ct"))
    return xor_bytes(master_key, kem_ss)


# ── Volume creation ─────────────────────────────────────────────────────────

def create_volume_single(
    path: str,
    password: str,
    progress_cb: Callable[[str], None] | None = None,
) -> dict:
    """Create an empty .qcv volume protected by a password.

    Returns the volume metadata dict.
    """
    def _p(m):
        if progress_cb:
            progress_cb(m)

    _p("Deriving 512-bit password key (Argon2id)...")
    argon_salt = secrets.token_bytes(32)
    argon_key = argon2id_derive(password.encode(), argon_salt)

    _p("Generating Kyber-768 keypair...")
    pk, sk = kyber_keygen()

    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk)
    final_key = xor_bytes(argon_key, kem_ss)

    _p("Encrypting Kyber private key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(argon_key, sk)

    # Build metadata
    def b64(b): return base64.b64encode(b).decode()
    volume_id = uuid.uuid4().bytes

    auth_fields = {
        "argon_salt":         b64(argon_salt),
        "kyber_kem_ct":       b64(kem_ct),
        "kyber_sk_enc_nonce": b64(sk_nonce),
        "kyber_sk_enc":       b64(sk_ct),
    }

    # Auth params stored unencrypted so mounting can derive the key
    auth_params = {
        "mode": "single",
        **auth_fields,
    }

    metadata = {
        "format_version": VOLUME_FORMAT_VERSION,
        "mode": "single",
        "key_bits": 512,
        "chunk_size": VOLUME_CHUNK_SIZE,
        "created_at": int(time.time()),
        **auth_fields,
    }
    metadata["hmac"] = _meta_hmac(final_key, auth_fields)

    # Empty directory
    dir_index: dict[str, Any] = {}

    # Encrypt metadata and directory
    meta_nonce, meta_ct = encrypt_metadata(final_key, metadata)
    dir_nonce, dir_ct = encrypt_directory(final_key, dir_index)

    _p("Writing volume container...")
    with open(path, "wb") as f:
        write_header(f, volume_id, meta_nonce, dir_nonce)
        _write_auth_params(f, auth_params)
        _write_encrypted_block(f, meta_ct)
        _write_encrypted_block(f, dir_ct)

    _p("Volume created.")
    return metadata


def create_volume_shamir(
    path: str,
    n: int,
    k: int,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[dict, list[str]]:
    """Create an empty .qcv volume protected by Shamir secret sharing.

    Returns (metadata_dict, share_strings).
    """
    def _p(m):
        if progress_cb:
            progress_cb(m)

    _p("Generating 512-bit random master key...")
    master_key = secrets.token_bytes(KEY_BYTES)

    _p("Generating Kyber-768 keypair...")
    pk, sk = kyber_keygen()

    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk)
    final_key = xor_bytes(master_key, kem_ss)

    _p("Encrypting Kyber private key under master key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(master_key, sk)

    _p(f"Splitting 512-bit key into {n} shares (threshold {k})...")
    raw_shares = shamir_split(master_key, n, k)
    share_strings = [encode_share(s) for s in raw_shares]

    def b64(b): return base64.b64encode(b).decode()
    volume_id = uuid.uuid4().bytes

    auth_fields = {
        "kyber_kem_ct":       b64(kem_ct),
        "kyber_sk_enc_nonce": b64(sk_nonce),
        "kyber_sk_enc":       b64(sk_ct),
    }

    # Auth params stored unencrypted so mounting can derive the key
    auth_params = {
        "mode": "shamir",
        "threshold": k,
        "total": n,
        **auth_fields,
    }

    metadata = {
        "format_version": VOLUME_FORMAT_VERSION,
        "mode": "shamir",
        "key_bits": 512,
        "threshold": k,
        "total": n,
        "chunk_size": VOLUME_CHUNK_SIZE,
        "created_at": int(time.time()),
        **auth_fields,
    }
    metadata["hmac"] = _meta_hmac(master_key, auth_fields)

    dir_index: dict[str, Any] = {}

    meta_nonce, meta_ct = encrypt_metadata(final_key, metadata)
    dir_nonce, dir_ct = encrypt_directory(final_key, dir_index)

    _p("Writing volume container...")
    with open(path, "wb") as f:
        write_header(f, volume_id, meta_nonce, dir_nonce)
        _write_auth_params(f, auth_params)
        _write_encrypted_block(f, meta_ct)
        _write_encrypted_block(f, dir_ct)

    _p("Volume created.")
    return metadata, share_strings


# ── Volume open / read / write / save ───────────────────────────────────────

class VolumeContainer:
    """In-memory representation of an open .qcv volume.

    After opening, the directory index lives in memory. File data is read
    from / written to the container on demand. Call save() to persist the
    updated directory index back to disk.
    """

    def __init__(self, path: str, final_key: bytes):
        self.path = path
        self.final_key = final_key
        self.header: dict = {}
        self.auth_params: dict = {}
        self.metadata: dict = {}
        self.dir_index: dict[str, dict] = {}
        self._file_data: dict[str, bytes] = {}  # path → encrypted blob
        self._dirty = False

    def open(self) -> None:
        """Read and decrypt the volume header, metadata, and directory.

        Raises ``ValueError`` for corrupt or unreadable volumes, and
        wraps decryption failures with a user-friendly message hinting
        at a wrong password/key.
        """
        with open(self.path, "rb") as f:
            self.header = read_header(f)
            self.auth_params = _read_auth_params(f)
            meta_ct = _read_encrypted_block(f)
            dir_ct = _read_encrypted_block(f)
            self._data_offset = f.tell()

            # Read all file data blobs (rest of the file)
            remaining = f.read()

        try:
            self.metadata = decrypt_metadata(
                self.final_key, self.header["meta_nonce"], meta_ct
            )
        except Exception as exc:
            raise ValueError(
                "Could not decrypt volume metadata — "
                "the password or key may be incorrect, "
                "or the volume file is corrupt"
            ) from exc

        try:
            self.dir_index = decrypt_directory(
                self.final_key, self.header["dir_nonce"], dir_ct
            )
        except Exception as exc:
            raise ValueError(
                "Could not decrypt volume directory index — "
                "the volume file may be corrupt"
            ) from exc

        # Parse file data blobs by offset
        for vpath, entry in self.dir_index.items():
            if entry.get("type") == "dir":
                continue
            offset = entry.get("data_offset", 0)
            length = entry.get("data_length", 0)
            if offset + length > len(remaining):
                raise ValueError(
                    f"File data for {vpath} extends past end of volume "
                    f"(offset {offset} + length {length} > {len(remaining)}) "
                    "— the volume file may be truncated or corrupt"
                )
            self._file_data[vpath] = remaining[offset:offset + length]

    def list_dir(self, dir_path: str = "/") -> list[str]:
        """List entries in a virtual directory."""
        if dir_path != "/" and not dir_path.endswith("/"):
            dir_path += "/"
        if dir_path == "/":
            prefix = "/"
        else:
            prefix = dir_path

        entries = set()
        for vpath in self.dir_index:
            if not vpath.startswith(prefix) or vpath == prefix:
                continue
            # Get the next path component after the prefix
            remainder = vpath[len(prefix):]
            if "/" in remainder:
                # It's a subdirectory entry
                entries.add(remainder.split("/")[0])
            else:
                entries.add(remainder)
        return sorted(entries)

    def read_file(self, vpath: str, verify_hash: bool = True) -> bytes:
        """Decrypt and return file contents.

        If *verify_hash* is True (default) and the directory entry stores
        a ``content_hash``, the SHA-256 of the decrypted data is checked
        against it.  A mismatch raises ``ValueError``.
        """
        if vpath not in self.dir_index:
            raise FileNotFoundError(f"No such file in volume: {vpath}")
        entry = self.dir_index[vpath]
        if entry.get("type") == "dir":
            raise IsADirectoryError(f"Is a directory: {vpath}")

        blob = self._file_data.get(vpath, b"")
        if not blob and entry.get("chunk_count", 0) > 0:
            raise ValueError(f"File data missing for {vpath}")

        if entry.get("chunk_count", 0) == 0:
            return b""

        plaintext = decrypt_file_data(
            blob, self.final_key,
            base64.b64decode(entry["nonce"]),
            entry["chunk_count"],
        )

        if verify_hash and "content_hash" in entry:
            actual_hash = hashlib.sha256(plaintext).hexdigest()
            if actual_hash != entry["content_hash"]:
                raise ValueError(
                    f"Content hash mismatch for {vpath}: "
                    f"expected {entry['content_hash'][:16]}…, "
                    f"got {actual_hash[:16]}…  — file may be corrupt"
                )

        return plaintext

    def write_file(self, vpath: str, data: bytes) -> None:
        """Encrypt and store file data in the volume."""
        nonce, blob, chunk_count, sha256_hex = encrypt_file_data(
            data, self.final_key, self.metadata.get("chunk_size", VOLUME_CHUNK_SIZE)
        )

        self.dir_index[vpath] = {
            "type": "file",
            "size": len(data),
            "mode": 0o100644,
            "mtime": int(time.time()),
            "nonce": base64.b64encode(nonce).decode(),
            "chunk_count": chunk_count,
            "data_offset": 0,  # recomputed on save
            "data_length": len(blob),
            "content_hash": sha256_hex,
        }
        self._file_data[vpath] = blob
        self._dirty = True

    def mkdir(self, vpath: str) -> None:
        """Create a virtual directory."""
        if not vpath.endswith("/"):
            vpath += "/"
        if vpath in self.dir_index:
            return  # already exists
        self.dir_index[vpath] = {
            "type": "dir",
            "mode": 0o40755,
            "mtime": int(time.time()),
        }
        self._dirty = True

    def delete(self, vpath: str) -> None:
        """Remove a file or empty directory from the volume."""
        if vpath not in self.dir_index:
            raise FileNotFoundError(f"No such entry: {vpath}")
        entry = self.dir_index[vpath]

        # If it's a directory, make sure it's empty
        if entry.get("type") == "dir":
            children = self.list_dir(vpath.rstrip("/"))
            if children:
                raise OSError(f"Directory not empty: {vpath}")

        del self.dir_index[vpath]
        self._file_data.pop(vpath, None)
        self._dirty = True

    def rename(self, old_path: str, new_path: str) -> None:
        """Rename a file or directory."""
        if old_path not in self.dir_index:
            raise FileNotFoundError(f"No such entry: {old_path}")
        if new_path in self.dir_index:
            raise FileExistsError(f"Destination already exists: {new_path}")

        self.dir_index[new_path] = self.dir_index.pop(old_path)
        if old_path in self._file_data:
            self._file_data[new_path] = self._file_data.pop(old_path)
        self._dirty = True

    def get_entry(self, vpath: str) -> dict | None:
        """Return directory entry metadata, or None if not found."""
        return self.dir_index.get(vpath)

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def save(self) -> None:
        """Re-encrypt and write the entire volume back to disk."""
        # Recompute data offsets
        data_blobs = []
        offset = 0
        for vpath in sorted(self.dir_index):
            entry = self.dir_index[vpath]
            if entry.get("type") == "dir":
                continue
            blob = self._file_data.get(vpath, b"")
            entry["data_offset"] = offset
            entry["data_length"] = len(blob)
            data_blobs.append(blob)
            offset += len(blob)

        # Re-encrypt metadata and directory
        meta_nonce, meta_ct = encrypt_metadata(self.final_key, self.metadata)
        dir_nonce, dir_ct = encrypt_directory(self.final_key, self.dir_index)

        # Write atomically: write to temp, then rename.
        # On disk-full or I/O error the temp file is cleaned up so we
        # never leave a partial .tmp beside the original volume.
        tmp_path = self.path + ".tmp"
        try:
            with open(tmp_path, "wb") as f:
                write_header(f, self.header["volume_id"], meta_nonce, dir_nonce)
                _write_auth_params(f, self.auth_params)
                _write_encrypted_block(f, meta_ct)
                _write_encrypted_block(f, dir_ct)
                for blob in data_blobs:
                    f.write(blob)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # Clean up partial temp file on any error (disk full, etc.)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        os.replace(tmp_path, self.path)

        # Update header nonces for next open
        self.header["meta_nonce"] = meta_nonce
        self.header["dir_nonce"] = dir_nonce
        self._dirty = False

    def stat(self) -> dict:
        """Return volume statistics."""
        file_count = sum(
            1 for e in self.dir_index.values() if e.get("type") != "dir"
        )
        dir_count = sum(
            1 for e in self.dir_index.values() if e.get("type") == "dir"
        )
        total_size = sum(
            e.get("size", 0) for e in self.dir_index.values()
            if e.get("type") != "dir"
        )
        return {
            "file_count": file_count,
            "dir_count": dir_count,
            "total_plaintext_size": total_size,
            "container_size": os.path.getsize(self.path) if os.path.exists(self.path) else 0,
        }
