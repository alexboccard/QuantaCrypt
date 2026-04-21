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
VOLUME_FORMAT_VERSION = 2
HEADER_SIZE = 512

# Volume uses smaller chunks than .qcx for better random-access performance.
# 64 KB balances GCM overhead (~0.025%) against seek granularity.
VOLUME_CHUNK_SIZE = 64 * 1024  # 64 KB

# Format v2: append-only journal after the baseline blobs.  When the journal
# exceeds this ratio of the baseline size, save() performs a full compact
# instead of appending.  See docs/design/volumes-delta-save.md.
_JOURNAL_COMPACT_RATIO = 0.3

# Minimum journal size before the ratio-based compact trigger fires, and
# minimum total journal size for the empty-baseline guard.  Raised from
# 1 MB to 8 MB so small / freshly-created volumes don't rewrite the whole
# container every few edits.
_JOURNAL_COMPACT_FLOOR = 8 << 20  # 8 MB

# Guard rails for journal record sizes — prevent a malicious or truncated
# file from directing us to allocate gigabytes before we detect corruption.
# (These are "obviously too big" bounds, not tight limits.)
_JOURNAL_MAX_HEADER_CT = 1 << 20  # 1 MB of encrypted header JSON is absurd
_JOURNAL_MIN_HEADER_CT = 16       # at minimum, GCM tag

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


# ── Journal record format (v2) ──────────────────────────────────────────────
# Each record is self-contained so a truncated journal tail is recoverable
# (replay simply stops at the last valid record).  Wire layout:
#   [header_nonce 12B][header_ct_len uint32 BE][header_ct + GCM tag][body]
# The header is an encrypted JSON object describing the op; body bytes are
# the raw encrypted file blob for "write" ops (same chunked AES-GCM format
# used in the baseline data section) or empty otherwise.

def _write_journal_record(
    f: IO[bytes],
    final_key: bytes,
    op: dict,
    body: bytes,
) -> int:
    """Append one journal record at current position. Returns body offset
    (absolute file offset where the body bytes start).  The caller should
    use this to update dir_index entries for "write" ops.

    The AAD binds each record to its byte offset in the container, so an
    attacker with file-access cannot reorder records (e.g. truncate newer
    records and re-shuffle older ones into their slots).  Each record's
    ciphertext is only valid at the position where it was written.
    """
    header_dict = {k: v for k, v in op.items() if k not in ("blob",)}
    header_dict["body_length"] = len(body)
    header_plain = json.dumps(
        header_dict, sort_keys=True, separators=(",", ":")
    ).encode()
    header_nonce = secrets.token_bytes(12)
    start = f.tell()
    aad = start.to_bytes(8, "big")
    header_ct = AESGCM(derive_aes_key(final_key)).encrypt(
        header_nonce, header_plain, aad
    )
    f.write(header_nonce)
    f.write(struct.pack(">I", len(header_ct)))
    f.write(header_ct)
    body_offset = start + 12 + 4 + len(header_ct)
    if body:
        f.write(body)
    return body_offset


def _read_journal_records(
    path: str,
    final_key: bytes,
    start_offset: int,
    end_offset: int,
) -> list[tuple[dict, int, int]]:
    """Read all journal records between *start_offset* and *end_offset*.

    Returns a list of (header_dict, body_offset, body_length) tuples.
    Stops silently at a truncated or corrupt record — the tail is treated
    as an incomplete append (crash during save), not an error.
    """
    aes = AESGCM(derive_aes_key(final_key))
    records: list[tuple[dict, int, int]] = []
    with open(path, "rb") as f:
        f.seek(start_offset)
        pos = start_offset
        while pos < end_offset:
            nonce = f.read(12)
            if len(nonce) < 12:
                break
            raw_len = f.read(4)
            if len(raw_len) < 4:
                break
            ct_len = struct.unpack(">I", raw_len)[0]
            if ct_len < _JOURNAL_MIN_HEADER_CT or ct_len > _JOURNAL_MAX_HEADER_CT:
                break
            ct = f.read(ct_len)
            if len(ct) < ct_len:
                break
            aad = pos.to_bytes(8, "big")
            try:
                header_plain = aes.decrypt(nonce, ct, aad)
                header = json.loads(header_plain)
            except Exception:
                # Truncated / corrupt / wrong-key / record-at-wrong-offset.
                # The last successful record is the effective end of the
                # journal; replay stops here.
                break
            if not isinstance(header, dict):
                break
            body_length = int(header.get("body_length", 0))
            if body_length < 0 or body_length > end_offset - pos:
                break
            body_offset = pos + 12 + 4 + ct_len
            # Skip the body without reading it — blobs are loaded lazily
            # via VolumeContainer._get_blob() at their absolute offsets.
            next_pos = body_offset + body_length
            if next_pos > end_offset:
                break
            f.seek(next_pos)
            records.append((header, body_offset, body_length))
            pos = next_pos
    return records


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
    # HMAC under final_key (not master_key) so that VolumeContainer.open()
    # can verify it without having to plumb master_key through the mount API.
    metadata["hmac"] = _meta_hmac(final_key, auth_fields)

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
        # _file_data holds encrypted blobs for files written this session
        # but not yet flushed to disk.  On open() we intentionally do NOT
        # pre-load all blobs — unmodified files are read lazily via
        # _get_blob() so mount RAM stays bounded by the working set.
        self._file_data: dict[str, bytes] = {}
        self._data_offset: int = 0
        self._file_size: int = 0
        # Format-v2 journal bookkeeping.  _journal_start is the absolute
        # byte offset where the append-only journal begins (= end of the
        # baseline blobs section).  _baseline_size is the size of the
        # baseline blobs section alone (used to decide when to compact).
        # _pending_ops records changes since the last save() so save()
        # can emit them as journal records in one append.
        self._baseline_size: int = 0
        self._journal_start: int = 0
        self._pending_ops: list[dict] = []
        self._dirty = False

    def open(self) -> None:
        """Read and decrypt the volume header, metadata, and directory.

        File data blobs are NOT read eagerly — they're loaded on demand by
        read_file() so mount latency stays bounded regardless of container
        size.  We only verify that each entry's offset+length falls within
        the container (defense-in-depth; GCM catches the rest on read).

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
            # Record the container size so bounds checks don't require
            # re-stat'ing the file on every _get_blob() call.
            f.seek(0, 2)
            self._file_size = f.tell()

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

        # Verify metadata HMAC to detect tampering with the auth fields
        # (argon_salt, kyber_kem_ct, kyber_sk_enc_nonce, kyber_sk_enc).  Both
        # volume modes now HMAC under final_key, so this works for single and
        # shamir without additional plumbing.
        _verify_meta_hmac(self.final_key, self.metadata)

        try:
            self.dir_index = decrypt_directory(
                self.final_key, self.header["dir_nonce"], dir_ct
            )
        except Exception as exc:
            raise ValueError(
                "Could not decrypt volume directory index — "
                "the volume file may be corrupt"
            ) from exc

        # Validate directory index keys: reject absolute-escape, traversal,
        # and non-absolute entries that an attacker could inject by tampering
        # with the encrypted directory block on disk.  AES-GCM already catches
        # bit flips, but this is defense-in-depth.
        for vpath in self.dir_index:
            if not vpath.startswith("/"):
                raise ValueError(
                    f"Directory entry has non-absolute path: {vpath!r} "
                    "— the volume file may be corrupt or tampered with"
                )
            # Normalize and confirm no '..' segments survive
            parts = [p for p in vpath.split("/") if p not in ("", ".")]
            if any(p == ".." for p in parts):
                raise ValueError(
                    f"Directory entry contains path traversal: {vpath!r} "
                    "— the volume file may be tampered with"
                )

        # Bounds-check each baseline file entry against the baseline size.
        # For v1 containers, baseline == entire data section (no journal).
        # For v2, the journal starts immediately after the baseline blobs;
        # any baseline entry that extends past _baseline_size is corrupt.
        self._baseline_size = sum(
            e.get("data_length", 0)
            for e in self.dir_index.values()
            if e.get("type") != "dir"
        )
        self._journal_start = self._data_offset + self._baseline_size
        # The baseline section must fit entirely within the file; anything
        # less means the container has been truncated inside the canonical
        # data and we have no safe recovery.  (A truncated *journal* tail
        # is tolerated — that's just a crash during save — but baseline
        # truncation is always an error.)
        if self._file_size < self._journal_start:
            raise ValueError(
                f"Volume file truncated within baseline data "
                f"(expected at least {self._journal_start} bytes, "
                f"got {self._file_size}) — the volume file may be corrupt"
            )
        # A v1 container must have nothing beyond the baseline; a v2
        # container may legitimately have a journal there.
        if self.header.get("version", 1) < 2 and self._file_size > self._journal_start:
            raise ValueError(
                "Trailing bytes after baseline data in v1 volume "
                "— the volume file may be truncated or corrupt"
            )
        remaining_size = self._baseline_size
        for vpath, entry in self.dir_index.items():
            if entry.get("type") == "dir":
                continue
            offset = entry.get("data_offset", 0)
            length = entry.get("data_length", 0)
            if offset + length > remaining_size:
                raise ValueError(
                    f"File data for {vpath} extends past end of volume "
                    f"(offset {offset} + length {length} > {remaining_size}) "
                    "— the volume file may be truncated or corrupt"
                )

        # Replay the append-only journal (v2+).  Each record updates the
        # in-memory dir_index on top of the baseline; write records point
        # future _get_blob() reads into the journal region.  A truncated
        # or corrupt tail is treated as an incomplete append (crash during
        # save): we stop replay at the last valid record and the volume
        # remains consistent.
        if self.header.get("version", 1) >= 2 and self._file_size > self._journal_start:
            self._replay_journal()

    def _replay_journal(self) -> None:
        """Apply journal records to the in-memory dir_index.

        Reads records starting at ``_journal_start`` until ``_file_size``.
        Each record header is encrypted under ``final_key``; a record whose
        header fails to decrypt (truncated, corrupt, or never fully flushed)
        terminates replay, which is treated as an incomplete append — the
        container state up to that point is consistent.
        """
        records = _read_journal_records(
            self.path, self.final_key,
            self._journal_start, self._file_size,
        )
        for header, body_offset, body_length in records:
            op_type = header.get("type")
            vpath = header.get("vpath")
            if not isinstance(vpath, str) or not vpath.startswith("/"):
                # Skip malformed records defensively; don't abort replay.
                continue
            if op_type == "write":
                self.dir_index[vpath] = {
                    "type": "file",
                    "size": header.get("size", 0),
                    "mode": header.get("mode", 0o100644),
                    "mtime": header.get("mtime", 0),
                    "nonce": header.get("nonce", ""),
                    "chunk_count": header.get("chunk_count", 0),
                    # data_offset is stored relative to _data_offset so the
                    # same _get_blob() logic works for both baseline and
                    # journal entries.
                    "data_offset": body_offset - self._data_offset,
                    "data_length": body_length,
                    "content_hash": header.get("content_hash", ""),
                }
            elif op_type == "delete":
                self.dir_index.pop(vpath, None)
            elif op_type == "rename":
                new_vpath = header.get("new_vpath")
                if (isinstance(new_vpath, str) and new_vpath.startswith("/")
                        and vpath in self.dir_index):
                    self.dir_index[new_vpath] = self.dir_index.pop(vpath)
            elif op_type == "mkdir":
                # Directories are cheap to recreate on rmdir/mkdir cycles;
                # replay unconditionally sets the entry.
                if not vpath.endswith("/"):
                    vpath = vpath + "/"
                self.dir_index[vpath] = {
                    "type": "dir",
                    "mode": header.get("mode", 0o40755),
                    "mtime": header.get("mtime", 0),
                }
            elif op_type == "rmdir":
                if not vpath.endswith("/"):
                    vpath = vpath + "/"
                self.dir_index.pop(vpath, None)
            # Unknown op types are silently skipped for forward compat.

    def _get_blob(self, vpath: str) -> bytes:
        """Return the encrypted blob for *vpath*.

        Prefers the in-memory write cache (`_file_data`) so freshly-written
        files don't round-trip through disk, falls back to seek+read on the
        container file for unmodified entries.  Returned bytes are NOT
        cached — the FUSE layer maintains its own decrypted LRU, and we
        don't want to grow _file_data unboundedly on pure-read workloads.
        """
        if vpath in self._file_data:
            return self._file_data[vpath]
        entry = self.dir_index[vpath]
        length = entry.get("data_length", 0)
        if length == 0:
            return b""
        offset = entry.get("data_offset", 0)
        with open(self.path, "rb") as f:
            f.seek(self._data_offset + offset)
            blob = f.read(length)
        if len(blob) < length:
            raise ValueError(
                f"File data for {vpath} is truncated on disk "
                f"(expected {length} bytes, got {len(blob)})"
            )
        return blob

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

        chunk_count = entry.get("chunk_count", 0)
        size = entry.get("size", 0)
        data_length = entry.get("data_length", 0)
        chunk_size = self.metadata.get("chunk_size", VOLUME_CHUNK_SIZE)

        # Defense-in-depth bounds check: reject absurd chunk_count /
        # data_length that a tampered directory entry could inject.  Without
        # this, a malformed entry with chunk_count = 2**32 - 1 would loop
        # forever or OOM before AES-GCM authentication could catch it.
        if not isinstance(chunk_count, int) or chunk_count < 0:
            raise ValueError(f"Invalid chunk_count for {vpath}: {chunk_count!r}")
        # Expected max chunks given the declared plaintext size; allow a small
        # slop factor for the final partial chunk.
        max_expected_chunks = max(1, (size + chunk_size - 1) // chunk_size) if size else 1
        if chunk_count > max_expected_chunks:
            raise ValueError(
                f"chunk_count for {vpath} ({chunk_count}) exceeds what {size} "
                f"bytes at chunk_size {chunk_size} would produce "
                f"(max {max_expected_chunks}) — directory entry may be corrupt"
            )

        if chunk_count == 0:
            return b""

        blob = self._get_blob(vpath)

        # Declared data_length must match the on-disk / in-memory blob;
        # a mismatch indicates truncation or tampering that the hash
        # check may miss.
        if data_length != len(blob):
            raise ValueError(
                f"data_length for {vpath} ({data_length}) does not match "
                f"blob length ({len(blob)}) — directory entry may be corrupt"
            )
        if not blob:
            raise ValueError(f"File data missing for {vpath}")

        plaintext = decrypt_file_data(
            blob, self.final_key,
            base64.b64decode(entry["nonce"]),
            chunk_count,
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
        """Encrypt and store file data in the volume.

        The blob lives in _file_data until the next save(), which will
        append it to the journal region of the container (format v2+).
        """
        nonce, blob, chunk_count, sha256_hex = encrypt_file_data(
            data, self.final_key, self.metadata.get("chunk_size", VOLUME_CHUNK_SIZE)
        )
        mtime = int(time.time())
        mode = 0o100644
        nonce_b64 = base64.b64encode(nonce).decode()

        self.dir_index[vpath] = {
            "type": "file",
            "size": len(data),
            "mode": mode,
            "mtime": mtime,
            "nonce": nonce_b64,
            "chunk_count": chunk_count,
            "data_offset": 0,  # reset on save() / compact()
            "data_length": len(blob),
            "content_hash": sha256_hex,
        }
        self._file_data[vpath] = blob
        # Record the op so save() can emit one journal record per change.
        self._pending_ops.append({
            "type": "write",
            "vpath": vpath,
            "size": len(data),
            "mode": mode,
            "mtime": mtime,
            "nonce": nonce_b64,
            "chunk_count": chunk_count,
            "content_hash": sha256_hex,
        })
        self._dirty = True

    def mkdir(self, vpath: str) -> None:
        """Create a virtual directory."""
        if not vpath.endswith("/"):
            vpath += "/"
        if vpath in self.dir_index:
            return  # already exists
        mtime = int(time.time())
        mode = 0o40755
        self.dir_index[vpath] = {
            "type": "dir",
            "mode": mode,
            "mtime": mtime,
        }
        self._pending_ops.append({
            "type": "mkdir",
            "vpath": vpath,
            "mode": mode,
            "mtime": mtime,
        })
        self._dirty = True

    def delete(self, vpath: str) -> None:
        """Remove a file or empty directory from the volume."""
        if vpath not in self.dir_index:
            raise FileNotFoundError(f"No such entry: {vpath}")
        entry = self.dir_index[vpath]
        is_dir = entry.get("type") == "dir"

        # If it's a directory, make sure it's empty
        if is_dir:
            children = self.list_dir(vpath.rstrip("/"))
            if children:
                raise OSError(f"Directory not empty: {vpath}")

        del self.dir_index[vpath]
        self._file_data.pop(vpath, None)
        self._pending_ops.append({
            "type": "rmdir" if is_dir else "delete",
            "vpath": vpath,
        })
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
        self._pending_ops.append({
            "type": "rename",
            "vpath": old_path,
            "new_vpath": new_path,
        })
        self._dirty = True

    def get_entry(self, vpath: str) -> dict | None:
        """Return directory entry metadata, or None if not found."""
        return self.dir_index.get(vpath)

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def save(self) -> None:
        """Persist pending changes to disk.

        Format-v2 fast path: append pending ops as journal records at the
        end of the container.  This makes save() proportional to the size
        of the changes, not the size of the container — a 1-byte edit on
        a 1 GB volume is ~4 KB of I/O instead of 1 GB.

        Falls back to a full compact when:
          * the container is still format v1 (upgrade to v2 in one shot), or
          * the journal would exceed _JOURNAL_COMPACT_RATIO of the baseline
            after this append (the next open() would spend too long
            replaying).

        Crash safety: each journal record is self-authenticating
        (AES-GCM on the header + empty-AAD body).  A crash mid-append
        leaves a partial record; open() stops replay at the last complete
        record, which is consistent with the last completed save().
        """
        if not self._pending_ops and not self._dirty:
            return

        # v1 containers always upgrade via compact.  This keeps the on-disk
        # version in sync with the actual layout (no mixed v1-header + v2-
        # journal containers in the wild).
        if self.header.get("version", 1) < VOLUME_FORMAT_VERSION:
            self.compact()
            return

        # Heuristic: if the existing journal + our pending ops would push
        # the journal past _JOURNAL_COMPACT_RATIO of the baseline, compact
        # now so open() stays fast.  Estimate pending journal bytes
        # optimistically — the exact size is overhead + body length.
        existing_journal = max(0, self._file_size - self._journal_start)
        pending_body_bytes = sum(
            len(self._file_data.get(op["vpath"], b""))
            for op in self._pending_ops
            if op["type"] == "write"
        )
        # Rough: each record header is ~250 bytes encrypted (small JSON + 12B
        # nonce + 4B length + 16B tag).  Overestimating here only biases us
        # toward compacting more eagerly, which is fine.
        pending_overhead = len(self._pending_ops) * 300
        total_journal = existing_journal + pending_overhead + pending_body_bytes
        # Only compact if the ratio AND the absolute floor are both exceeded
        # — otherwise small volumes would rewrite themselves on almost every
        # save, which defeats the delta-save win.
        ratio_exceeded = (
            self._baseline_size > 0
            and total_journal > self._baseline_size * _JOURNAL_COMPACT_RATIO
        )
        if ratio_exceeded and total_journal > _JOURNAL_COMPACT_FLOOR:
            self.compact()
            return
        # Empty baseline: compact only when the journal itself is large
        # enough to care about (same floor).
        if self._baseline_size == 0 and total_journal > _JOURNAL_COMPACT_FLOOR:
            self.compact()
            return

        self._append_journal()

    def _coalesce_pending_ops(self) -> list[dict]:
        """Collapse redundant ops before emitting to the journal.

        * If a path has multiple writes in the same session, only the last
          write's body matters (``_file_data`` already holds only the
          latest blob); emit a single write record.
        * If a write is followed by a delete on the same path, drop the
          write entirely — persisting an orphan write record with an empty
          body would be invalid on crash-recovery (replay would see a
          chunk_count>0 entry with a 0-byte blob).
        * Similarly, a mkdir immediately followed by rmdir is a no-op.

        Returns the coalesced ops in the order they should be written.
        Rename ops are preserved as-is — they're path-change edges in the
        dependency graph, not content-change ops.
        """
        # Walk backwards: the last op for each path wins.  We track the
        # final state per path and then replay the ops that matter.
        last_effective: dict[str, dict] = {}
        # Renames carry source + target; handle separately so we don't
        # collapse /x→/y into a no-op when /y is later overwritten.
        rename_chain: list[dict] = []
        for op in self._pending_ops:
            if op["type"] == "rename":
                rename_chain.append(op)
                continue
            vpath = op["vpath"]
            last_effective[vpath] = op

        # Drop write+delete pairs: if the last op for a path is a delete /
        # rmdir, and there was no rename of a different path INTO it, we
        # can skip the delete for paths that never existed before this
        # batch.  For simplicity we always emit the delete (it's cheap) but
        # drop the preceding write (which would be garbage).
        # The "last_effective" map already gives us this: we only emit the
        # last op per path.
        coalesced: list[dict] = []
        emitted: set[str] = set()
        # Preserve the temporal order of rename records relative to writes /
        # deletes: rebuild in original order, skipping ops that aren't the
        # final effective op for their path.
        for op in self._pending_ops:
            if op["type"] == "rename":
                coalesced.append(op)
                continue
            vpath = op["vpath"]
            if vpath in emitted:
                continue
            if last_effective.get(vpath) is op:
                coalesced.append(op)
                emitted.add(vpath)
        return coalesced

    def _append_journal(self) -> None:
        """Append pending ops as journal records at end-of-file (v2)."""
        ops = self._coalesce_pending_ops()
        with open(self.path, "r+b") as f:
            f.seek(0, 2)  # SEEK_END
            for op in ops:
                body = b""
                if op["type"] == "write":
                    body = self._file_data.get(op["vpath"], b"")
                    # Sanity: a write op whose blob was later popped (by a
                    # delete on the same path) should have been coalesced
                    # away.  If we still see an empty body with chunk_count
                    # > 0, something slipped through — skip to avoid
                    # persisting a broken record.
                    if not body and op.get("chunk_count", 0) > 0:
                        continue
                body_offset = _write_journal_record(f, self.final_key, op, body)
                if op["type"] == "write" and op["vpath"] in self.dir_index:
                    entry = self.dir_index[op["vpath"]]
                    # Journal-region body offset is absolute; store relative
                    # to _data_offset so _get_blob() uses one formula.
                    entry["data_offset"] = body_offset - self._data_offset
                    entry["data_length"] = len(body)
            f.flush()
            os.fsync(f.fileno())
            self._file_size = f.tell()

        self._pending_ops.clear()
        self._file_data.clear()
        self._dirty = False

    def compact(self) -> None:
        """Rewrite the entire container as a fresh baseline with no journal.

        Used automatically for v1→v2 upgrade and whenever the journal grows
        large relative to the baseline.  Also available to callers (e.g. a
        "Compact volume" action in the Volume Manager UI) to reclaim space
        that deleted / overwritten files leave in the journal.

        Preserves atomicity via ``.tmp`` + ``os.replace()``.  Memory profile
        is O(largest file in _file_data) plus a 1 MB sliding window for
        streaming unmodified blobs from the current container.
        """
        # Capture OLD offsets before overwriting them in the dir_index;
        # we need them to copy unmodified blobs from the current file.
        old_offsets = {
            vp: e.get("data_offset", 0)
            for vp, e in self.dir_index.items()
            if e.get("type") != "dir"
        }
        old_data_offset = self._data_offset

        # Pass 1: update offsets + lengths in dir_index.  For modified files
        # data_length is already set by write_file; for unmodified ones it
        # was established at open() and is preserved from the current entry.
        new_offset = 0
        for vpath in sorted(self.dir_index):
            entry = self.dir_index[vpath]
            if entry.get("type") == "dir":
                continue
            if vpath in self._file_data:
                entry["data_length"] = len(self._file_data[vpath])
            length = entry.get("data_length", 0)
            entry["data_offset"] = new_offset
            new_offset += length

        # Re-encrypt metadata and directory (cheap; ~KB of JSON)
        meta_nonce, meta_ct = encrypt_metadata(self.final_key, self.metadata)
        dir_nonce, dir_ct = encrypt_directory(self.final_key, self.dir_index)

        # Pass 2: stream to .tmp.  On disk-full / I/O error the temp file
        # is cleaned up so we never leave a partial .tmp beside the original.
        tmp_path = self.path + ".tmp"
        _COPY_CHUNK = 1 << 20  # 1 MB sliding window for unmodified blobs
        try:
            with open(tmp_path, "wb") as tmp_f:
                write_header(tmp_f, self.header["volume_id"], meta_nonce, dir_nonce)
                _write_auth_params(tmp_f, self.auth_params)
                _write_encrypted_block(tmp_f, meta_ct)
                _write_encrypted_block(tmp_f, dir_ct)
                new_data_offset = tmp_f.tell()

                # Open the current container read-only to copy unmodified
                # blobs.  os.replace() below atomically swaps it; any open
                # descriptor still refers to the old inode until it closes.
                with open(self.path, "rb") as src_f:
                    for vpath in sorted(self.dir_index):
                        entry = self.dir_index[vpath]
                        if entry.get("type") == "dir":
                            continue
                        length = entry.get("data_length", 0)
                        if length == 0:
                            continue
                        if vpath in self._file_data:
                            tmp_f.write(self._file_data[vpath])
                        else:
                            src_f.seek(old_data_offset + old_offsets[vpath])
                            remaining = length
                            while remaining > 0:
                                chunk = src_f.read(min(remaining, _COPY_CHUNK))
                                if not chunk:
                                    raise ValueError(
                                        f"Volume file truncated while copying "
                                        f"unmodified blob for {vpath}"
                                    )
                                tmp_f.write(chunk)
                                remaining -= len(chunk)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        os.replace(tmp_path, self.path)

        # Update state for continued use.  _file_data is cleared because all
        # blobs now live canonically on disk at the new offsets; future reads
        # go through _get_blob() which will seek-read them fresh.  The
        # journal region is empty post-compact, so _journal_start coincides
        # with the end of the baseline blobs.
        self._data_offset = new_data_offset
        self._baseline_size = new_offset  # sum of lengths written above
        self._journal_start = new_data_offset + new_offset
        # Re-stat to pick up the new file size for bounds checks.
        self._file_size = os.path.getsize(self.path)
        self.header["meta_nonce"] = meta_nonce
        self.header["dir_nonce"] = dir_nonce
        # Keep the header version in sync with what _compact actually wrote
        # (v1 containers are upgraded to v2 on first save via this path).
        self.header["version"] = VOLUME_FORMAT_VERSION
        self.metadata["format_version"] = VOLUME_FORMAT_VERSION
        self._pending_ops.clear()
        self._file_data.clear()
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
