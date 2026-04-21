"""QuantaCrypt Core Cryptography Module v1 (512-bit streaming edition).

Key material is 512 bits throughout:
  - Argon2id produces a 64-byte key
  - Kyber-768 shared secret (32 bytes) is HKDF-SHA-512 expanded to 64 bytes
  - XOR combination gives 64-byte final key material
  - SHA-512(final_key)[:32] used as AES-256-GCM key
  - Shamir over M521 (2^521 - 1), the largest Mersenne prime > 2^512

Chunked AES-GCM streaming — O(CHUNK_SIZE) RAM regardless of file size.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import IO, Callable

import math
import shamirs
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.kyber import Kyber768

KEY_BYTES          = 64
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 1   # single lane: full 64MB per hash path (see OWASP Argon2id guidance)
SHAMIR_PRIME       = (2 ** 521) - 1   # M521 Mersenne prime
FORMAT_VERSION     = 1
MIN_FORMAT_VERSION = 1   # files below this version are not supported
MAX_FORMAT_VERSION = 1   # files above this need a newer app
HKDF_INFO          = b"quantacrypt-v1-kem-expansion"
HMAC_INFO          = b"quantacrypt-v1-metadata-auth"
MAGIC              = b"QCBIN\x01"   # A2: single canonical definition, imported everywhere

# Streaming constants
# 4 MB plaintext chunks: large enough to amortise GCM overhead, small enough
# that RAM stays bounded (peak ≈ 2–3 × CHUNK_SIZE for read + encrypt + write buffers).
# Overhead: 8B header (seq + ct_len) + 16B GCM tag per chunk ≈ 0.0006% for 4 MB chunks.
CHUNK_SIZE     = 4 * 1024 * 1024          # 4 MB plaintext per chunk

__all__ = [
    # Constants
    "KEY_BYTES", "FORMAT_VERSION", "MIN_FORMAT_VERSION", "MAX_FORMAT_VERSION",
    "MAGIC", "CHUNK_SIZE", "SHAMIR_PRIME",
    "MNEMONIC_WORDS_PER_SHARE",
    # Key derivation
    "argon2id_derive", "expand_kem_ss", "derive_aes_key",
    # Symmetric crypto
    "aes_gcm_encrypt", "aes_gcm_decrypt", "xor_bytes",
    # KEM
    "kyber_keygen", "kyber_encaps", "kyber_decaps",
    # Shamir
    "shamir_split", "shamir_recover", "encode_share", "decode_share",
    # Streaming
    "stream_encrypt_payload", "stream_decrypt_payload",
    "encrypt_single_streaming", "encrypt_shamir_streaming",
    "decrypt_streaming",
    # Mnemonic
    "share_to_mnemonic", "mnemonic_to_share",
]


def argon2id_derive(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password, salt=salt,
        time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM, hash_len=KEY_BYTES, type=Type.ID,
    )

def expand_kem_ss(kem_ss_raw: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=KEY_BYTES,
                salt=None, info=HKDF_INFO).derive(kem_ss_raw)

def derive_aes_key(key_material: bytes) -> bytes:
    return hashlib.sha512(key_material).digest()[:32]

def aes_gcm_encrypt(key_material: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(derive_aes_key(key_material)).encrypt(nonce, plaintext, None)
    return nonce, ct

def aes_gcm_decrypt(key_material: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(derive_aes_key(key_material)).decrypt(nonce, ciphertext, None)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"xor_bytes: length mismatch {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))

def _meta_hmac(key_material: bytes, meta_fields: dict) -> str:
    """Compute HMAC-SHA256 over a canonical encoding of authenticated metadata fields.
    Protects argon_salt, kyber_kem_ct, kyber_sk_enc_nonce, kyber_sk_enc, nonce
    against tampering. The tag is stored inside meta and verified before decryption."""
    # Canonical: sorted keys, deterministic JSON, prefixed with domain label
    canon = HMAC_INFO + json.dumps(meta_fields, sort_keys=True, separators=(",",":")).encode()
    tag   = hmac.new(key_material[:32], canon, hashlib.sha256).digest()
    return base64.b64encode(tag).decode()

def _verify_meta_hmac(key_material: bytes, meta: dict) -> bool:
    """Verify metadata HMAC.
    Returns True if HMAC is present and valid.
    Raises ValueError if HMAC is absent or invalid (tampering detected)."""
    if "hmac" not in meta:
        raise ValueError("Metadata HMAC is missing — file may have been tampered with or is from an unsupported version")
    stored   = meta["hmac"]
    # Exclude structural/display fields that are present in meta at decryption time
    # but were NOT in auth_fields when the HMAC was computed at encryption time.
    # "format_version" and "created_at" are .qcv-only fields — excluding them is a
    # no-op for .qcx metadata (which uses "version" and lacks "created_at").
    _EXCLUDED = {"hmac", "version", "format_version", "created_at",
                 "mode", "key_bits", "threshold", "total",
                 "chunk_size", "payload_offset"}
    fields   = {k: v for k, v in meta.items() if k not in _EXCLUDED}
    expected = _meta_hmac(key_material, fields)
    if not hmac.compare_digest(stored, expected):
        raise ValueError("Metadata authentication failed — file may have been tampered with")
    return True

def kyber_keygen() -> tuple[bytes, bytes]:
    """Generate a Kyber-768 keypair: (public_key, secret_key)."""
    return Kyber768.keygen()

def kyber_encaps(pk: bytes) -> tuple[bytes, bytes]:
    kem_ss_raw, kem_ct = Kyber768.encaps(pk)
    return kem_ct, expand_kem_ss(kem_ss_raw)

def kyber_decaps(sk: bytes, kem_ct: bytes) -> bytes:
    return expand_kem_ss(Kyber768.decaps(sk, kem_ct))


def shamir_split(secret_bytes: bytes, n: int, k: int) -> list[dict]:
    if not (2 <= k <= n <= 255):
        raise ValueError(
            f"Invalid Shamir parameters: need 2 <= k <= n <= 255 (got k={k}, n={n})"
        )
    secret_int = int.from_bytes(secret_bytes, "big")
    if secret_int >= SHAMIR_PRIME:
        raise ValueError(f"Secret ({len(secret_bytes)*8} bits) exceeds M521 prime — cannot split safely")
    shares = shamirs.shares(secret_int, quantity=n, threshold=k, modulus=SHAMIR_PRIME)
    return [{"index": s.index, "value": s.value, "modulus": s.modulus,
             "threshold": k} for s in shares]

def shamir_recover(share_dicts: list[dict]) -> bytes:
    if not share_dicts:
        raise ValueError("Cannot recover from an empty share list")
    # If every share carries a threshold, reject obviously-insufficient sets
    # before asking the library to do something undefined.  A stored threshold
    # is advisory: the library will still attempt recovery with fewer, but the
    # result would be garbage rather than an error.
    thresholds = {s.get("threshold") for s in share_dicts if "threshold" in s}
    if thresholds and all(t is not None for t in thresholds):
        min_threshold = min(thresholds)  # be lenient if shares disagree
        if len(share_dicts) < min_threshold:
            raise ValueError(
                f"Not enough shares to recover the secret "
                f"(have {len(share_dicts)}, need at least {min_threshold})"
            )
    objs       = [shamirs.shamirs.share(s["index"], s["value"], s["modulus"]) for s in share_dicts]
    secret_int = shamirs.recover(objs)
    if secret_int < 0 or secret_int >= (1 << (KEY_BYTES * 8)):
        raise ValueError(
            "Recovered secret is out of range — shares may be corrupted or from a different file"
        )
    return secret_int.to_bytes(KEY_BYTES, "big")

def encode_share(share_dict: dict) -> str:
    return "QCSHARE-" + base64.b64encode(json.dumps(share_dict).encode()).decode()

def decode_share(share_str: str) -> dict:
    s = share_str.strip()
    if not s.startswith("QCSHARE-"):
        raise ValueError("Not a valid QuantaCrypt share")
    try:
        d = json.loads(base64.b64decode(s[8:]).decode())
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise ValueError("Share is malformed (could not decode)")
    # Validate required fields and types
    for field in ("index", "value", "modulus"):
        if field not in d:
            raise ValueError(f"Share missing required field: {field!r}")
        if not isinstance(d[field], int):
            raise ValueError(f"Share field {field!r} must be an integer, got {type(d[field]).__name__}")
    # Validate modulus matches the known prime — reject any crafted/downgraded modulus
    if d["modulus"] != SHAMIR_PRIME:
        raise ValueError(
            f"Share modulus does not match expected M521 prime "
            f"(got {d['modulus']}, expected {SHAMIR_PRIME}). "
            "This share may be from a different version or have been tampered with."
        )
    # Validate index and value are in sensible ranges
    if not (1 <= d["index"] <= 255):
        raise ValueError(f"Share index out of range: {d['index']}")
    if not (0 < d["value"] < SHAMIR_PRIME):
        raise ValueError(f"Share value out of range")
    return d




# ── v1 Streaming Payload: chunked AES-GCM ────────────────────────────────────
# Security properties:
#   • Each chunk is an independent AES-GCM AEAD unit — O(CHUNK_SIZE) RAM.
#   • Nonce per chunk = base_nonce XOR chunk_index (12-byte big-endian).
#     base_nonce is random per file, so cross-file nonce reuse is impossible.
#   • AAD per chunk = chunk_index (8-byte big-endian) + last-chunk flag byte.
#     Prevents chunk reordering (wrong index → bad tag) and truncation (last
#     chunk must have flag=0xFF; earlier chunks flag=0x00).
#   • chunk_count in metadata + HMAC gives a second truncation guard.
#   • On-disk layout: [uint32_be(ct_len)][ciphertext+tag] repeated, then metadata.

def _chunk_nonce(base_nonce: bytes, chunk_idx: int) -> bytes:
    idx_bytes = chunk_idx.to_bytes(12, "big")
    return bytes(b ^ n for b, n in zip(base_nonce, idx_bytes))

def _chunk_aad(chunk_idx: int, is_last: bool) -> bytes:
    return chunk_idx.to_bytes(8, "big") + (b"\xff" if is_last else b"\x00")

def stream_encrypt_payload(
    src_path: str,
    dst_file: IO[bytes],
    final_key: bytes,
    payload_size: int,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[bytes, int, int, str]:
    """
    Stream-encrypt src_path into dst_file using chunked AES-GCM.
    Writes [uint32_be(seq)][uint32_be(ct_len)][ct+tag] for each chunk.
    Returns (base_nonce, chunk_count, bytes_written, plaintext_sha256_hex).
    The plaintext hash is computed incrementally during encryption (zero extra I/O).
    dst_file must already be open and positioned correctly.
    """
    base_nonce = secrets.token_bytes(12)
    aes_key     = derive_aes_key(final_key)
    cipher      = AESGCM(aes_key)
    chunk_count = 0
    bytes_written = 0
    last_report = 0
    content_hash = hashlib.sha256()

    with open(src_path, "rb") as src:
        # Read ahead by one chunk to know when we're at the last one
        buf = src.read(CHUNK_SIZE)
        while buf:
            content_hash.update(buf)
            nxt = src.read(CHUNK_SIZE)
            is_last = (not nxt)
            nonce = _chunk_nonce(base_nonce, chunk_count)
            aad   = _chunk_aad(chunk_count, is_last)
            ct    = cipher.encrypt(nonce, buf, aad)    # len = len(buf) + 16
            dst_file.write(chunk_count.to_bytes(4, "big"))  # reuse field as sequence guard
            ct_len = len(ct)
            dst_file.write(ct_len.to_bytes(4, "big"))
            dst_file.write(ct)
            bytes_written += 4 + 4 + ct_len
            chunk_count   += 1
            if progress_cb and payload_size:
                done = min(chunk_count * CHUNK_SIZE, payload_size)
                pct  = done / payload_size
                if pct - last_report >= 0.01:
                    progress_cb(f"Encrypting payload (AES-256-GCM, 512-bit key material)... {int(pct*100)}%")
                    last_report = pct
            buf = nxt

    return base_nonce, chunk_count, bytes_written, content_hash.hexdigest()

def stream_decrypt_payload(
    src_path: str,
    dst_file: IO[bytes],
    final_key: bytes,
    payload_offset: int,
    chunk_count: int,
    base_nonce: bytes,
    progress_cb: Callable[[str], None] | None = None,
) -> str:
    """
    Stream-decrypt chunked payload from src_path (starting at payload_offset)
    into dst_file.  Raises ValueError on any authentication failure.
    Returns the SHA-256 hex digest of the decrypted plaintext, computed
    incrementally during decryption (zero extra I/O).
    """
    aes_key = derive_aes_key(final_key)
    cipher  = AESGCM(aes_key)
    content_hash = hashlib.sha256()
    last_report = 0.0

    with open(src_path, "rb") as src:
        src.seek(payload_offset)
        for i in range(chunk_count):
            is_last  = (i == chunk_count - 1)
            seq_raw  = src.read(4)
            if len(seq_raw) < 4:
                raise ValueError("File appears truncated — payload is incomplete")
            seq = int.from_bytes(seq_raw, "big")
            if seq != i:
                raise ValueError(f"Chunk sequence mismatch at position {i} (got {seq})")
            ct_len_raw = src.read(4)
            if len(ct_len_raw) < 4:
                raise ValueError("File appears truncated — chunk header incomplete")
            ct_len = int.from_bytes(ct_len_raw, "big")
            ct     = src.read(ct_len)
            if len(ct) < ct_len:
                raise ValueError("File appears truncated — chunk data incomplete")
            nonce = _chunk_nonce(base_nonce, i)
            aad   = _chunk_aad(i, is_last)
            try:
                plain = cipher.decrypt(nonce, ct, aad)
            except (ValueError, InvalidTag):
                raise ValueError(
                    f"Authentication failed on chunk {i} — "
                    "file may be corrupt or the wrong key was used"
                )
            content_hash.update(plain)
            dst_file.write(plain)
            # Throttle progress callbacks to ~1% intervals to avoid
            # flooding the Tk event queue on large files (especially
            # volume files decrypted at 64 KB granularity).
            if progress_cb and chunk_count:
                pct = (i + 1) / chunk_count
                if pct - last_report >= 0.01 or i + 1 == chunk_count:
                    progress_cb(f"Decrypting payload (AES-256-GCM)... {int(pct*100)}%")
                    last_report = pct

    return content_hash.hexdigest()




# ── v1 Streaming API ──────────────────────────────────────────────────────────
# These functions write/read the chunked payload from disk and return/accept
# the metadata dict.  The caller (encryptor.py / decryptor.py) handles the
# outer file assembly (magic + meta JSON at tail).

def encrypt_single_streaming(
    src_path: str,
    dst_file: IO[bytes],
    password: str,
    filename: str = "",
    progress_cb: Callable[[str], None] | None = None,
) -> dict:
    """
    v1: Stream-encrypt src_path into dst_file (already open, positioned after
    any embedded binary).  Returns the metadata dict (to be written as tail).
    RAM usage: O(CHUNK_SIZE), not O(file_size).
    """
    def _p(m): progress_cb and progress_cb(m)
    payload_size = os.path.getsize(src_path)
    _p("Deriving 512-bit password key (Argon2id)...")
    argon_salt = secrets.token_bytes(32)
    argon_key  = argon2id_derive(password.encode(), argon_salt)
    _p("Generating Kyber-768 keypair...")
    pk, sk = kyber_keygen()
    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk)
    final_key = xor_bytes(argon_key, kem_ss)
    _p("Encrypting Kyber private key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(argon_key, sk)

    # Stream the payload as chunks (also computes plaintext SHA-256 incrementally)
    _p("Encrypting payload (AES-256-GCM, 512-bit key material)...")
    base_nonce, chunk_count, _, content_sha256 = stream_encrypt_payload(
        src_path, dst_file, final_key, payload_size, progress_cb)

    # Encrypt filename + metadata separately (tiny, in-memory) so it's authenticated.
    # The content hash is stored here so it's only revealed after successful decryption.
    fname_plain = json.dumps({"n": filename, "sz": payload_size,
                               "ts": int(time.time()),
                               "sha256": content_sha256},
                              separators=(",", ":")).encode()
    fname_nonce, fname_ct = aes_gcm_encrypt(final_key, fname_plain)

    def b64(b): return base64.b64encode(b).decode()
    auth_fields = {
        "argon_salt":          b64(argon_salt),
        "kyber_kem_ct":        b64(kem_ct),
        "kyber_sk_enc_nonce":  b64(sk_nonce),
        "kyber_sk_enc":        b64(sk_ct),
        "payload_nonce":       b64(base_nonce),
        "payload_chunk_count": chunk_count,
        "filename_nonce":      b64(fname_nonce),
        "filename_enc":        b64(fname_ct),
    }
    meta = {"version": FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "chunk_size": CHUNK_SIZE, **auth_fields}
    meta["hmac"] = _meta_hmac(final_key, auth_fields)
    return meta


def encrypt_shamir_streaming(
    src_path: str,
    dst_file: IO[bytes],
    n: int,
    k: int,
    filename: str = "",
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[dict, list[str]]:
    """
    v1: Stream-encrypt src_path into dst_file using Shamir key split.
    Returns (meta_dict, share_strings).
    """
    def _p(m): progress_cb and progress_cb(m)
    payload_size = os.path.getsize(src_path)
    _p("Generating 512-bit random master key...")
    master_key = secrets.token_bytes(KEY_BYTES)
    _p("Generating Kyber-768 keypair...")
    pk, sk = kyber_keygen()
    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk)
    final_key = xor_bytes(master_key, kem_ss)
    _p("Encrypting Kyber private key under master key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(master_key, sk)

    # Stream the payload as chunks (also computes plaintext SHA-256 incrementally)
    _p("Encrypting payload (AES-256-GCM, 512-bit key material)...")
    base_nonce, chunk_count, _, content_sha256 = stream_encrypt_payload(
        src_path, dst_file, final_key, payload_size, progress_cb)

    # Encrypt filename + metadata separately (tiny, in-memory) so it's authenticated.
    # The content hash is stored here so it's only revealed after successful decryption.
    fname_plain = json.dumps({"n": filename, "sz": payload_size,
                               "ts": int(time.time()),
                               "sha256": content_sha256},
                              separators=(",", ":")).encode()
    fname_nonce, fname_ct = aes_gcm_encrypt(final_key, fname_plain)

    _p(f"Splitting 512-bit key into {n} shares over M521 (threshold {k})...")
    raw_shares    = shamir_split(master_key, n, k)
    share_strings = [encode_share(s) for s in raw_shares]

    def b64(b): return base64.b64encode(b).decode()
    auth_fields = {
        "kyber_kem_ct":        b64(kem_ct),
        "kyber_sk_enc_nonce":  b64(sk_nonce),
        "kyber_sk_enc":        b64(sk_ct),
        "payload_nonce":       b64(base_nonce),
        "payload_chunk_count": chunk_count,
        "filename_nonce":      b64(fname_nonce),
        "filename_enc":        b64(fname_ct),
    }
    meta = {"version": FORMAT_VERSION, "mode": "shamir", "key_bits": 512,
            "threshold": k, "total": n, "chunk_size": CHUNK_SIZE, **auth_fields}
    meta["hmac"] = _meta_hmac(master_key, auth_fields)
    return meta, share_strings


def decrypt_streaming(
    src_path: str,
    dst_file: IO[bytes],
    meta: dict,
    final_key: bytes,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[str, int, int]:
    """
    v1: Stream-decrypt chunked payload from src_path into dst_file.
    payload_offset is read from meta (set by the encryptor to skip any embedded binary).
    Returns (filename, sz, ts) where filename is the original filename, sz is the
    original file size in bytes, and ts is the Unix timestamp of encryption.
    """
    def _p(m): progress_cb and progress_cb(m)
    def d64(k): return base64.b64decode(meta[k])

    payload_offset = meta.get("payload_offset", 0)
    chunk_count    = meta["payload_chunk_count"]
    base_nonce     = d64("payload_nonce")

    _p("Decrypting payload (AES-256-GCM)...")
    decrypted_sha256 = stream_decrypt_payload(
        src_path, dst_file, final_key,
        payload_offset, chunk_count, base_nonce, progress_cb)

    # Decrypt the filename/size/ts/sha256 envelope
    fname_plain = aes_gcm_decrypt(final_key, d64("filename_nonce"), d64("filename_enc"))
    inner = json.loads(fname_plain)

    # Verify content integrity: compare the SHA-256 of the decrypted output
    # against the hash recorded at encryption time.  This catches disk errors,
    # partial writes, or any corruption that somehow survives per-chunk GCM auth.
    # Gracefully skip for files encrypted before this feature was added.
    expected_sha256 = inner.get("sha256")
    if expected_sha256 and decrypted_sha256 != expected_sha256:
        raise ValueError(
            "Content integrity check failed — the decrypted output does not match "
            "the original file. The file may have been corrupted."
        )

    return inner.get("n", ""), inner.get("sz", 0), inner.get("ts", 0)


# ── Mnemonic Encoding (BIP-39 wordlist, 50 words per share) ───────────────────
# Layout (545 bits total → 50 × 11-bit words):
#   [521 bits: value] [8 bits: index] [8 bits: threshold] [8 bits: SHA-256 checksum]
# Value occupies the high bits so the first word draws from the full 2048-word vocabulary.
# The M521 modulus is a constant and never stored in the share.

_INDEX_BITS     = 8
_THRESHOLD_BITS = 8
_VALUE_BITS     = 521
_CHECKSUM_BITS  = 8
_TOTAL_BITS     = _INDEX_BITS + _THRESHOLD_BITS + _VALUE_BITS + _CHECKSUM_BITS  # 545
_NUM_WORDS      = math.ceil(_TOTAL_BITS / 11)  # 50

_WORDLIST_CACHE = None
def _load_wordlist():
    global _WORDLIST_CACHE
    if _WORDLIST_CACHE is None:
        from mnemonic import Mnemonic
        _WORDLIST_CACHE = Mnemonic('english').wordlist
    return _WORDLIST_CACHE

def _int_to_words(n: int, bit_length: int, wordlist: list) -> list:
    num_words = math.ceil(bit_length / 11)
    result = []
    remaining = num_words * 11
    for _ in range(num_words):
        remaining -= 11
        result.append(wordlist[(n >> remaining) & 0x7FF])
    return result

def _words_to_int(words: list, bit_length: int, wordlist: list) -> int:
    n = 0
    for w in words:
        n = (n << 11) | wordlist.index(w.lower())
    return n & ((1 << bit_length) - 1)

def share_to_mnemonic(share_dict: dict) -> str:
    """
    Encode a share dict into a 50-word mnemonic phrase.
    All data (index, threshold, value) is packed with an 8-bit SHA-256 checksum.
    The M521 modulus is not stored — it's a constant recovered at decode time.

    Bit layout (value-first for word diversity):
      [521 bits: value] [8 bits: index] [8 bits: threshold] [8 bits: checksum]
    Value occupies the high bits so the first word of the mnemonic is drawn
    from the full 2048-word BIP-39 vocabulary, not biased toward word 0.
    """
    wordlist  = _load_wordlist()
    index     = share_dict["index"]
    threshold = share_dict.get("threshold", 0)  # optional, stored for self-containment
    value     = share_dict["value"]

    # Pack bits: value in HIGH bits, then index, then threshold
    # Layout: value(521) | index(8) | threshold(8)
    data_bits  = _VALUE_BITS + _INDEX_BITS + _THRESHOLD_BITS  # 537
    packed     = (value << (_INDEX_BITS + _THRESHOLD_BITS)) | (index << _THRESHOLD_BITS) | threshold
    packed_len = math.ceil(data_bits / 8)
    packed_bytes = packed.to_bytes(packed_len, "big")

    # 8-bit checksum
    checksum   = hashlib.sha256(packed_bytes).digest()[0]
    full_int   = (packed << _CHECKSUM_BITS) | checksum

    words = _int_to_words(full_int, _TOTAL_BITS, wordlist)
    if len(words) != _NUM_WORDS:
        raise ValueError(f"Internal error: generated {len(words)} words, expected {_NUM_WORDS}")
    return " ".join(words)


def mnemonic_to_share(mnemonic: str) -> dict:
    """
    Decode a 50-word mnemonic back into a share dict.
    Raises ValueError on bad word or checksum mismatch.
    """
    wordlist = _load_wordlist()
    words    = mnemonic.strip().split()

    if len(words) != _NUM_WORDS:
        raise ValueError(f"Expected {_NUM_WORDS} words, got {len(words)}")

    # Check all words are valid
    bad = [w for w in words if w.lower() not in wordlist]
    if bad:
        raise ValueError(f"Unknown word(s): {', '.join(bad)}")

    full_int = _words_to_int(words, _TOTAL_BITS, wordlist)

    checksum        = full_int & 0xFF
    packed          = full_int >> _CHECKSUM_BITS
    data_bits       = _VALUE_BITS + _INDEX_BITS + _THRESHOLD_BITS
    packed_bytes    = packed.to_bytes(math.ceil(data_bits / 8), "big")
    expected_cs     = hashlib.sha256(packed_bytes).digest()[0]

    if checksum != expected_cs:
        raise ValueError(
            f"Checksum mismatch (got {checksum:#04x}, expected {expected_cs:#04x}) — "
            "share may have a typo or been corrupted"
        )

    # Unpack: value in high bits, then index, then threshold
    threshold = packed & 0xFF
    index     = (packed >> _THRESHOLD_BITS) & 0xFF
    value     = packed >> (_INDEX_BITS + _THRESHOLD_BITS)

    return {
        "index":     index,
        "value":     value,
        "modulus":   SHAMIR_PRIME,
        "threshold": threshold,
    }


MNEMONIC_WORDS_PER_SHARE = _NUM_WORDS  # 50
