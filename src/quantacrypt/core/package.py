"""High-level .qcx operations shared by every front end.

Everything here is UI-agnostic: paths in, paths out, progress as strings,
cancellation as a predicate.  The Tk wizards and the ``qc-core`` service
both build on these so key derivation, output naming, and folder staging
exist exactly once.
"""

from __future__ import annotations

import base64 as _b64
import json
import os
import struct
import tempfile
import zipfile
from typing import Callable, Iterable

from quantacrypt.core import crypto as cc
from quantacrypt.core.crypto import (
    MAGIC, MIN_FORMAT_VERSION, MAX_FORMAT_VERSION, CancelledOperation,
)
from quantacrypt.core.errors import CorruptPayload, InvalidInput, InvalidRequest

Progress = Callable[[str], None] | None
CancelCheck = Callable[[], bool] | None

_MAX_TAIL = 1 << 20  # 1 MB tail search window for the metadata envelope


# ── Parsing ───────────────────────────────────────────────────────────────────

def load_pkg(path: str) -> dict:
    """Parse a .qcx file's metadata envelope without reading the payload.

    Raises ``ValueError`` with a user-readable reason for anything that is
    not a supported QuantaCrypt file.
    """
    file_size = os.path.getsize(path)
    tail_size = min(file_size, _MAX_TAIL)
    with open(path, "rb") as f:
        f.seek(file_size - tail_size)
        tail = f.read(tail_size)
    i = tail.rfind(MAGIC)
    if i < 0:
        raise ValueError("Not a QuantaCrypt file")
    o = i + len(MAGIC)
    if o + 4 > len(tail):
        raise ValueError("File appears truncated or corrupt")
    n = struct.unpack(">I", tail[o:o + 4])[0]
    if o + 4 + n > len(tail):
        raise ValueError("File appears truncated or corrupt")
    pkg = json.loads(tail[o + 4:o + 4 + n])
    if not isinstance(pkg, dict):
        raise ValueError("File metadata envelope is not a valid dictionary — file may be corrupt")
    meta = pkg.get("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("File metadata is not a valid dictionary — file may be corrupt")
    ver = meta.get("version", 1)
    if ver > MAX_FORMAT_VERSION:
        raise ValueError(
            f"This file was created with a newer version of QuantaCrypt (format v{ver}). "
            f"Please upgrade the app."
        )
    if ver < MIN_FORMAT_VERSION:
        raise ValueError(
            f"This file uses an older format (v{ver}) that is no longer supported. "
            f"Use an older version of QuantaCrypt to decrypt it, "
            f"then re-encrypt with this version."
        )
    if "mode" not in meta:
        raise ValueError("File metadata is missing required field 'mode' — file may be corrupt")
    if meta["mode"] not in ("single", "shamir"):
        raise ValueError(f"Unknown encryption mode {meta['mode']!r} — file may be corrupt or from an unsupported version")
    if meta["mode"] == "shamir":
        for field in ("threshold", "total"):
            if field not in meta:
                raise ValueError(f"Shamir file metadata is missing required field '{field}' — file may be corrupt")
        if not (2 <= meta["threshold"] <= meta["total"] <= 255):
            raise ValueError(f"Invalid Shamir parameters: threshold={meta.get('threshold')}, total={meta.get('total')}")
    return pkg


def inspect_summary(path: str) -> dict:
    """What can be said about a .qcx without any credential."""
    meta = load_pkg(path)["meta"]
    return {
        "path": path,
        "size": os.path.getsize(path),
        "version": meta.get("version", 1),
        "mode": meta["mode"],
        "threshold": meta.get("threshold"),
        "total": meta.get("total"),
        "embedded": bool(meta.get("payload_offset")),
        "argon2": "argon_salt" in meta,
    }


# ── Shares ───────────────────────────────────────────────────────────────────

def normalize_shares(shares: Iterable[str]) -> list[str]:
    """Accept QCSHARE- codes or 50-word mnemonics (mixed), return codes,
    de-duplicated, in input order.  Raises ``ValueError`` on an unreadable
    share so the caller can name which one."""
    codes: list[str] = []
    seen: set[str] = set()
    for i, raw in enumerate(shares, 1):
        s = (raw or "").strip()
        if not s:
            continue
        try:
            if s.upper().startswith("QCSHARE-"):
                code = cc.encode_share(cc.decode_share(s))
            else:
                code = cc.encode_share(cc.mnemonic_to_share(" ".join(s.split())))
        except Exception as exc:
            raise InvalidInput(f"Share {i} can't be read — {exc}") from exc
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)
    return codes


def extract_share_codes(text: str) -> list[str]:
    """Find every share in free text (share files, pasted notes) as QCSHARE-
    codes, in order of appearance.  Tolerates headers and prose: QCSHARE-
    lines are taken as-is; runs of BIP-39 words are gathered and converted
    when a run reaches the 50-word share length.  Duplicates collapse.
    Used by both UIs so "Load from file…" and "Paste all" agree."""
    codes: list[str] = []
    seen: set[str] = set()
    lines = [ln.strip() for ln in (text or "").splitlines()]
    for ln in lines:
        if ln.upper().startswith("QCSHARE-"):
            try:
                code = cc.encode_share(cc.decode_share(ln))
            except Exception:
                continue
            if code not in seen:
                seen.add(code); codes.append(code)
    try:
        wl_set = set(cc._load_wordlist())
    except Exception:  # wordlist unavailable — codes only
        return codes
    block: list[str] = []

    def _flush():
        if len(block) == cc.MNEMONIC_WORDS_PER_SHARE:
            try:
                code = cc.encode_share(cc.mnemonic_to_share(" ".join(block)))
            except Exception:
                code = None
            if code and code not in seen:
                seen.add(code); codes.append(code)
        block.clear()

    for ln in lines:
        toks = ln.lower().split()
        if toks and all(t in wl_set for t in toks):
            block.extend(toks)
            if len(block) > cc.MNEMONIC_WORDS_PER_SHARE:
                del block[:-cc.MNEMONIC_WORDS_PER_SHARE]
        else:
            _flush()
    _flush()
    return codes


def shares_with_mnemonics(shares: list[str], k: int) -> list[dict]:
    """Pair each share code with its mnemonic for display / saving."""
    out = []
    for i, s in enumerate(shares, 1):
        out.append({
            "index": i,
            "code": s,
            "mnemonic": cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k}),
        })
    return out


# ── Key derivation ───────────────────────────────────────────────────────────

def derive_final_key(meta: dict, *, password: str | None = None,
                     shares: Iterable[str] | None = None,
                     progress: Progress = None,
                     cancel_check: CancelCheck = None) -> tuple[bytes, bytes]:
    """Return ``(final_key, hmac_key)`` for a .qcx metadata dict.

    Single mode needs ``password``; Shamir mode needs at least ``threshold``
    distinct ``shares`` (codes or mnemonics).  Verifies the metadata HMAC
    before returning, so a wrong credential surfaces here.
    """
    def _p(m):
        if progress:
            progress(m)

    def _check():
        if cancel_check and cancel_check():
            raise CancelledOperation("Cancelled")

    def d64(k):
        return _b64.b64decode(meta[k])

    if meta["mode"] == "single":
        if not password:
            raise InvalidInput("A password is required to open this file")
        _p("Deriving 512-bit password key (Argon2id)...")
        pw_bytes = password.encode()
        argon_key = cc.argon2id_derive(pw_bytes, d64("argon_salt"))
        del pw_bytes
        _check()
        _p("Decrypting Kyber private key...")
        sk = cc.aes_gcm_decrypt(argon_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
        _check()
        _p("Decapsulating shared secret...")
        kem_ss = cc.kyber_decaps(sk, d64("kyber_kem_ct"))
        final_key = cc.xor_bytes(argon_key, kem_ss)
        hmac_key = final_key
    else:
        k = meta["threshold"]
        codes = normalize_shares(shares or [])
        if len(codes) < k:
            raise InvalidInput(
                f"Need {k} different shares to open this file, got {len(codes)}")
        _p(f"Combining {k} shares to recover the key...")
        share_dicts = [cc.decode_share(s) for s in codes[:k]]
        master_key = cc.shamir_recover(share_dicts)
        _check()
        _p("Decrypting Kyber private key...")
        sk = cc.aes_gcm_decrypt(master_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
        _check()
        _p("Decapsulating shared secret...")
        kem_ss = cc.kyber_decaps(sk, d64("kyber_kem_ct"))
        final_key = cc.xor_bytes(master_key, kem_ss)
        hmac_key = master_key
    _check()
    cc._verify_meta_hmac(hmac_key, meta)
    return final_key, hmac_key


def verify_first_chunk(qcx_path: str, meta: dict, final_key: bytes) -> None:
    """Decrypt chunk 0 only — proves the key without writing any output.
    Raises on a wrong key or a corrupt/truncated payload."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # The filename envelope is always present and encrypted under the same
    # key, so it proves the key even for a 0-byte payload (which has no
    # chunk to decrypt).
    cc.aes_gcm_decrypt(final_key, _b64.b64decode(meta["filename_nonce"]),
                       _b64.b64decode(meta["filename_enc"]))
    if meta.get("payload_chunk_count", 0) == 0:
        return
    payload_offset = meta.get("payload_offset", 0)
    base_nonce = _b64.b64decode(meta["payload_nonce"])
    cipher = AESGCM(cc.derive_aes_key(final_key))
    with open(qcx_path, "rb") as f:
        f.seek(payload_offset)
        seq_raw = f.read(4)
        if len(seq_raw) < 4:
            raise ValueError("File appears truncated")
        seq = struct.unpack(">I", seq_raw)[0]
        if seq != 0:
            raise ValueError(f"First chunk has unexpected sequence number {seq} — file may be corrupt")
        len_raw = f.read(4)
        if len(len_raw) < 4:
            raise ValueError("File appears truncated")
        ct_len = struct.unpack(">I", len_raw)[0]
        if ct_len > cc.CHUNK_SIZE + 16:
            raise ValueError(
                f"Chunk declares an implausible size ({ct_len} bytes) — file may be corrupt")
        ct = f.read(ct_len)
    nonce = cc._chunk_nonce(base_nonce, 0)
    aad = cc._chunk_aad(0, meta["payload_chunk_count"] == 1)
    try:
        cipher.decrypt(nonce, ct, aad)
    except Exception as exc:  # InvalidTag: the key is proven, so the data is bad
        raise CorruptPayload(
            "The file's contents are damaged or were altered after encryption — "
            "the password is right, but this copy can't be restored. Try another "
            "copy or a backup.") from exc


# ── Output naming ─────────────────────────────────────────────────────────────

def safe_output_name(fname: str | None) -> str:
    """Original filename from the payload → a name safe to create.
    basename() blocks traversal; control characters and NULs are dropped;
    an empty result becomes 'decrypted'."""
    name = os.path.basename(fname or "")
    name = "".join(ch for ch in name if ch.isprintable() and ch not in ("/", "\0"))
    name = name.strip()
    # Keep a leading dot (hidden files like .env are legitimate names); only
    # the bare "." / ".." entries and trailing dots are dropped.
    name = name.rstrip(".")
    if name.strip(".") == "":
        name = ""
    return name or "decrypted"


def unique_path(out_dir: str, name: str) -> tuple[str, bool]:
    """``(path, renamed)`` — never overwrite: report.pdf → report_2.pdf."""
    out = os.path.join(out_dir, name)
    root, ext = os.path.splitext(name)
    n = 2
    while os.path.exists(out):
        out = os.path.join(out_dir, f"{root}_{n}{ext}")
        n += 1
    return out, n > 2


def _place_without_clobber(tmp: str, out_dir: str, name: str) -> tuple[str, bool]:
    """Move ``tmp`` to a fresh name in ``out_dir`` atomically: ``os.link``
    fails with EEXIST instead of replacing, so a file that appears between
    the existence check and the rename is never overwritten.  Falls back to
    ``os.replace`` on filesystems without hard links (exFAT, some SMB)."""
    renamed = False
    root, ext = os.path.splitext(name)
    n = 1
    while True:
        cand = os.path.join(out_dir, name if n == 1 else f"{root}_{n}{ext}")
        try:
            os.link(tmp, cand)
        except FileExistsError:
            n += 1; renamed = True
            continue
        except OSError:
            cand, renamed = unique_path(out_dir, name)
            os.replace(tmp, cand)
            return cand, renamed
        os.unlink(tmp)
        return cand, renamed


def batch_output_paths(paths: list[str], out_dir: str) -> list[str]:
    """Map each batch input to a UNIQUE <stem>.qcx in out_dir.

    Inputs with colliding stems (report.txt + report.md) must not map to
    the same output — the second os.replace would silently destroy the
    first file's ciphertext while both show as succeeded.
    """
    outs, used = [], set()
    for p in paths:
        stem = os.path.splitext(os.path.basename(p))[0]
        cand, i = stem, 2
        while (cand + ".qcx").lower() in used:
            cand = f"{stem}_{i}"
            i += 1
        used.add((cand + ".qcx").lower())
        outs.append(os.path.join(out_dir, cand + ".qcx"))
    return outs


# ── Folders ───────────────────────────────────────────────────────────────────

def folder_stats(folder: str) -> tuple[int, int]:
    """Return (file_count, total_bytes) for a folder tree."""
    count, total = 0, 0
    for dirpath, _, filenames in os.walk(folder):
        for fn in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
            count += 1
    return count, total


def zip_folder(folder: str, dst_path: str, progress_cb: Progress = None,
               cancel_check: CancelCheck = None) -> None:
    """Zip folder into dst_path with paths relative to folder's parent so the
    top-level directory name survives inside the archive.  The archive being
    written is skipped if the walk reaches it (output inside source)."""
    parent = os.path.dirname(os.path.abspath(folder))
    dst_abs = os.path.abspath(dst_path)
    total_files, _ = folder_stats(folder)
    done = 0
    with zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for dirpath, dirnames, filenames in os.walk(folder):
            dirnames.sort()
            filenames.sort()
            for fn in filenames:
                if cancel_check and cancel_check():
                    raise CancelledOperation("Compression cancelled")
                full = os.path.join(dirpath, fn)
                if os.path.abspath(full) == dst_abs:
                    continue
                zf.write(full, os.path.relpath(full, parent))
                done += 1
                if progress_cb and total_files:
                    pct = done / total_files
                    progress_cb(f"Compressing folder… {int(pct * 100)}% ({done}/{total_files} files)")


# ── Encrypt / decrypt ─────────────────────────────────────────────────────────

def encrypt_to_qcx(source: str, output: str, *, mode: str,
                   password: str | None = None, k: int | None = None,
                   n: int | None = None, progress: Progress = None,
                   cancel_check: CancelCheck = None,
                   embed_binary: str | None = None) -> dict:
    """Encrypt a file or folder to ``output`` (.qcx).  Atomic: writes to
    ``output + '.tmp'`` and renames.  Folders are zipped first to a 0600
    staging file beside the output.  Returns a JSON-able summary."""
    if mode not in ("password", "single", "shamir"):
        raise InvalidRequest(f"Unknown mode {mode!r}")
    single = mode in ("password", "single")
    if single and not password:
        raise InvalidInput("A password is required")
    if not single and not (k and n and 2 <= k <= n <= 255):
        raise InvalidRequest("Split-key mode needs 2 <= k <= n <= 255")
    if not os.path.exists(source):
        raise FileNotFoundError(source)
    out_abs = os.path.abspath(output)
    src_abs = os.path.abspath(source)
    is_folder = os.path.isdir(source)
    if out_abs == src_abs:
        raise InvalidInput("The output file can't be the source file itself")
    if is_folder and out_abs.startswith(src_abs + os.sep):
        raise InvalidInput("The output file can't be inside the folder being encrypted")

    staging = None
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(out_abs)}.qc-enc-",
                               dir=os.path.dirname(out_abs) or None)
    os.close(fd)
    try:
        if is_folder:
            fd, staging = tempfile.mkstemp(
                prefix=f".{os.path.basename(out_abs)}.qc-staging-", suffix=".zip",
                dir=os.path.dirname(out_abs) or None)
            os.close(fd)
            zip_folder(source, staging, progress_cb=progress, cancel_check=cancel_check)
            src_path = staging
            orig = os.path.basename(src_abs.rstrip(os.sep)) + ".zip"
        else:
            src_path = source
            orig = os.path.basename(source)

        with open(tmp, "wb") as f:
            if embed_binary:
                with open(embed_binary, "rb") as df:
                    while True:
                        chunk = df.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
            payload_offset = f.tell()
            if single:
                meta = cc.encrypt_single_streaming(
                    src_path, f, password, filename=orig,
                    progress_cb=progress, cancel_check=cancel_check)
                shares: list[str] = []
            else:
                meta, shares = cc.encrypt_shamir_streaming(
                    src_path, f, n, k, filename=orig,
                    progress_cb=progress, cancel_check=cancel_check)
            meta["payload_offset"] = payload_offset
            if progress:
                progress("Writing binary... 100%")
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        os.replace(tmp, out_abs)
        if embed_binary:
            try:
                os.chmod(out_abs, os.stat(out_abs).st_mode | 0o110)
            except OSError:
                pass
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    finally:
        if staging:
            try:
                os.remove(staging)
            except OSError:
                pass
    return {
        "output": out_abs,
        "size": os.path.getsize(out_abs),
        "filename": orig,
        "mode": "single" if single else "shamir",
        "threshold": None if single else k,
        "total": None if single else n,
        "shares": [] if single else shares_with_mnemonics(shares, k),
    }


def decrypt_qcx(path: str, output_dir: str, *, password: str | None = None,
                shares: Iterable[str] | None = None, verify_only: bool = False,
                progress: Progress = None, cancel_check: CancelCheck = None) -> dict:
    """Decrypt ``path`` into ``output_dir`` under its original filename, or
    just prove the credentials when ``verify_only``.  Never overwrites."""
    meta = load_pkg(path)["meta"]
    final_key, _hmac_key = derive_final_key(
        meta, password=password, shares=shares,
        progress=progress, cancel_check=cancel_check)
    if verify_only:
        if progress:
            progress("Checking file integrity...")
        verify_first_chunk(path, meta, final_key)
        return {"verified": True, "mode": meta["mode"]}

    if not os.path.isdir(output_dir):
        raise InvalidInput(f"The output folder doesn't exist: {output_dir}")
    fd, tmp = tempfile.mkstemp(prefix=".qc-decrypt-", dir=output_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            try:
                fname, orig_size, ts = cc.decrypt_streaming(
                    path, f, meta, final_key,
                    progress_cb=progress, cancel_check=cancel_check)
            except CancelledOperation:
                raise
            except Exception as exc:
                low = (str(exc) or type(exc).__name__).lower()
                if "invalidtag" in low or "authentication" in low:
                    # derive_final_key already proved the key (envelope +
                    # HMAC), so a chunk that fails to authenticate is damage.
                    raise CorruptPayload(
                        "The file's contents are damaged or were altered after "
                        "encryption — the password is right, but this copy can't "
                        "be restored. Try another copy or a backup.") from exc
                raise
        name = safe_output_name(fname)
        out, renamed = _place_without_clobber(tmp, output_dir, name)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    if ts:
        try:
            os.utime(out, (ts, ts))
        except OSError:
            pass
    return {
        "output": out,
        "filename": name,
        "size": os.path.getsize(out),
        "original_size": orig_size,
        "timestamp": ts,
        "renamed": renamed,
    }
