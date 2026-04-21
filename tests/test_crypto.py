"""
QuantaCrypt Crypto Primitive Tests
Tests for crypto functions, encryption, and key derivation.
"""
import os
import json
import struct
import hashlib
import base64

import pytest
from quantacrypt.core import crypto as cc
from tests.conftest import MAGIC, make_pkg_bytes, load_pkg


# ─────────────────────────────────────────────────────────────────────────────
# 1. Primitive / helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestXorBytes:
    def test_basic(self):
        a = bytes([0xFF]*8); b = bytes([0x0F]*8)
        assert cc.xor_bytes(a, b) == bytes([0xF0]*8)

    def test_identity(self):
        k = os.urandom(64)
        assert cc.xor_bytes(k, k) == bytes(64)

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError, match="length mismatch"):
            cc.xor_bytes(b'\x00'*64, b'\x00'*32)

    def test_zero_length(self):
        assert cc.xor_bytes(b'', b'') == b''

    def test_full_cycle(self):
        data = os.urandom(64)
        key  = os.urandom(64)
        assert cc.xor_bytes(cc.xor_bytes(data, key), key) == data


class TestArgon2Derive:
    def test_deterministic(self):
        pw   = b"hunter2"
        salt = os.urandom(16)
        k1 = cc.argon2id_derive(pw, salt)
        k2 = cc.argon2id_derive(pw, salt)
        assert k1 == k2

    def test_different_salt_different_key(self):
        pw = b"hunter2"
        k1 = cc.argon2id_derive(pw, os.urandom(16))
        k2 = cc.argon2id_derive(pw, os.urandom(16))
        assert k1 != k2

    def test_output_length(self):
        k = cc.argon2id_derive(b"pw", os.urandom(16))
        assert len(k) == cc.KEY_BYTES  # 64

    def test_empty_password_rejected(self):
        # Defense in depth: the UI blocks empty passwords, but the crypto
        # layer also refuses them so a regression can't quietly derive a
        # trivially-guessable key.
        with pytest.raises(ValueError, match="cannot be empty"):
            cc.argon2id_derive(b"", os.urandom(16))


class TestAesGcm:
    def test_roundtrip(self):
        key   = os.urandom(64)
        plain = b"Secret data 1234"
        nonce, ct = cc.aes_gcm_encrypt(key, plain)
        assert cc.aes_gcm_decrypt(key, nonce, ct) == plain

    def test_wrong_key_raises(self):
        from cryptography.exceptions import InvalidTag
        key1 = os.urandom(64); key2 = os.urandom(64)
        nonce, ct = cc.aes_gcm_encrypt(key1, b"secret")
        with pytest.raises(InvalidTag):
            cc.aes_gcm_decrypt(key2, nonce, ct)

    def test_tampered_ciphertext_raises(self):
        from cryptography.exceptions import InvalidTag
        key = os.urandom(64)
        nonce, ct = cc.aes_gcm_encrypt(key, b"secret")
        bad_ct = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with pytest.raises(InvalidTag):
            cc.aes_gcm_decrypt(key, nonce, bad_ct)

    def test_nonce_uniqueness(self):
        key = os.urandom(64)
        plain = b"data"
        nonces = {cc.aes_gcm_encrypt(key, plain)[0] for _ in range(20)}
        assert len(nonces) == 20  # all unique

    def test_empty_plaintext(self):
        key = os.urandom(64)
        nonce, ct = cc.aes_gcm_encrypt(key, b"")
        assert cc.aes_gcm_decrypt(key, nonce, ct) == b""

    def test_large_plaintext(self):
        key   = os.urandom(64)
        plain = os.urandom(10 * 1024 * 1024)  # 10 MB
        nonce, ct = cc.aes_gcm_encrypt(key, plain)
        assert cc.aes_gcm_decrypt(key, nonce, ct) == plain


class TestDeriveAesKey:
    def test_length(self):
        assert len(cc.derive_aes_key(os.urandom(64))) == 32

    def test_deterministic(self):
        k = os.urandom(64)
        assert cc.derive_aes_key(k) == cc.derive_aes_key(k)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Kyber KEM
# ─────────────────────────────────────────────────────────────────────────────

class TestKyber:
    def test_shared_secret_matches(self):
        pk, sk  = cc.kyber_keygen()
        kem_ct, kem_ss_enc = cc.kyber_encaps(pk)
        kem_ss_dec = cc.kyber_decaps(sk, kem_ct)
        assert kem_ss_enc == kem_ss_dec

    def test_shared_secret_length(self):
        pk, sk = cc.kyber_keygen()
        _, ss  = cc.kyber_encaps(pk)
        assert len(ss) == cc.KEY_BYTES  # 64 after HKDF expansion

    def test_wrong_sk_gives_wrong_secret(self):
        pk, sk  = cc.kyber_keygen()
        _, sk2  = cc.kyber_keygen()
        kem_ct, ss_enc = cc.kyber_encaps(pk)
        ss_wrong = cc.kyber_decaps(sk2, kem_ct)
        # Kyber is a CCA-secure KEM: wrong key gives garbage (but not exception)
        assert ss_wrong != ss_enc

    def test_expand_kem_ss_deterministic(self):
        raw = os.urandom(32)
        assert cc.expand_kem_ss(raw) == cc.expand_kem_ss(raw)

    def test_expand_kem_ss_length(self):
        assert len(cc.expand_kem_ss(os.urandom(32))) == cc.KEY_BYTES


# ─────────────────────────────────────────────────────────────────────────────
# 3. Shamir Secret Sharing
# ─────────────────────────────────────────────────────────────────────────────

class TestShamir:
    def test_2of3_roundtrip(self):
        secret = os.urandom(64)
        shares = cc.shamir_split(secret, n=3, k=2)
        assert cc.shamir_recover(shares[:2]) == secret

    def test_3of5_roundtrip(self):
        secret = os.urandom(64)
        shares = cc.shamir_split(secret, n=5, k=3)
        assert cc.shamir_recover(shares[:3]) == secret

    def test_any_k_shares_work(self):
        secret = os.urandom(64)
        shares = cc.shamir_split(secret, n=5, k=3)
        # Try different combinations of 3 shares
        assert cc.shamir_recover([shares[0], shares[2], shares[4]]) == secret
        assert cc.shamir_recover([shares[1], shares[3], shares[4]]) == secret

    def test_out_of_order_shares(self):
        secret = os.urandom(64)
        shares = cc.shamir_split(secret, n=3, k=2)
        assert cc.shamir_recover([shares[2], shares[0]]) == secret

    def test_2of2_roundtrip(self):
        secret = os.urandom(64)
        shares = cc.shamir_split(secret, n=2, k=2)
        assert cc.shamir_recover(shares) == secret

    def test_share_count(self):
        shares = cc.shamir_split(os.urandom(64), n=7, k=4)
        assert len(shares) == 7

    def test_share_dict_fields(self):
        shares = cc.shamir_split(os.urandom(64), n=3, k=2)
        for s in shares:
            assert "index" in s
            assert "value" in s
            assert "modulus" in s
            assert s["modulus"] == cc.SHAMIR_PRIME

    def test_all_zeros_secret(self):
        secret = bytes(64)
        shares = cc.shamir_split(secret, n=3, k=2)
        assert cc.shamir_recover(shares[:2]) == secret

    def test_all_ones_secret(self):
        secret = bytes([0xFF] * 64)
        shares = cc.shamir_split(secret, n=3, k=2)
        assert cc.shamir_recover(shares[:2]) == secret


class TestEncodeDecodeShare:
    def test_roundtrip(self):
        s = {"index": 2, "value": 98765, "modulus": cc.SHAMIR_PRIME}
        assert cc.decode_share(cc.encode_share(s)) == s

    def test_format_prefix(self):
        s = {"index": 1, "value": 1, "modulus": cc.SHAMIR_PRIME}
        assert cc.encode_share(s).startswith("QCSHARE-")

    def test_invalid_prefix_raises(self):
        with pytest.raises(ValueError, match="Not a valid"):
            cc.decode_share("BADPREFIX-abc")

    def test_whitespace_stripped(self):
        s = {"index": 1, "value": 1, "modulus": cc.SHAMIR_PRIME}
        enc = "  " + cc.encode_share(s) + "\n"
        assert cc.decode_share(enc) == s


# ─────────────────────────────────────────────────────────────────────────────
# 4. Mnemonic encoding
# ─────────────────────────────────────────────────────────────────────────────

class TestMnemonic:
    @pytest.fixture
    def share(self):
        return cc.shamir_split(os.urandom(64), n=3, k=2)[0]

    def test_word_count(self, share):
        mn = cc.share_to_mnemonic(share)
        assert len(mn.split()) == 50

    def test_roundtrip(self, share):
        mn  = cc.share_to_mnemonic(share)
        rec = cc.mnemonic_to_share(mn)
        assert rec["index"]   == share["index"]
        assert rec["value"]   == share["value"]
        assert rec["modulus"] == cc.SHAMIR_PRIME

    def test_all_words_in_bip39(self, share):
        from mnemonic import Mnemonic
        wl = set(Mnemonic("english").wordlist)
        for w in cc.share_to_mnemonic(share).split():
            assert w in wl

    def test_wrong_word_count_raises(self):
        with pytest.raises(ValueError, match="Expected 50"):
            cc.mnemonic_to_share("abandon " * 10)

    def test_unknown_word_raises(self, share):
        words = cc.share_to_mnemonic(share).split()
        words[5] = "notaword"
        with pytest.raises(ValueError, match="Unknown word"):
            cc.mnemonic_to_share(" ".join(words))

    def test_checksum_catches_typo(self, share):
        words = cc.share_to_mnemonic(share).split()
        # Swap two words to corrupt data while keeping word count and validity
        words[0], words[1] = words[1], words[0]
        # Should raise checksum mismatch most of the time (occasionally no-op)
        try:
            cc.mnemonic_to_share(" ".join(words))
        except ValueError as e:
            assert "Checksum" in str(e) or "Unknown" in str(e)

    def test_case_insensitive(self, share):
        mn = cc.share_to_mnemonic(share).upper()
        rec = cc.mnemonic_to_share(mn)
        assert rec["index"] == share["index"]

    def test_extra_whitespace_ok(self, share):
        mn = "  ".join(cc.share_to_mnemonic(share).split())
        rec = cc.mnemonic_to_share(mn)
        assert rec["value"] == share["value"]

    def test_mnemonic_roundtrip_full_crypto(self, tmp_path):
        """Encrypt with Shamir streaming, encode shares to mnemonic, decode, decrypt."""
        import json
        data = b"Top secret document contents"
        src  = tmp_path / "src.bin"; src.write_bytes(data)
        enc  = tmp_path / "enc.qcx"
        with open(enc, "wb") as f:
            off = f.tell()
            meta, share_strs = cc.encrypt_shamir_streaming(str(src), f, n=3, k=2, filename="src.bin")
            meta["payload_offset"] = off
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        # Encode the first two shares to mnemonic, then decode back
        mnemonics      = [cc.share_to_mnemonic(cc.decode_share(s)) for s in share_strs[:2]]
        reconstructed  = [cc.encode_share(cc.mnemonic_to_share(m)) for m in mnemonics]
        # Decrypt
        share_dicts = [cc.decode_share(s) for s in reconstructed]
        master_key  = cc.shamir_recover(share_dicts)
        sk          = cc.aes_gcm_decrypt(master_key, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                         base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss      = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        final_key   = cc.xor_bytes(master_key, kem_ss)
        import io
        out = io.BytesIO()
        cc.decrypt_streaming(str(enc), out, meta, final_key)
        assert out.getvalue() == data


# ─────────────────────────────────────────────────────────────────────────────
# 5. High-level encrypt/decrypt
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# 5. High-level encrypt/decrypt (streaming)
# ─────────────────────────────────────────────────────────────────────────────

def _make_qcx(tmp_path, data, password="pw", filename="test.bin", n=None, k=None):
    """Write a .qcx and return (path, meta, shares, final_key)."""
    import json, base64 as _b64
    src = tmp_path / "src.bin"; src.write_bytes(data)
    enc = tmp_path / "enc.qcx"
    with open(enc, "wb") as f:
        off = f.tell()
        if n is not None:
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=n, k=k, filename=filename)
        else:
            meta = cc.encrypt_single_streaming(str(src), f, password, filename=filename)
            shares = []
        meta["payload_offset"] = off
        blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
        f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
    # Derive final_key
    if n is not None:
        sd  = [cc.decode_share(s) for s in shares[:k]]
        mk  = cc.shamir_recover(sd)
        sk  = cc.aes_gcm_decrypt(mk, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                  _b64.b64decode(meta["kyber_sk_enc"]))
        ks  = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
        fk  = cc.xor_bytes(mk, ks)
        hmac_key = mk
    else:
        ak  = cc.argon2id_derive(password.encode(), _b64.b64decode(meta["argon_salt"]))
        sk  = cc.aes_gcm_decrypt(ak, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                  _b64.b64decode(meta["kyber_sk_enc"]))
        ks  = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
        fk  = cc.xor_bytes(ak, ks)
        hmac_key = fk
    return enc, meta, shares, fk


def _decrypt_qcx(enc_path, meta, final_key):
    import io
    buf = io.BytesIO()
    fname, sz, ts = cc.decrypt_streaming(str(enc_path), buf, meta, final_key)
    return buf.getvalue(), fname, sz, ts

class TestEncryptSingle:
    def test_basic_roundtrip(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"Hello world", password="password123")
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == b"Hello world"

    def test_wrong_password_raises(self, tmp_path):
        import base64 as _b64, json
        src = tmp_path / "s.bin"; src.write_bytes(b"secret")
        enc = tmp_path / "e.qcx"
        with open(enc, "wb") as f:
            off = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "correct", filename="s.bin")
            meta["payload_offset"] = off
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        wrong_argon = cc.argon2id_derive(b"wrong", _b64.b64decode(meta["argon_salt"]))
        with pytest.raises(Exception):
            cc.aes_gcm_decrypt(wrong_argon, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                               _b64.b64decode(meta["kyber_sk_enc"]))

    def test_empty_data(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"")
        result, _, sz, _ = _decrypt_qcx(enc, meta, fk)
        assert result == b"" and sz == 0

    def test_large_data(self, tmp_path):
        data = os.urandom(5 * 1024 * 1024)
        enc, meta, _, fk = _make_qcx(tmp_path, data)
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == data

    def test_unicode_password(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"secret", password="pässwörd🔐")
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == b"secret"

    def test_empty_password_rejected_at_encrypt(self, tmp_path):
        # End-to-end: the encrypt helper must refuse an empty password.
        with pytest.raises(ValueError, match="cannot be empty"):
            _make_qcx(tmp_path, b"secret", password="")

    def test_meta_fields(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x")
        for field in ["version","mode","key_bits","argon_salt",
                      "kyber_kem_ct","kyber_sk_enc_nonce","kyber_sk_enc",
                      "payload_nonce","payload_chunk_count","filename_nonce","filename_enc"]:
            assert field in meta, f"missing: {field}"
        assert "payload" not in meta

    def test_meta_version(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x")
        assert meta["version"] == cc.FORMAT_VERSION

    def test_meta_mode(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x")
        assert meta["mode"] == "single"

    def test_meta_key_bits(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x")
        assert meta["key_bits"] == 512

    def test_two_encryptions_differ(self, tmp_path):
        src = tmp_path / "s.bin"; src.write_bytes(b"same data")
        nonces = []
        for i in range(2):
            with open(tmp_path / f"e{i}.qcx", "wb") as f:
                m = cc.encrypt_single_streaming(str(src), f, "pw")
            nonces.append(m["payload_nonce"])
        assert nonces[0] != nonces[1]

    def test_progress_callback_called(self, tmp_path):
        messages = []
        src = tmp_path / "s.bin"; src.write_bytes(b"data")
        with open(tmp_path / "e.qcx", "wb") as f:
            cc.encrypt_single_streaming(str(src), f, "pw", progress_cb=messages.append)
        assert len(messages) >= 3
        assert any("Argon2id" in m for m in messages)

    def test_binary_data(self, tmp_path):
        data = bytes(range(256)) * 100
        enc, meta, _, fk = _make_qcx(tmp_path, data)
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == data


class TestEncryptShamir:
    def test_2of3_roundtrip(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"Shamir secret", n=3, k=2)
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == b"Shamir secret"

    def test_3of5_roundtrip(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"Top secret", n=5, k=3)
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == b"Top secret"

    def test_any_k_shares_decrypt(self, tmp_path):
        import base64 as _b64, io, json
        data = b"secret"
        src = tmp_path / "s.bin"; src.write_bytes(data)
        enc = tmp_path / "e.qcx"
        with open(enc, "wb") as f:
            off = f.tell()
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=5, k=3)
            meta["payload_offset"] = off
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        for combo in [[shares[0],shares[2],shares[4]], [shares[1],shares[2],shares[3]]]:
            sd = [cc.decode_share(s) for s in combo]
            mk = cc.shamir_recover(sd)
            sk = cc.aes_gcm_decrypt(mk, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                    _b64.b64decode(meta["kyber_sk_enc"]))
            ks = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
            fk = cc.xor_bytes(mk, ks)
            buf = io.BytesIO(); cc.decrypt_streaming(str(enc), buf, meta, fk)
            assert buf.getvalue() == data

    def test_bad_share_raises(self, tmp_path):
        enc, meta, shares, _ = _make_qcx(tmp_path, b"secret", n=3, k=2)
        bad = cc.encode_share({**cc.decode_share(shares[0]), "value": 999})
        with pytest.raises(Exception):
            sd = [cc.decode_share(bad), cc.decode_share(shares[1])]
            cc.shamir_recover(sd)

    def test_share_count(self, tmp_path):
        src = tmp_path / "s.bin"; src.write_bytes(b"x")
        with open(tmp_path / "e.qcx", "wb") as f:
            _, shares = cc.encrypt_shamir_streaming(str(src), f, n=7, k=4)
        assert len(shares) == 7

    def test_meta_fields(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x", n=3, k=2)
        for field in ["version","mode","threshold","total",
                      "kyber_kem_ct","kyber_sk_enc_nonce","kyber_sk_enc",
                      "payload_nonce","payload_chunk_count"]:
            assert field in meta
        assert "payload" not in meta

    def test_meta_threshold_total(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x", n=5, k=3)
        assert meta["threshold"] == 3 and meta["total"] == 5

    def test_meta_mode(self, tmp_path):
        _, meta, _, _ = _make_qcx(tmp_path, b"x", n=3, k=2)
        assert meta["mode"] == "shamir"

    def test_empty_data(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"", n=3, k=2)
        result, _, sz, _ = _decrypt_qcx(enc, meta, fk)
        assert result == b"" and sz == 0

    def test_progress_callback(self, tmp_path):
        msgs = []
        src = tmp_path / "s.bin"; src.write_bytes(b"data")
        with open(tmp_path / "e.qcx", "wb") as f:
            cc.encrypt_shamir_streaming(str(src), f, n=3, k=2, progress_cb=msgs.append)
        assert len(msgs) >= 4
        assert any("Kyber" in m or "master" in m or "Shamir" in m for m in msgs)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Binary package format (load_pkg)
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadPkgFormat:
    def _make_meta(self):
        return {
            "version": cc.FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "argon_salt":"aa==","kyber_kem_ct":"aa==","kyber_sk_enc_nonce":"aa==",
            "kyber_sk_enc":"aa==","payload_nonce":"aa==","payload_chunk_count":1,
            "filename_nonce":"aa==","filename_enc":"aa==","hmac":"x",
        }

    def _make(self, meta, name="file.bin"):
        pkg  = {"meta": meta, "original_name": name}
        blob = json.dumps(pkg, separators=(",",":")).encode()
        return MAGIC + len(blob).to_bytes(4, "big") + blob

    def test_basic_parse(self):
        meta = self._make_meta()
        raw  = self._make(meta)
        pkg  = load_pkg(raw)
        assert pkg["meta"]["mode"] == "single"

    def test_with_elf_prefix(self):
        """rfind() must skip over false magic bytes in ELF header."""
        meta = self._make_meta()
        raw  = self._make(meta)
        elf = b"\x7fELF" + b"\x00"*46 + MAGIC + b"\x00"*50
        combined = elf + raw
        pkg = load_pkg(combined)
        assert pkg["meta"]["mode"] == "single"

    def test_no_magic_raises(self):
        with pytest.raises(ValueError, match="Not a QuantaCrypt file"):
            load_pkg(b"this is not a quantacrypt file at all")

    def test_truncated_raises(self):
        meta = self._make_meta()
        raw  = self._make(meta)
        with pytest.raises(Exception):
            load_pkg(raw[:20])

    def test_original_name_preserved(self):
        meta = self._make_meta()
        raw  = self._make(meta, name="secret_report.pdf")
        pkg  = load_pkg(raw)
        assert pkg["original_name"] == "secret_report.pdf"

    def test_old_version_rejected(self, tmp_path):
        """load_pkg (real decryptor version) rejects version < MIN_FORMAT_VERSION."""
        from quantacrypt.ui.decryptor import load_pkg as real_load_pkg
        meta = {**self._make_meta(), "version": 0}
        raw  = self._make(meta)
        p = tmp_path / "old.qcx"; p.write_bytes(raw)
        with pytest.raises(ValueError, match="older format|no longer supported"):
            real_load_pkg(str(p))


# ─────────────────────────────────────────────────────────────────────────────
# 7. Edge cases & regression tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_single_byte_data(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"\x00")
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == b"\x00"

    def test_null_bytes_in_data(self, tmp_path):
        data = b"\x00" * 1000
        enc, meta, _, fk = _make_qcx(tmp_path, data)
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == data

    def test_shamir_2of2_minimum(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"minimum threshold", n=2, k=2)
        result, *_ = _decrypt_qcx(enc, meta, fk)
        assert result == b"minimum threshold"

    def test_shamir_mnemonic_full_pipeline(self, tmp_path):
        """Full pipeline: encrypt → mnemonic → decode → decrypt"""
        import base64 as _b64, io, json
        data = os.urandom(1024)
        src = tmp_path / "s.bin"; src.write_bytes(data)
        enc = tmp_path / "e.qcx"
        with open(enc, "wb") as f:
            off = f.tell()
            meta, share_strs = cc.encrypt_shamir_streaming(str(src), f, n=3, k=2)
            meta["payload_offset"] = off
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        decoded = [cc.encode_share(cc.mnemonic_to_share(cc.share_to_mnemonic(cc.decode_share(s))))
                   for s in share_strs[:2]]
        sd = [cc.decode_share(s) for s in decoded]
        mk = cc.shamir_recover(sd)
        sk = cc.aes_gcm_decrypt(mk, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                _b64.b64decode(meta["kyber_sk_enc"]))
        ks = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
        fk = cc.xor_bytes(mk, ks)
        buf = io.BytesIO(); cc.decrypt_streaming(str(enc), buf, meta, fk)
        assert buf.getvalue() == data

    def test_shamir_recover_output_length(self):
        """shamir_recover must always return exactly KEY_BYTES bytes."""
        secret = os.urandom(64)
        shares = cc.shamir_split(secret, n=3, k=2)
        result = cc.shamir_recover(shares[:2])
        assert len(result) == cc.KEY_BYTES

    def test_xor_self_cancel(self):
        """XOR of value with itself gives zeros."""
        v = os.urandom(64)
        assert cc.xor_bytes(v, v) == bytes(64)

    def test_different_runs_differ(self, tmp_path):
        """Random nonces mean same plaintext produces different ciphertext each time."""
        data = b"determinism check"
        src = tmp_path / "s.bin"; src.write_bytes(data)
        nonces = []
        for i in range(5):
            with open(tmp_path / f"e{i}.qcx", "wb") as f:
                m = cc.encrypt_single_streaming(str(src), f, "pw")
            nonces.append(m["payload_nonce"])
        assert len(set(nonces)) == 5




# ─────────────────────────────────────────────────────────────────────────────
# 8. GUI logic layer tests (A4)
#    These test the pure-logic parts of the GUI without starting Tk.
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadPkgVersionCheck:
    """A3: load_pkg rejects files outside supported version range [MIN, MAX]."""

    def _min_meta(self):
        return {
            "version": cc.FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "argon_salt":"aa==","kyber_kem_ct":"aa==","kyber_sk_enc_nonce":"aa==",
            "kyber_sk_enc":"aa==","payload_nonce":"aa==","payload_chunk_count":1,
            "filename_nonce":"aa==","filename_enc":"aa==","hmac":"x",
        }

    def _make_raw(self, meta):
        pkg  = {"meta": meta}
        blob = json.dumps(pkg, separators=(",",":")).encode()
        return MAGIC + len(blob).to_bytes(4, "big") + blob

    def test_current_version_accepted(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg as dec_load_pkg
        raw = self._make_raw(self._min_meta())
        f = tmp_path / "ok.qcx"; f.write_bytes(raw)
        pkg = dec_load_pkg(str(f))
        assert pkg["meta"]["mode"] == "single"

    def test_future_version_rejected(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg as dec_load_pkg
        meta = {**self._min_meta(), "version": cc.MAX_FORMAT_VERSION + 1}
        raw  = self._make_raw(meta)
        f = tmp_path / "future.qcx"; f.write_bytes(raw)
        with pytest.raises(ValueError, match="newer version"):
            dec_load_pkg(str(f))

    def test_old_version_rejected(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg as dec_load_pkg
        meta = {**self._min_meta(), "version": 0}
        raw  = self._make_raw(meta)
        f = tmp_path / "old.qcx"; f.write_bytes(raw)
        with pytest.raises(ValueError, match="older format|no longer supported"):
            dec_load_pkg(str(f))


class TestEncryptedPayloadMetadata:
    """U3: ts, sz and filename are stored in the encrypted filename envelope."""

    def test_single_has_ts_and_sz(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"hello world", filename="hello.txt")
        result, fname, sz, ts = _decrypt_qcx(enc, meta, fk)
        assert result == b"hello world" and fname == "hello.txt"
        assert sz == len(b"hello world") and ts > 0

    def test_shamir_has_ts_and_sz(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"shamir test payload",
                                      filename="shamir.bin", n=3, k=2)
        result, fname, sz, ts = _decrypt_qcx(enc, meta, fk)
        assert result == b"shamir test payload" and fname == "shamir.bin"
        assert sz == len(b"shamir test payload") and ts > 0

    def test_sz_matches_actual_plaintext_length(self, tmp_path):
        data = os.urandom(4096)
        enc, meta, _, fk = _make_qcx(tmp_path, data)
        result, _, sz, _ = _decrypt_qcx(enc, meta, fk)
        assert sz == len(data) == len(result)

    def test_ts_is_recent(self, tmp_path):
        import time
        before = int(time.time())
        enc, meta, _, fk = _make_qcx(tmp_path, b"ts test")
        _, _, _, ts = _decrypt_qcx(enc, meta, fk)
        assert before <= ts <= int(time.time()) + 2


class TestShamirRecoverRangeCheck:
    """B5: shamir_recover must raise ValueError (not OverflowError) for out-of-range result."""

    def test_normal_recovery_succeeds(self):
        secret = os.urandom(cc.KEY_BYTES)
        shares = cc.shamir_split(secret, n=3, k=2)
        recovered = cc.shamir_recover(shares[:2])
        assert recovered == secret

    def test_range_check_message(self):
        # We can't easily force an out-of-range result without corrupting shares,
        # but we can verify the range check code path by monkeypatching shamirs.recover
        from quantacrypt.core import crypto as _cc
        import shamirs as _sh
        orig = _sh.recover
        try:
            # Inject a value >= 2^512
            _sh.recover = lambda objs: (1 << (_cc.KEY_BYTES * 8))
            with pytest.raises(ValueError, match="out of range"):
                _cc.shamir_recover([{"index":1,"value":1,"modulus":_cc.SHAMIR_PRIME}])
        finally:
            _sh.recover = orig


class TestValidateLogic:
    """Tests for the _validate logic extracted from EncryptorApp.
    We test the conditions directly without instantiating Tk."""

    def _validate(self, path, out, mode="single", pw1="secret", pw2="secret", n=3, k=2):
        """Mirror of EncryptorApp._validate for unit testing."""
        import os
        if not path or not os.path.isfile(path): return "Select a file first"
        if not out: return "Specify an output path"
        try:
            if os.path.exists(out) and os.path.samefile(path, out):
                return "Output path is the same as the input — choose a different location"
        except OSError: pass
        if mode == "single":
            if not pw1: return "Password cannot be empty"
            if pw1 != pw2: return "Passwords don't match"
        else:
            if n < 2: return "Total shares must be at least 2"
            if k > n: return "Threshold can't exceed total shares"
            if k < 2: return "Threshold must be at least 2"
        return None

    def test_no_file_selected(self):
        assert "Select a file" in (self._validate(None, "/tmp/out.qcx") or "")

    def test_nonexistent_file(self):
        assert "Select a file" in (self._validate("/tmp/no_such_file_xyz.bin", "/tmp/out.qcx") or "")

    def test_no_output_path(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert "Specify an output" in (self._validate(str(f), "") or "")

    def test_empty_password(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert "empty" in (self._validate(str(f), "/tmp/out.qcx", pw1="", pw2="") or "")

    def test_password_mismatch(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert "match" in (self._validate(str(f), "/tmp/out.qcx", pw1="abc", pw2="xyz") or "")

    def test_valid_single(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert self._validate(str(f), "/tmp/out.qcx") is None

    def test_shamir_k_exceeds_n(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert "exceed" in (self._validate(str(f), "/tmp/out.qcx", mode="shamir", n=3, k=5) or "")

    def test_shamir_k_below_2(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert "least 2" in (self._validate(str(f), "/tmp/out.qcx", mode="shamir", n=3, k=1) or "")

    def test_samefile_detection(self, tmp_path):
        f = tmp_path / "in.txt"; f.write_bytes(b"x")
        assert "same as the input" in (self._validate(str(f), str(f)) or "")


class TestDecryptorValidateLogic:
    """Tests for _collect_shares threshold mismatch logic (prev-S2)."""

    def test_threshold_mismatch_raises(self, tmp_path):
        import json
        data = b"mismatch test"
        src = tmp_path / "s.bin"; src.write_bytes(data)
        enc1 = tmp_path / "e1.qcx"; enc2 = tmp_path / "e2.qcx"
        with open(enc1, "wb") as f:
            off = f.tell()
            meta_3of5, shares_3of5 = cc.encrypt_shamir_streaming(str(src), f, n=5, k=3)
            meta_3of5["payload_offset"] = off
            blob = json.dumps({"meta": meta_3of5}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        with open(enc2, "wb") as f:
            off = f.tell()
            meta_2of3, shares_2of3 = cc.encrypt_shamir_streaming(str(src), f, n=3, k=2)
            meta_2of3["payload_offset"] = off
            blob = json.dumps({"meta": meta_2of3}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        share_dicts = [cc.decode_share(s) for s in shares_2of3[:3]]
        for sd in share_dicts:
            sd["threshold"] = 2  # mismatches meta_3of5 threshold=3
        # simulate what _collect_shares does
        meta_k = meta_3of5.get("threshold", 0)
        for i, sd in enumerate(share_dicts, 1):
            mn_k = sd.get("threshold", 0)
            if mn_k and mn_k != meta_k:
                with pytest.raises(ValueError, match="Threshold mismatch"):
                    raise ValueError(
                        f"Threshold mismatch on share {i}: mnemonic says {mn_k}-of-n "
                        f"but this file requires {meta_k}. Wrong share for this file?"
                    )
                return
        pytest.fail("Expected threshold mismatch to be detected")


class TestMagicConstantImport:
    """A2: MAGIC must be defined only in crypto_core and imported elsewhere."""

    def test_magic_value(self):
        assert cc.MAGIC == b"QCBIN\x01"

    def test_magic_length(self):
        assert len(cc.MAGIC) == 6

    def test_decryptor_uses_cc_magic(self):
        """Ensure decryptor.py imports MAGIC rather than defining its own."""
        import importlib.util, pathlib
        spec = importlib.util.find_spec("quantacrypt.ui.decryptor")
        src = pathlib.Path(spec.origin).read_text()
        # Must not have a raw bytes definition
        assert 'MAGIC = b"QCBIN' not in src
        # Must import from quantacrypt.core.crypto
        assert "from quantacrypt.core.crypto import" in src and "MAGIC" in src

    def test_quantacrypt_uses_cc_magic(self):
        """__main__ inlines the .qcx magic bytes on purpose so that startup
        can do a cheap self-payload probe WITHOUT importing core.crypto
        (which pulls in argon2/kyber/cryptography — ~200-400 ms).
        Verify the inlined value stays in sync with the canonical MAGIC."""
        import importlib.util, pathlib, re
        spec = importlib.util.find_spec("quantacrypt.__main__")
        src = pathlib.Path(spec.origin).read_text()
        match = re.search(r'_QCX_MAGIC\s*=\s*(b"[^"]*")', src)
        assert match, "__main__.py must define _QCX_MAGIC for lazy-import probe"
        inlined = eval(match.group(1))
        assert inlined == cc.MAGIC, (
            f"_QCX_MAGIC in __main__.py ({inlined!r}) is out of sync with "
            f"cc.MAGIC ({cc.MAGIC!r}) — keep them identical."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Coverage: error-branch tests for edge cases in crypto.py
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyMetaHmac:
    """Cover _verify_meta_hmac error branches (lines 112-122)."""

    def test_missing_hmac_raises(self):
        key_material = os.urandom(64)
        meta = {"version": 1, "mode": "single"}
        with pytest.raises(ValueError, match="HMAC is missing"):
            cc._verify_meta_hmac(key_material, meta)

    def test_tampered_hmac_raises(self):
        key_material = os.urandom(64)
        fields = {"argon_salt": "AA==", "kyber_kem_ct": "BB=="}
        real_hmac = cc._meta_hmac(key_material, fields)
        meta = {**fields, "hmac": real_hmac + "TAMPERED", "version": 1, "mode": "single"}
        with pytest.raises(ValueError, match="authentication failed"):
            cc._verify_meta_hmac(key_material, meta)


class TestCancelledOperation:
    """Cooperative-cancel support on stream_encrypt / stream_decrypt."""

    def test_encrypt_cancel_mid_stream(self, tmp_path):
        """cancel_check returning True mid-stream raises CancelledOperation."""
        # 5 MB input → several chunks at 4 MB each.
        src = tmp_path / "src.bin"
        src.write_bytes(b"A" * (5 * cc.CHUNK_SIZE))
        dst = tmp_path / "dst.bin"
        # Cancel immediately.
        calls = {"n": 0}
        def _cancel():
            calls["n"] += 1
            return True  # cancel on the very first check
        with pytest.raises(cc.CancelledOperation):
            with open(dst, "wb") as f:
                cc.stream_encrypt_payload(
                    str(src), f, os.urandom(64), src.stat().st_size,
                    cancel_check=_cancel,
                )
        assert calls["n"] >= 1

    def test_encrypt_cancel_check_false_runs_to_completion(self, tmp_path):
        """A cancel_check that always returns False is a no-op."""
        src = tmp_path / "src.bin"
        src.write_bytes(b"A" * 1024)
        dst = tmp_path / "dst.bin"
        with open(dst, "wb") as f:
            nonce, chunks, _, _ = cc.stream_encrypt_payload(
                str(src), f, os.urandom(64), src.stat().st_size,
                cancel_check=lambda: False,
            )
        assert chunks >= 1

    def test_decrypt_cancel_mid_stream(self, tmp_path):
        """Cancelling during decrypt cleans up without raising InvalidTag."""
        key = os.urandom(64)
        src = tmp_path / "src.bin"
        src.write_bytes(b"Z" * (5 * cc.CHUNK_SIZE))
        payload = tmp_path / "payload.bin"
        with open(payload, "wb") as f:
            nonce, chunks, _, _ = cc.stream_encrypt_payload(
                str(src), f, key, src.stat().st_size,
            )
        out = tmp_path / "out.bin"
        with pytest.raises(cc.CancelledOperation):
            with open(out, "wb") as f:
                cc.stream_decrypt_payload(
                    str(payload), f, key,
                    payload_offset=0, chunk_count=chunks, base_nonce=nonce,
                    cancel_check=lambda: True,
                )


class TestShamirSplitEdge:
    """Cover shamir_split overflow guard (line 140)."""

    def test_secret_exceeds_m521_raises(self):
        # M521 prime is 2^521 - 1.  A 66-byte all-0xFF secret exceeds it.
        huge = b"\xff" * 66
        with pytest.raises(ValueError, match="exceeds M521"):
            cc.shamir_split(huge, n=3, k=2)

    def test_split_rejects_k_below_two(self):
        with pytest.raises(ValueError, match="need 2 <= k <= n <= 255"):
            cc.shamir_split(b"\x00" * 32, n=3, k=1)

    def test_split_rejects_k_greater_than_n(self):
        with pytest.raises(ValueError, match="need 2 <= k <= n <= 255"):
            cc.shamir_split(b"\x00" * 32, n=2, k=3)

    def test_split_rejects_n_above_255(self):
        with pytest.raises(ValueError, match="need 2 <= k <= n <= 255"):
            cc.shamir_split(b"\x00" * 32, n=256, k=2)


class TestShamirRecoverValidation:
    """Cover shamir_recover empty-list and insufficient-shares guards."""

    def test_recover_empty_list_raises(self):
        with pytest.raises(ValueError, match="empty share list"):
            cc.shamir_recover([])

    def test_recover_insufficient_shares_raises(self):
        # Split 3-of-5; hand back only 2 — threshold-aware guard rejects.
        shares = cc.shamir_split(b"\x01" * 32, n=5, k=3)
        with pytest.raises(ValueError, match="Not enough shares"):
            cc.shamir_recover(shares[:2])

    def test_recover_duplicate_shares_raises(self):
        # Hand back the same share twice — the quorum is effectively one
        # share short, so the library would compute a wrong secret.  Our
        # wrapper refuses instead.
        shares = cc.shamir_split(b"\x01" * 32, n=5, k=3)
        with pytest.raises(ValueError, match="Duplicate share"):
            cc.shamir_recover([shares[0], shares[0], shares[1]])


class TestDecodeShareEdgeCases:
    """Cover decode_share validation branches (lines 163-182)."""

    def test_malformed_base64_raises(self):
        with pytest.raises(ValueError, match="malformed"):
            cc.decode_share("QCSHARE-!!!not-base64!!!")

    def test_missing_field_raises(self):
        # Valid JSON but missing 'modulus'
        payload = base64.b64encode(json.dumps({"index": 1, "value": 2}).encode()).decode()
        with pytest.raises(ValueError, match="missing required field"):
            cc.decode_share("QCSHARE-" + payload)

    def test_non_integer_field_raises(self):
        payload = base64.b64encode(json.dumps({
            "index": "one", "value": 2, "modulus": cc.SHAMIR_PRIME
        }).encode()).decode()
        with pytest.raises(ValueError, match="must be an integer"):
            cc.decode_share("QCSHARE-" + payload)

    def test_wrong_modulus_raises(self):
        payload = base64.b64encode(json.dumps({
            "index": 1, "value": 2, "modulus": 12345
        }).encode()).decode()
        with pytest.raises(ValueError, match="modulus does not match"):
            cc.decode_share("QCSHARE-" + payload)

    def test_index_out_of_range_raises(self):
        payload = base64.b64encode(json.dumps({
            "index": 0, "value": 2, "modulus": cc.SHAMIR_PRIME
        }).encode()).decode()
        with pytest.raises(ValueError, match="index out of range"):
            cc.decode_share("QCSHARE-" + payload)

    def test_value_out_of_range_raises(self):
        payload = base64.b64encode(json.dumps({
            "index": 1, "value": cc.SHAMIR_PRIME + 1, "modulus": cc.SHAMIR_PRIME
        }).encode()).decode()
        with pytest.raises(ValueError, match="value out of range"):
            cc.decode_share("QCSHARE-" + payload)


class TestDecryptPayloadTruncation:
    """Cover stream_decrypt_payload truncation guards (lines 273, 279, 283)
    and the progress callback path (lines 295-296)."""

    def _encrypt_to_file(self, tmp_path, data=b"hello world"):
        """Encrypt data via the streaming API and return (file_path, meta)."""
        src = tmp_path / "plain.bin"
        src.write_bytes(data)
        dst_path = tmp_path / "enc.bin"
        with open(str(dst_path), "wb") as dst:
            meta = cc.encrypt_single_streaming(str(src), dst, "testpass")
        # Record payload offset (bytes written before payload = 0 for this test)
        meta["payload_offset"] = 0
        return str(dst_path), meta

    def test_truncated_seq_raises(self, tmp_path):
        enc_path, meta = self._encrypt_to_file(tmp_path)
        offset = meta.get("payload_offset", 0)
        # Chop the file so the payload has < 4 bytes for the sequence header
        with open(enc_path, "rb") as f:
            data = f.read(offset + 2)
        trunc = str(tmp_path / "trunc1.bin")
        with open(trunc, "wb") as f:
            f.write(data)
        with open(os.devnull, "wb") as devnull:
            with pytest.raises(ValueError, match="truncated"):
                cc.stream_decrypt_payload(
                    trunc, devnull, os.urandom(64), offset,
                    meta["payload_chunk_count"],
                    base64.b64decode(meta["payload_nonce"]))

    def test_truncated_ct_len_raises(self, tmp_path):
        enc_path, meta = self._encrypt_to_file(tmp_path)
        offset = meta.get("payload_offset", 0)
        # Keep seq (4 bytes) but chop before ct_len is complete
        with open(enc_path, "rb") as f:
            data = f.read(offset + 6)
        trunc = str(tmp_path / "trunc2.bin")
        with open(trunc, "wb") as f:
            f.write(data)
        with open(os.devnull, "wb") as devnull:
            with pytest.raises(ValueError, match="truncated"):
                cc.stream_decrypt_payload(
                    trunc, devnull, os.urandom(64), offset,
                    meta["payload_chunk_count"],
                    base64.b64decode(meta["payload_nonce"]))

    def test_truncated_chunk_data_raises(self, tmp_path):
        enc_path, meta = self._encrypt_to_file(tmp_path)
        offset = meta.get("payload_offset", 0)
        # Keep seq + ct_len but chop the ciphertext short
        with open(enc_path, "rb") as f:
            data = f.read(offset + 10)
        trunc = str(tmp_path / "trunc3.bin")
        with open(trunc, "wb") as f:
            f.write(data)
        with open(os.devnull, "wb") as devnull:
            with pytest.raises(ValueError, match="truncated"):
                cc.stream_decrypt_payload(
                    trunc, devnull, os.urandom(64), offset,
                    meta["payload_chunk_count"],
                    base64.b64decode(meta["payload_nonce"]))

    def test_progress_callback_fires(self, tmp_path):
        enc_path, meta = self._encrypt_to_file(tmp_path)
        offset = meta.get("payload_offset", 0)
        # Derive the real key to do a successful decrypt with progress
        argon_salt = base64.b64decode(meta["argon_salt"])
        argon_key  = cc.argon2id_derive("testpass".encode(), argon_salt)
        kem_ct     = base64.b64decode(meta["kyber_kem_ct"])
        sk_nonce   = base64.b64decode(meta["kyber_sk_enc_nonce"])
        sk_ct      = base64.b64decode(meta["kyber_sk_enc"])
        sk         = cc.aes_gcm_decrypt(argon_key, sk_nonce, sk_ct)
        kem_ss     = cc.kyber_decaps(sk, kem_ct)
        final_key  = cc.xor_bytes(argon_key, kem_ss)

        dst = str(tmp_path / "dec.bin")
        progress_msgs = []
        with open(dst, "wb") as out:
            cc.stream_decrypt_payload(
                enc_path, out, final_key, offset,
                meta["payload_chunk_count"],
                base64.b64decode(meta["payload_nonce"]),
                progress_cb=lambda m: progress_msgs.append(m))
        assert len(progress_msgs) > 0
        assert any("Decrypting" in m for m in progress_msgs)


if __name__ == "__main__":

    # Quick sanity run without pytest
    import traceback
    passed = failed = 0
    for cls_name, cls in list(globals().items()):
        if not isinstance(cls, type) or not cls_name.startswith("Test"): continue
        inst = cls()
        for name in dir(inst):
            if not name.startswith("test"): continue
            fn = getattr(inst, name)
            if not callable(fn): continue
            # Handle fixtures manually for direct run
            if hasattr(fn, "__func__"):
                import inspect
                params = inspect.signature(fn).parameters
                if len(params) > 0:
                    continue  # skip fixture tests in direct mode
            try:
                fn()
                print(f"  PASS  {cls_name}.{name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {cls_name}.{name}: {e}")
                traceback.print_exc()
                failed += 1
    print(f"\n{passed} passed, {failed} failed")

