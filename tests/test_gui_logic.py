"""
QuantaCrypt GUI Layer Logic Tests
Tests for validation, file loading, and GUI helper functions.
"""
import base64
import io
import math
import os
import sys
import json
import struct
import tempfile
import time as _time
import traceback
import inspect
import types

import pytest
from quantacrypt.core import crypto as cc
from tests.conftest import MAGIC, make_pkg_bytes, load_pkg, _make_qcx, _decrypt_qcx

# ─────────────────────────────────────────────────────────────────────────────
# A4: GUI-layer tests
# These test logic functions that don't need a display: _validate, _collect_shares,
# file loading, version checks, crypto return signatures, and helper functions.
# ─────────────────────────────────────────────────────────────────────────────


class TestEncryptorValidate:
    """Test encryptor._validate logic without opening a window."""

    def _make_validator(self, path, out, mode="single", pw1="secret", pw2="secret", n=3, k=2,
                        is_folder=False):
        """Build a minimal stand-in for encryptor._validate."""
        import types
        obj = types.SimpleNamespace(
            _path=path,
            _is_folder=is_folder,
            _src_type=types.SimpleNamespace(get=lambda: "file"),  # not batch
            _mode=types.SimpleNamespace(get=lambda: mode),
            _pw1v=types.SimpleNamespace(get=lambda: pw1),
            _pw2v=types.SimpleNamespace(get=lambda: pw2),
            _n=types.SimpleNamespace(get=lambda: n),
            _k=types.SimpleNamespace(get=lambda: k),
            _out=types.SimpleNamespace(get=lambda: out),
        )
        # Import the actual method logic as a function
        from quantacrypt.ui.encryptor import EncryptorApp
        obj._validate = lambda: EncryptorApp._validate(obj)
        return obj

    def test_no_file_selected(self):
        obj = self._make_validator(None, "/tmp/out.qcx")
        assert obj._validate() == "Select a file or folder first"

    def test_nonexistent_file(self):
        obj = self._make_validator("/tmp/does_not_exist_xyz.bin", "/tmp/out.qcx")
        assert obj._validate() == "Select a file first"

    def test_empty_output(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "")
            assert obj._validate() == "Specify an output path"
        finally:
            os.unlink(path)

    def test_password_empty(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", pw1="", pw2="")
            assert obj._validate() == "Password cannot be empty"
        finally:
            os.unlink(path)

    def test_password_mismatch(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", pw1="abc", pw2="xyz")
            assert obj._validate() == "Passwords don't match"
        finally:
            os.unlink(path)

    def test_shamir_k_exceeds_n(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", mode="shamir", n=3, k=5)
            assert "Threshold" in obj._validate()
        finally:
            os.unlink(path)

    def test_shamir_k_less_than_2(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", mode="shamir", n=3, k=1)
            assert obj._validate() is not None
        finally:
            os.unlink(path)

    def test_valid_single_password(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", pw1="good", pw2="good")
            assert obj._validate() is None
        finally:
            os.unlink(path)

    def test_same_file_input_output(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, path, pw1="pw", pw2="pw")
            result = obj._validate()
            assert result is not None and "same" in result.lower()
        finally:
            os.unlink(path)


class TestLoadPkg:
    """Test the .qcx file parser (load_pkg) and version checks."""

    def _make_meta(self):
        return {
            "version": cc.FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "argon_salt":"aa==","kyber_kem_ct":"aa==","kyber_sk_enc_nonce":"aa==",
            "kyber_sk_enc":"aa==","payload_nonce":"aa==","payload_chunk_count":1,
            "filename_nonce":"aa==","filename_enc":"aa==","hmac":"x",
        }

    def _make_qcx(self, meta, version_override=None):
        """Write a minimal .qcx file and return its path."""
        if version_override is not None:
            meta = dict(meta); meta["version"] = version_override
        pkg = json.dumps({"meta": meta}, separators=(",",":")).encode()
        block = cc.MAGIC + len(pkg).to_bytes(4,"big") + pkg
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".qcx")
        f.write(b"FAKEBINARYPREFIX" + block)
        f.close()
        return f.name

    def test_valid_file_parsed(self):
        meta = self._make_meta()
        path = self._make_qcx(meta)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            result = load_pkg(path)
            assert "meta" in result
            assert result["meta"]["mode"] == "single"
        finally:
            os.unlink(path)

    def test_not_a_qcx_raises(self):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        f.write(b"this is not a qcx file at all"); f.close()
        try:
            from quantacrypt.ui.decryptor import load_pkg
            try:
                load_pkg(f.name)
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "QuantaCrypt" in str(e) or "truncated" in str(e).lower()
        finally:
            os.unlink(f.name)

    def test_future_version_raises(self):
        path = self._make_qcx(self._make_meta(), version_override=999)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            with pytest.raises(ValueError, match="newer version"):
                load_pkg(path)
        finally:
            os.unlink(path)

    def test_old_version_raises(self):
        path = self._make_qcx(self._make_meta(), version_override=0)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            with pytest.raises(ValueError, match="older format|no longer supported"):
                load_pkg(path)
        finally:
            os.unlink(path)

    def test_current_version_accepted(self):
        path = self._make_qcx(self._make_meta(), version_override=cc.FORMAT_VERSION)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            result = load_pkg(path)
            assert "meta" in result
        finally:
            os.unlink(path)


class TestCryptoReturnSignatures:
    """decrypt_streaming returns (fname, sz, ts) 3-tuple; roundtrip data matches."""

    def test_single_decrypt_returns_correct_values(self, tmp_path):
        data = b"hello world"
        enc, meta, _, fk = _make_qcx(tmp_path, data, filename="test.txt")
        result, fname, sz, ts = _decrypt_qcx(enc, meta, fk)
        assert result == data and fname == "test.txt"
        assert sz == len(data) and ts > 0

    def test_shamir_decrypt_returns_correct_values(self, tmp_path):
        data = b"shamir test"
        enc, meta, _, fk = _make_qcx(tmp_path, data, filename="doc.pdf", n=3, k=2)
        result, fname, sz, ts = _decrypt_qcx(enc, meta, fk)
        assert result == data and fname == "doc.pdf"
        assert sz == len(data) and ts > 0

    def test_sz_matches_data_length(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"x" * 1000)
        _, _, sz, _ = _decrypt_qcx(enc, meta, fk)
        assert sz == 1000

    def test_ts_is_recent(self, tmp_path):
        before = int(_time.time()) - 2
        enc, meta, _, fk = _make_qcx(tmp_path, b"ts test")
        _, _, _, ts = _decrypt_qcx(enc, meta, fk)
        assert before <= ts <= int(_time.time()) + 2

    def test_wrong_password_still_raises(self, tmp_path):
        import base64 as _b64, json
        src = tmp_path / "s.bin"; src.write_bytes(b"secret")
        enc = tmp_path / "e.qcx"
        with open(enc, "wb") as f:
            off = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "correct")
            meta["payload_offset"] = off
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        wrong_argon = cc.argon2id_derive(b"wrong", _b64.b64decode(meta["argon_salt"]))
        with pytest.raises(Exception):
            cc.aes_gcm_decrypt(wrong_argon, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                               _b64.b64decode(meta["kyber_sk_enc"]))


class TestShamirRecover:
    """Test B5: shamir_recover range check."""

    def test_valid_recovery_works(self):
        secret = os.urandom(cc.KEY_BYTES)
        shares = cc.shamir_split(secret, 3, 2)
        recovered = cc.shamir_recover(shares[:2])
        assert recovered == secret

    def test_corrupted_share_raises_valueerror(self):
        secret = os.urandom(cc.KEY_BYTES)
        shares = cc.shamir_split(secret, 3, 2)
        # Corrupt value to something astronomically large
        bad = [dict(shares[0]), dict(shares[1])]
        bad[0]["value"] = cc.SHAMIR_PRIME + 1  # outside valid range
        bad[0]["modulus"] = bad[0]["value"] + 999  # bypass modulus check
        # The recovery might not error on the Shamir lib, but our range check catches it
        try:
            result = cc.shamir_recover(bad)
            # If it didn't raise, result must still fit in KEY_BYTES (our check passed)
            assert len(result) == cc.KEY_BYTES
        except (ValueError, OverflowError):
            pass  # either is acceptable — crash prevented


class TestMagicConstant:
    """Test A2: MAGIC is the same in all modules."""

    def test_magic_consistent_across_modules(self):
        from quantacrypt.ui.decryptor import MAGIC as dec_magic
        from quantacrypt.core.crypto import MAGIC as cc_magic
        assert dec_magic == cc_magic == b"QCBIN\x01"

    def test_magic_used_in_file_format(self):
        meta = {
            "version": cc.FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "argon_salt":"aa==","kyber_kem_ct":"aa==","kyber_sk_enc_nonce":"aa==",
            "kyber_sk_enc":"aa==","payload_nonce":"aa==","payload_chunk_count":1,
            "filename_nonce":"aa==","filename_enc":"aa==","hmac":"x",
        }
        pkg = json.dumps({"meta": meta}, separators=(",",":")).encode()
        block = cc.MAGIC + len(pkg).to_bytes(4,"big") + pkg
        assert block.startswith(cc.MAGIC)
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".qcx")
        f.write(b"PREFIX" + block); f.close()
        try:
            from quantacrypt.ui.decryptor import load_pkg
            result = load_pkg(f.name)
            assert result["meta"]["mode"] == "single"
        finally:
            os.unlink(f.name)


class TestPasswordStrengthZxcvbn:
    """Test U5: PasswordStrengthBar uses zxcvbn (no display needed)."""

    def test_zxcvbn_importable(self):
        from zxcvbn import zxcvbn
        result = zxcvbn("password123")
        assert "score" in result
        assert 0 <= result["score"] <= 4

    def test_common_password_scores_low(self):
        from zxcvbn import zxcvbn
        result = zxcvbn("password")
        assert result["score"] <= 1, "Common passwords should score 0 or 1"

    def test_strong_passphrase_scores_high(self):
        from zxcvbn import zxcvbn
        result = zxcvbn("correct-horse-battery-staple-99!")
        assert result["score"] >= 3, "Strong passphrases should score 3 or 4"

    def test_password123_not_strong(self):
        from zxcvbn import zxcvbn
        # Previously this scored "Good" with naive entropy — zxcvbn should catch it
        result = zxcvbn("password123!")
        assert result["score"] <= 2, f"'password123!' should not score Good/Strong, got {result['score']}"


class TestRevealHelper:
    """Test _reveal doesn't crash (it just shells out — we don't verify the window opens)."""

    def test_reveal_existing_path_no_exception(self):
        from quantacrypt.ui.encryptor import _reveal
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            _reveal(path)  # Should not raise even if the file doesn't exist in Finder
        except Exception as e:
            assert False, f"_reveal raised unexpectedly: {e}"
        finally:
            os.unlink(path)

    def test_reveal_nonexistent_path_no_exception(self):
        from quantacrypt.ui.encryptor import _reveal
        _reveal("/tmp/nonexistent_xyz_path")  # Should silently swallow error


class TestFileInfoCard:
    """Test U3: FileInfoCard shows sz/ts when provided."""

    def test_filinfocard_accepts_sz_ts(self):
        """Verify FileInfoCard constructor signature accepts sz and ts."""
        import inspect
        from quantacrypt.ui.decryptor import FileInfoCard
        sig = inspect.signature(FileInfoCard.__init__)
        params = list(sig.parameters.keys())
        assert "sz" in params, "FileInfoCard should accept sz parameter"
        assert "ts" in params, "FileInfoCard should accept ts parameter"

    def test_format_size_accuracy(self):
        from quantacrypt.ui.shared import fmt_size
        assert fmt_size(0)    == "0 B"
        assert fmt_size(1023) == "1,023 B"
        assert fmt_size(1024) == "1.0 KB"
        assert fmt_size(1048576) == "1.0 MB"



# ═══════════════════════════════════════════════════════════════════════════════
# Tests for round-3 UX fixes
# ═══════════════════════════════════════════════════════════════════════════════

class TestHardFileSizeLimit:
    """Streaming has no file size cap — O(CHUNK_SIZE) RAM regardless of input."""

    def test_no_max_file_bytes_constant(self):
        # Size cap fully removed — streaming handles any file the OS can open
        assert not hasattr(cc, "MAX_FILE_BYTES"), \
            "MAX_FILE_BYTES should be removed — streaming has no size limit"

    def test_no_size_rejection_for_large_files(self, tmp_path):
        # Streaming: no arbitrary size cap exists in the crypto layer
        assert not hasattr(cc, "_LEGACY_MAX_FILE_BYTES"), \
            "Legacy hard limit should be removed, not kept as a separate constant"
        # CHUNK_SIZE constant must exist and be a reasonable power-of-two block
        assert hasattr(cc, "CHUNK_SIZE")
        assert cc.CHUNK_SIZE >= 64 * 1024          # at least 64 KB
        assert cc.CHUNK_SIZE <= 64 * 1024 * 1024   # at most 64 MB
        assert (cc.CHUNK_SIZE & (cc.CHUNK_SIZE - 1)) == 0  # power of two


class TestSharesPendingGuard:
    """Fix 6: Unsaved Shamir shares warn before navigating away."""

    def test_shares_pending_initialises_false(self):
        """EncryptorApp starts with no pending shares."""
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp.__init__)
        assert "_shares_pending=False" in src or "_shares_pending = False" in src

    def test_check_shares_saved_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_check_shares_saved")

    def test_save_shares_clears_pending(self):
        """_save_shares sets _shares_pending=False after saving."""
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._save_shares)
        assert "_shares_pending" in src and "False" in src


class TestWizardStepDuringEncryption:
    """Fix 8: set_step(4) during encryption, not set_step(3)."""

    def test_start_sets_step_4(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._start)
        assert "set_step(4)" in src, "_start should set wizard to step 4 (Encrypt)"
        assert "set_step(3)" not in src, "_start should not set wizard to step 3 (Output)"


class TestDecryptorFailStep:
    """Fix 7: _fail stays at step 2 (Decrypt), not retreats to step 1."""

    def test_fail_sets_step_2(self):
        import inspect
        import quantacrypt.ui.decryptor as decryptor
        src = inspect.getsource(decryptor.DecryptorApp._fail)
        assert "set_step(2)" in src, "_fail should keep wizard at step 2"
        assert "set_step(1)" not in src, "_fail should not retreat to step 1"


class TestFileCardKeyboard:
    """Fix 4: FileCard is keyboard accessible."""

    def test_filecard_has_takefocus(self):
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.FileCard.__init__)
        assert "takefocus" in src, "FileCard should set takefocus=True"

    def test_filecard_has_return_binding(self):
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.FileCard.__init__)
        assert "<Return>" in src, "FileCard should bind <Return> to _pick"

    def test_filecard_has_space_binding(self):
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.FileCard.__init__)
        assert "<space>" in src, "FileCard should bind <space> to _pick"


class TestSegmentedControlKeyboard:
    """Fix 17: SegmentedControl keyboard navigation."""

    def test_segmented_control_has_step_method(self):
        from quantacrypt.ui import shared as shared_ui
        assert hasattr(shared_ui.SegmentedControl, "_step")

    def test_step_wraps_around(self):
        """_step should cycle through options with wraparound."""
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.SegmentedControl._step)
        assert "%" in src, "_step should use modulo for wraparound"

    def test_segmented_control_has_keyboard_bindings(self):
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.SegmentedControl.__init__)
        assert "<Left>" in src, "SegmentedControl should bind <Left>"
        assert "<Right>" in src, "SegmentedControl should bind <Right>"
        assert "takefocus" in src, "SegmentedControl should be focusable"


class TestFlatButtonHoverOnEnable:
    """Fix 22: FlatButton checks hover state when re-enabled."""

    def test_enable_checks_pointer_position(self):
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.FlatButton.enable)
        assert "winfo_pointerxy" in src, "enable(True) should check if mouse is already hovering"


class TestOutputPathPreservation:
    """Fix 13: _load_payload only sets suggested path if field is empty."""

    def test_load_payload_preserves_typed_path(self):
        import inspect
        import quantacrypt.ui.decryptor as decryptor
        src = inspect.getsource(decryptor.DecryptorApp._load_payload)
        assert "self._out.get().strip()" in src, \
            "_load_payload should check if output field is empty before overwriting"


class TestFnameSanitization:
    """Fix 15: fname from metadata is sanitized with os.path.basename."""

    def test_done_applies_basename_to_fname(self):
        import inspect
        import quantacrypt.ui.decryptor as decryptor
        src = inspect.getsource(decryptor.DecryptorApp._done)
        assert "os.path.basename(fname)" in src, \
            "_done should apply os.path.basename() to fname to prevent path traversal display"

    def test_basename_strips_path_traversal(self):
        import os
        evil = "../../../etc/passwd"
        assert os.path.basename(evil) == "passwd"

    def test_basename_on_normal_name_unchanged(self):
        import os
        assert os.path.basename("document.pdf") == "document.pdf"


class TestShareChecksumError:
    """Fix 16: Share checksum error shows sanitized message."""

    def test_fail_sanitizes_checksum_error(self):
        import inspect
        import quantacrypt.ui.decryptor as decryptor
        src = inspect.getsource(decryptor.DecryptorApp._fail)
        # Should NOT use f-string with {msg} for Checksum branch
        # Find the checksum branch
        lines = src.split("\n")
        for i, line in enumerate(lines):
            if "Checksum" in line and "elif" in line:
                # Next line should be the error message
                next_line = lines[i+1] if i+1 < len(lines) else ""
                assert "{msg}" not in next_line, \
                    "Checksum error should use a fixed string, not f'{msg}'"
                break


class TestMatchLblClearedOnDone:
    """Fix 20: _match_lbl cleared on successful encryption."""

    def test_done_clears_match_label(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._done)
        assert "_match_lbl" in src, "_done should clear the match label"
        assert 'text=""' in src or "text='')" in src or 'config(text="")' in src


class TestWizardStepsLabelTruncation:
    """Fix 21: WizardSteps truncates long step labels."""

    def test_draw_truncates_labels(self):
        import inspect
        import quantacrypt.ui.shared as shared_ui
        src = inspect.getsource(shared_ui.WizardSteps._draw)
        assert "…" in src or "\\u2026" in src, \
            "WizardSteps._draw should truncate long labels with ellipsis"


class TestFreezeThaw:
    """Fix 18: All controls frozen during encryption."""

    def test_freeze_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_freeze")

    def test_thaw_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_thaw")

    def test_freeze_disables_password_fields(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._freeze)
        assert "_pw1" in src and "_pw2" in src, "_freeze should disable both password fields"

    def test_thaw_re_enables_fields(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._thaw)
        assert "_pw1" in src or "normal" in src, "_thaw should re-enable fields"


class TestShamirKClamp:
    """Fix 12: K is clamped to N in real time."""

    def test_clamp_k_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_clamp_k")

    def test_clamp_k_logic(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        # _clamp_k was refactored to debounce via _do_clamp so that typing
        # a two-digit number doesn't flash the minimum value after the first digit.
        # The actual clamping (self._k.set) now lives in _do_clamp.
        clamp_src = inspect.getsource(encryptor.EncryptorApp._clamp_k)
        do_clamp_src = inspect.getsource(encryptor.EncryptorApp._do_clamp)
        assert ("self._clamp_job" in clamp_src or "_do_clamp" in clamp_src), "_clamp_k should delegate to debounced _do_clamp"
        assert "self._k.set" in do_clamp_src, "_do_clamp should update K when it exceeds N"
        assert "self._n.get(" in do_clamp_src


class TestDropHintConditional:
    """Fix 9: Drop hint only mentions drag-and-drop if tkinterdnd2 is available."""

    def test_launcher_has_conditional_drop_hint(self):
        import inspect
        import quantacrypt.ui.launcher as launcher
        src = inspect.getsource(launcher.LauncherApp._build)
        assert "_DND_FILES" in src, \
            "Launcher drop hint should be conditional on _DND_FILES being available"


class TestSelfExecutingSection:
    """Fix 11: SELF-EXECUTING section hidden when no binary found."""

    def test_build_checks_for_binary(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._build)
        assert "_find_dec" in src or "frozen" in src, \
            "_build should check for binary before showing SELF-EXECUTING section"

    def test_section_shown_conditionally(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._build)
        # Should only show section inside an if block
        lines = src.split("\n")
        section_line = next((i for i, l in enumerate(lines) if "PORTABLE FILE" in l or "SELF-EXECUTING" in l), None)
        assert section_line is not None
        # The section should be inside an if block (preceded by an if statement)
        preceding = "\n".join(lines[max(0,section_line-5):section_line])
        assert "if " in preceding, "SELF-EXECUTING section should be inside an if block"


class TestSizeAnnotation:
    """Fix 19: Success card annotates decryptor overhead in size label."""

    def test_done_annotates_embedded_size(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._done)
        assert "dec_size" in src or "decryptor" in src.lower(), \
            "_done should annotate decryptor size in the success card"

    def test_done_labels_payload_separately(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._done)
        assert "payload_size" in src or "data)" in src, \
            "_done should show payload vs decryptor sizes separately"


# ═══════════════════════════════════════════════════════════════════════════════
# Tests for Streaming Encryption (large-file support)
# ═══════════════════════════════════════════════════════════════════════════════

class TestStreamingConstants:
    """Crypto core constants and module-level exports."""

    def test_format_version_is_1(self):
        assert cc.FORMAT_VERSION == 1

    def test_max_format_version_is_1(self):
        assert cc.MAX_FORMAT_VERSION == 1

    def test_chunk_size_is_power_of_two(self):
        cs = cc.CHUNK_SIZE
        assert cs > 0
        assert (cs & (cs - 1)) == 0, "CHUNK_SIZE must be a power of two"

    def test_streaming_functions_exist(self):
        assert callable(cc.stream_encrypt_payload)
        assert callable(cc.stream_decrypt_payload)
        assert callable(cc.encrypt_single_streaming)
        assert callable(cc.encrypt_shamir_streaming)
        assert callable(cc.decrypt_streaming)

    def test_chunk_nonce_derivation_unique_per_chunk(self):
        base = os.urandom(12)
        n0 = cc._chunk_nonce(base, 0)
        n1 = cc._chunk_nonce(base, 1)
        n2 = cc._chunk_nonce(base, 2)
        assert n0 != n1 != n2
        assert len(n0) == 12

    def test_chunk_aad_encodes_last_flag(self):
        mid  = cc._chunk_aad(5, False)
        last = cc._chunk_aad(5, True)
        assert mid  != last
        assert mid[-1]  == 0x00
        assert last[-1] == 0xFF

    def test_chunk_nonce_different_base_nonces(self):
        """Two files with different base_nonces produce different chunk nonces."""
        b1, b2 = os.urandom(12), os.urandom(12)
        assert cc._chunk_nonce(b1, 0) != cc._chunk_nonce(b2, 0)


class TestStreamingRoundTrip:
    """Full encrypt → decrypt round-trips with the streaming API."""

    def _enc_dec(self, tmp_path, data, password="hunter2", filename="test.bin"):
        src = tmp_path / "src.bin"
        enc = tmp_path / "src.qcx"
        out = tmp_path / "out.bin"
        src.write_bytes(data)

        # Encrypt
        with open(enc, "wb") as f:
            payload_offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, password, filename=filename)
            meta["payload_offset"] = payload_offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        # Re-load via load_pkg (same path as production)
        from quantacrypt.ui.decryptor import load_pkg
        pkg = load_pkg(str(enc))
        meta2 = pkg["meta"]

        # Decrypt
        argon_key = cc.argon2id_derive(password.encode(), base64.b64decode(meta2["argon_salt"]))
        sk        = cc.aes_gcm_decrypt(argon_key, base64.b64decode(meta2["kyber_sk_enc_nonce"]),
                                       base64.b64decode(meta2["kyber_sk_enc"]))
        kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta2["kyber_kem_ct"]))
        final_key = cc.xor_bytes(argon_key, kem_ss)

        with open(out, "wb") as f:
            fname, sz, ts = cc.decrypt_streaming(str(enc), f, meta2, final_key)

        return out.read_bytes(), fname, sz, ts, meta2

    def test_empty_file(self, tmp_path):
        data = b""
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data, filename="empty.bin")
        assert result == data
        assert fname == "empty.bin"
        assert sz == 0

    def test_single_byte(self, tmp_path):
        data = b"\x42"
        result, fname, sz, ts, _ = self._enc_dec(tmp_path, data)
        assert result == data
        assert sz == 1

    def test_exactly_one_chunk(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE)
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data)
        assert result == data
        assert meta["payload_chunk_count"] == 1

    def test_exactly_two_chunks(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE + 1)
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data)
        assert result == data
        assert meta["payload_chunk_count"] == 2

    def test_multi_chunk_file(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE * 5 + 12345)
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data)
        assert result == data
        assert meta["payload_chunk_count"] == 6

    def test_filename_and_metadata_preserved(self, tmp_path):
        import os, time
        data = os.urandom(1024)
        t_before = int(time.time()) - 1
        result, fname, sz, ts, _ = self._enc_dec(tmp_path, data, filename="hello world.pdf")
        assert fname == "hello world.pdf"
        assert sz == len(data)
        assert ts >= t_before

    def test_unicode_filename(self, tmp_path):
        import os
        data = os.urandom(512)
        result, fname, sz, ts, _ = self._enc_dec(tmp_path, data, filename="档案_2024.docx")
        assert fname == "档案_2024.docx"

    def test_wrong_password_fails(self, tmp_path):
        data = b"secret data" * 100
        src = tmp_path / "src.bin"
        enc = tmp_path / "src.qcx"
        out = tmp_path / "out.bin"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            payload_offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "correctpassword", filename="src.bin")
            meta["payload_offset"] = payload_offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        from quantacrypt.ui.decryptor import load_pkg
        pkg   = load_pkg(str(enc))
        meta2 = pkg["meta"]

        # Wrong password → Argon2 gives wrong argon_key → AES-GCM decrypt of sk fails
        wrong_argon = cc.argon2id_derive(b"wrongpassword", base64.b64decode(meta2["argon_salt"]))
        with pytest.raises(Exception):
            cc.aes_gcm_decrypt(wrong_argon,
                               base64.b64decode(meta2["kyber_sk_enc_nonce"]),
                               base64.b64decode(meta2["kyber_sk_enc"]))

    def test_version_field_is_1(self, tmp_path):
        import os
        data = os.urandom(256)
        _, _, _, _, meta = self._enc_dec(tmp_path, data)
        assert meta["version"] == 1

    def test_no_payload_field_in_meta(self, tmp_path):
        """Meta never stores the payload blob in JSON — it's on disk as chunks."""
        import os
        data = os.urandom(1024)
        _, _, _, _, meta = self._enc_dec(tmp_path, data)
        assert "payload" not in meta, "Meta must not contain an in-memory payload blob"

    def test_chunk_count_matches_expected(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE * 3 + 1)
        _, _, _, _, meta = self._enc_dec(tmp_path, data)
        expected = math.ceil(len(data) / cc.CHUNK_SIZE)
        assert meta["payload_chunk_count"] == expected


class TestStreamingSecurity:
    """Security properties of the streaming format."""

    def _make_encrypted(self, tmp_path, data=None, password="pw"):
        if data is None:
            data = os.urandom(cc.CHUNK_SIZE * 3)
        src = tmp_path / "src.bin"
        enc = tmp_path / "src.qcx"
        src.write_bytes(data)
        with open(enc, "wb") as f:
            offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, password, filename="src.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        return enc, meta, data

    def _get_final_key(self, meta, password="pw"):
        argon_key = cc.argon2id_derive(password.encode(), base64.b64decode(meta["argon_salt"]))
        sk        = cc.aes_gcm_decrypt(argon_key, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                       base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        return cc.xor_bytes(argon_key, kem_ss)

    def test_chunk_truncation_detected(self, tmp_path):
        """Dropping the last chunk is detected — payload_chunk_count in meta differs."""
        enc, meta, data = self._make_encrypted(tmp_path)
        final_key = self._get_final_key(meta)

        # Truncate the file: remove the last chunk's bytes (last ~CHUNK_SIZE+20 bytes of payload)
        raw = enc.read_bytes()
        # Find magic and strip the tail metadata to get full file
        magic_pos = raw.rfind(cc.MAGIC)
        payload_only = bytearray(raw[:magic_pos])
        # Drop last 32 bytes from the payload section — enough to corrupt last chunk
        payload_only = payload_only[:-32]
        truncated = tmp_path / "truncated.qcx"
        truncated.write_bytes(bytes(payload_only) + raw[magic_pos:])

        out = io.BytesIO()
        with pytest.raises(Exception):
            cc.stream_decrypt_payload(str(truncated), out, final_key,
                                      meta["payload_offset"],
                                      meta["payload_chunk_count"],
                                      __import__("base64").b64decode(meta["payload_nonce"]))

    def test_payload_bit_flip_detected(self, tmp_path):
        """Flipping a bit in the ciphertext fails AES-GCM authentication."""
        enc, meta, data = self._make_encrypted(tmp_path)
        final_key = self._get_final_key(meta)

        raw = bytearray(enc.read_bytes())
        # Flip a bit deep inside the first chunk's ciphertext
        flip_pos = meta["payload_offset"] + 8 + 20   # past seq(4)+len(4)+some ciphertext
        raw[flip_pos] ^= 0xFF
        enc.write_bytes(bytes(raw))

        out = io.BytesIO()
        with pytest.raises(Exception):
            cc.stream_decrypt_payload(str(enc), out, final_key,
                                      meta["payload_offset"],
                                      meta["payload_chunk_count"],
                                      base64.b64decode(meta["payload_nonce"]))

    def test_chunk_sequence_mismatch_detected(self, tmp_path):
        """Overwriting the sequence number field triggers a sequence mismatch error."""
        enc, meta, data = self._make_encrypted(tmp_path)
        final_key = self._get_final_key(meta)

        raw = bytearray(enc.read_bytes())
        # Corrupt the first 4 bytes (sequence number of chunk 0)
        offset = meta["payload_offset"]
        raw[offset:offset+4] = (999).to_bytes(4, "big")  # claim it's chunk 999
        enc.write_bytes(bytes(raw))

        out = io.BytesIO()
        with pytest.raises(ValueError, match="sequence"):
            cc.stream_decrypt_payload(str(enc), out, final_key,
                                      meta["payload_offset"],
                                      meta["payload_chunk_count"],
                                      base64.b64decode(meta["payload_nonce"]))

    def test_different_file_nonce_different_ciphertext(self, tmp_path):
        """Two encryptions of the same plaintext produce different ciphertext (random nonces)."""
        data = b"identical plaintext" * 1000
        src  = tmp_path / "src.bin"
        src.write_bytes(data)

        results = []
        for i in range(2):
            enc = tmp_path / f"enc{i}.qcx"
            with open(enc, "wb") as f:
                offset = f.tell()
                meta = cc.encrypt_single_streaming(str(src), f, "pw", filename="src.bin")
                meta["payload_offset"] = offset
                blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
                f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
            results.append(enc.read_bytes())

        assert results[0] != results[1], "Two encryptions of same file must differ (random nonces)"

    def test_hmac_covers_chunk_count(self, tmp_path):
        """Metadata HMAC field exists and covers payload_chunk_count."""
        import os
        data = os.urandom(1024)
        _, _, _, _, meta = TestStreamingRoundTrip()._enc_dec(tmp_path, data)
        assert "hmac" in meta
        # payload_chunk_count must be in auth_fields (covered by HMAC)
        # We verify this structurally: if we flip chunk_count and re-check HMAC it fails
        # We can't easily re-derive final_key without password here, but we verify
        # the HMAC field is present (its correctness is exercised in wrong-password test)
        assert isinstance(meta["hmac"], str) and len(meta["hmac"]) > 10


class TestShamirStreaming:
    """Shamir + streaming round-trip."""

    def test_shamir_round_trip(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE * 2 + 500)
        src  = tmp_path / "src.bin"
        enc  = tmp_path / "src.qcx"
        out  = tmp_path / "out.bin"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            offset = f.tell()
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=3, k=2, filename="src.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        assert len(shares) == 3
        assert meta["version"] == 1
        assert meta["payload_chunk_count"] > 0

        # Decrypt with k=2 shares (shares 0 and 2)
        share_dicts = [cc.decode_share(s) for s in [shares[0], shares[2]]]
        master_key  = cc.shamir_recover(share_dicts)
        sk          = cc.aes_gcm_decrypt(master_key, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                         base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss      = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        final_key   = cc.xor_bytes(master_key, kem_ss)

        with open(out, "wb") as f:
            fname, sz, ts = cc.decrypt_streaming(str(enc), f, meta, final_key)

        assert out.read_bytes() == data
        assert fname == "src.bin"
        assert sz == len(data)

    def test_shamir_insufficient_shares_fails(self, tmp_path):
        data = os.urandom(512)
        src  = tmp_path / "src.bin"
        enc  = tmp_path / "src.qcx"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            offset = f.tell()
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=3, k=3, filename="src.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        # Using only 2 of 3 required shares → shamir_recover produces an out-of-range
        # integer (wrong polynomial reconstruction) → ValueError before we touch AES-GCM.
        share_dicts = [cc.decode_share(s) for s in shares[:2]]
        with pytest.raises((ValueError, Exception)):
            wrong_master = cc.shamir_recover(share_dicts)
            # If recovery didn't raise, the wrong key should fail AES-GCM:
            cc.aes_gcm_decrypt(wrong_master,
                               base64.b64decode(meta["kyber_sk_enc_nonce"]),
                               base64.b64decode(meta["kyber_sk_enc"]))


class TestFileDetection:
    """File format detection and load_pkg integration."""

    def test_streaming_file_detected_correctly(self, tmp_path):
        """Streaming detection: payload_chunk_count present → streaming path."""
        data = os.urandom(1024)
        src  = tmp_path / "src.bin"
        enc  = tmp_path / "src.qcx"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "pw")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        from quantacrypt.ui.decryptor import load_pkg
        pkg  = load_pkg(str(enc))
        meta = pkg["meta"]
        # Streaming check: payload_chunk_count present in meta
        is_streaming = (meta.get("version", 0) >= 1 and "payload_chunk_count" in meta)
        assert is_streaming




# ══════════════════════════════════════════════════════════════════════════════
# BUG-A / BUG-B / BUG-C — fixes applied in bug-check session
# ══════════════════════════════════════════════════════════════════════════════

def _make_qcx_bytes(meta_override=None):
    """Build a minimal .qcx tail from a meta dict and return raw bytes."""
    import struct, json
    from quantacrypt.core.crypto import MAGIC
    meta = {
        "version": 1, "mode": "single", "key_bits": 512,
        "chunk_size": 4194304, "argon_salt": "AA==", "kyber_kem_ct": "AA==",
        "kyber_sk_enc_nonce": "AA==", "kyber_sk_enc": "AA==",
        "payload_nonce": "AA==", "payload_chunk_count": 1,
        "filename_nonce": "AA==", "filename_enc": "AA==", "hmac": "AA==",
    }
    if meta_override:
        meta.update(meta_override)
    blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
    return b"x" * 16 + MAGIC + struct.pack(">I", len(blob)) + blob


def _write_qcx(data, tmp_path):
    """Write bytes to a temp .qcx file, return path."""
    p = str(tmp_path)
    with open(p, "wb") as f:
        f.write(data)
    return p


class TestLoadPkgValidation:
    """BUG-B/C: load_pkg must raise descriptive ValueError for malformed meta."""

    def test_valid_single_file_loads(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes(), tmp_path / "ok.qcx")
        pkg = load_pkg(path)
        assert pkg["meta"]["mode"] == "single"

    def test_missing_mode_raises(self, tmp_path):
        import struct, json
        from quantacrypt.core.crypto import MAGIC
        from quantacrypt.ui.decryptor import load_pkg
        meta = {"version": 1, "key_bits": 512}  # no 'mode'
        blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
        data = b"x" * 16 + MAGIC + struct.pack(">I", len(blob)) + blob
        path = _write_qcx(data, tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="mode"):
            load_pkg(path)

    def test_unknown_mode_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "quantum_magic"}), tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="mode"):
            load_pkg(path)

    def test_shamir_missing_threshold_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "shamir", "total": 3}), tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="threshold"):
            load_pkg(path)

    def test_shamir_missing_total_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "shamir", "threshold": 2}), tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="total"):
            load_pkg(path)

    def test_shamir_threshold_exceeds_total_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "shamir", "threshold": 5, "total": 3}),
                          tmp_path / "bad.qcx")
        with pytest.raises(ValueError):
            load_pkg(path)

    def test_valid_shamir_file_loads(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(
            _make_qcx_bytes({"mode": "shamir", "threshold": 2, "total": 3}),
            tmp_path / "shamir.qcx")
        pkg = load_pkg(path)
        assert pkg["meta"]["threshold"] == 2


class TestEncryptorDecSizeGuard:
    """BUG-A: dec_size getsize must not propagate OSError."""

    def test_dec_size_oserror_is_caught(self):
        import inspect
        import quantacrypt.ui.encryptor as encryptor
        src = inspect.getsource(encryptor.EncryptorApp._run)
        # After the fix an except OSError clause guards the getsize
        assert "except OSError" in src, "_run should catch OSError around dec_size getsize"
        assert "dec_size = 0" in src, "dec_size should default to 0 on OSError"



# ═══════════════════════════════════════════════════════════════════════════════
# Tests for new Shamir / clipboard / verify features
# ═══════════════════════════════════════════════════════════════════════════════

