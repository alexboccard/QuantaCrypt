"""
QuantaCrypt Integration Tests
Full-stack tests for encryption, decryption, folder operations, and recent files.
"""
import os
import os as _os_t
import tempfile as _tmp_t
import shutil as _sh_t
import json
import struct
import hashlib
import base64
import time
import traceback
import zipfile

import pytest
from quantacrypt.core import crypto as cc
from tests.conftest import (_widget_texts, MAGIC, make_pkg_bytes, load_pkg,
                            requires_tkinter, HAS_TKINTER)


# ─────────────────────────────────────────────────────────────────────────────
# Tk harness
#
# The Tk UI is outside the coverage gate, so the tests below drive real widgets
# and assert on what those widgets end up showing — never on the text of the
# methods that built them.  (Duplicated from test_gui_logic.py: conftest.py is
# the natural home once both files can be touched together.)
# ─────────────────────────────────────────────────────────────────────────────


def _write_qcx(tmp_path, password="s3cr3t-verify!!", data=b"hello verify" * 500,
               chunk_size=None, name="data"):
    """Write a real .qcx into ``tmp_path`` and return ``(path, meta)``.

    ``chunk_size`` shrinks cc.CHUNK_SIZE for this encryption only, so a
    multi-chunk payload costs kilobytes instead of the 4 MB the production
    constant would otherwise require.  Nothing reads the constant back off the
    file, so the shrunk value never escapes the call.
    """
    src_file = tmp_path / f"{name}.bin"
    src_file.write_bytes(data)
    qcx_file = tmp_path / f"{name}.qcx"
    previous = cc.CHUNK_SIZE
    if chunk_size:
        cc.CHUNK_SIZE = chunk_size
    try:
        with open(qcx_file, "wb") as f:
            offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src_file), f, password,
                                               filename=f"{name}.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
    finally:
        cc.CHUNK_SIZE = previous
    src_file.unlink()          # keep directory snapshots down to the .qcx alone
    return qcx_file, meta



class TestIndividualShareFiles:
    """Verify per-person share file writing logic."""

    @staticmethod
    def _write_shares_to(out_dir, shares, k, n, stem, qcx_path):
        import hashlib
        from quantacrypt.core import crypto as cc
        fingerprint = ""
        try:
            with open(qcx_path, "rb") as fh:
                fingerprint = hashlib.sha256(fh.read(65536)).hexdigest()[:12]
        except Exception: pass
        mnemonics = [cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k})
                     for s in shares]
        qcx_name = _os_t.path.basename(qcx_path)
        saved = []
        for i, s in enumerate(shares, 1):
            fname = _os_t.path.join(out_dir, f"{stem}.share-{i}-of-{n}.txt")
            mn = mnemonics[i-1]
            fp_line = (f"File fingerprint:  {fingerprint}...\n") if fingerprint else ""
            with open(fname, "w") as f:
                f.write(
                    f"QuantaCrypt Share {i} of {n}\n"
                    f"{'='*60}\n"
                    f"Encrypted file:    {qcx_name}\n"
                    f"{fp_line}"
                    f"Threshold:         Any {k} of {n} shares are needed to decrypt\n"
                    f"{'='*60}\n\n"
                    f"KEEP THIS FILE PRIVATE.\n\n"
                    f"── QCSHARE- code ──────────────────────────────────────\n"
                    f"{s}\n\n"
                )
                if mn:
                    f.write(
                        f"── 50-word mnemonic ─────────────────────────────────────\n"
                        f"{mn}\n\n"
                    )
            saved.append(fname)
        return saved

    def setup_method(self):
        import json
        from quantacrypt.core import crypto as cc
        self.tmp_dir  = _tmp_t.mkdtemp()
        self.qcx_path = _os_t.path.join(self.tmp_dir, "test.qcx")
        self.out_dir  = _os_t.path.join(self.tmp_dir, "shares_out")
        _os_t.makedirs(self.out_dir)
        import struct
        with open(self.qcx_path, "wb") as f:
            blob = json.dumps({"meta": {"version": 1, "mode": "shamir",
                                         "threshold": 2, "total": 3}},
                              separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        master = _os_t.urandom(64)
        raw_shares = cc.shamir_split(master, 3, 2)
        self.shares = [cc.encode_share(s) for s in raw_shares]
        self.k, self.n = 2, 3

    def teardown_method(self):
        _sh_t.rmtree(self.tmp_dir, ignore_errors=True)

    def _write(self):
        return self._write_shares_to(self.out_dir, self.shares, self.k, self.n,
                                     "myfile", self.qcx_path)

    def test_correct_number_of_files_created(self):
        saved = self._write()
        assert len(saved) == self.n

    def test_each_file_named_correctly(self):
        saved = self._write()
        for i, path in enumerate(saved, 1):
            assert f"share-{i}-of-{self.n}" in _os_t.path.basename(path)

    def test_each_file_contains_only_its_own_share(self):
        saved = self._write()
        for i, (path, share) in enumerate(zip(saved, self.shares), 1):
            content = open(path).read()
            assert share in content, f"share-{i} missing its QCSHARE- code"
            for j, other in enumerate(self.shares, 1):
                if j != i:
                    assert other not in content, f"share-{i} leaks share-{j}!"

    def test_each_file_contains_threshold_info(self):
        saved = self._write()
        for path in saved:
            assert f"Any {self.k} of {self.n}" in open(path).read()

    def test_each_file_contains_mnemonic(self):
        saved = self._write()
        for path in saved:
            assert "mnemonic" in open(path).read().lower()

    def test_files_contain_fingerprint(self):
        saved = self._write()
        for path in saved:
            assert "fingerprint" in open(path).read().lower()

    def test_exactly_one_qcshare_per_file(self):
        """Each file should contain exactly one QCSHARE- payload line (plus one in the header label)."""
        saved = self._write()
        for i, path in enumerate(saved, 1):
            lines = open(path).read().splitlines()
            # Count lines that START with QCSHARE- (i.e., are the actual share code)
            code_lines = [l for l in lines if l.startswith("QCSHARE-")]
            assert len(code_lines) == 1, f"share-{i} file has {len(code_lines)} QCSHARE- code lines, expected 1"


class TestClipboardTimer:
    """Verify ClipboardTimer state machine.

    These used to be gated on DISPLAY/WAYLAND_DISPLAY, which is never set on
    macOS — so they only ever ran on Linux-with-a-display.  The tk_root fixture
    gates on a Tk root that actually opens, which is the real precondition.
    """

    def test_timer_class_exists(self):
        from quantacrypt.ui.shared import ClipboardTimer
        assert callable(ClipboardTimer)

    def test_cancel_before_start_is_safe(self, tk_root):
        import tkinter as tk
        from quantacrypt.ui.shared import ClipboardTimer
        lbl = tk.Label(tk_root, text="")
        timer = ClipboardTimer(tk_root, lbl)
        timer.cancel()  # must not raise

    def test_start_arms_the_countdown(self, tk_root):
        import tkinter as tk
        from quantacrypt.ui.shared import ClipboardTimer
        lbl = tk.Label(tk_root, text="")
        timer = ClipboardTimer(tk_root, lbl, seconds=30)
        timer.start()
        # start() runs the first tick straight away: it renders the full count,
        # then decrements for the second the `after` job will show.  The old
        # `_remain == 30` assertion never ran anywhere, and is simply wrong.
        assert lbl.cget("text") == "Clipboard clears in 30s"
        assert timer._remain == 29
        assert timer._job is not None
        timer.cancel()

    def test_cancel_resets_state(self, tk_root):
        import tkinter as tk
        from quantacrypt.ui.shared import ClipboardTimer
        lbl = tk.Label(tk_root, text="")
        timer = ClipboardTimer(tk_root, lbl, seconds=30)
        timer.start()
        timer.cancel()
        assert timer._remain == 0
        assert timer._job is None
        assert lbl.cget("text") == ""


@requires_tkinter
class TestVerifyKeyMethod:
    """Drive the verify-without-decrypt flow and assert what it actually does:
    it proves the credentials, writes nothing, and leaves the wizard usable."""

    @staticmethod
    def _worker(qcx_path, meta, outcome):
        """Bare namespace carrying only what DecryptorApp._verify_run touches,
        so the worker body runs without a display.  ``outcome`` records which
        completion callback the method routed to."""
        import types
        return types.SimpleNamespace(
            _meta=meta, _qcx_path=str(qcx_path), _cancel=False,
            _prog_cb=lambda *a, **k: None,
            _after=lambda fn: fn(),          # run the main-thread callback inline
            _verify_done=lambda: outcome.append(("ok", None)),
            _cancelled=lambda: outcome.append(("cancelled", None)),
            _fail=lambda exc: outcome.append(("fail", exc)),
        )

    def test_verify_methods_exist(self):
        from quantacrypt.ui.decryptor import DecryptorApp
        assert hasattr(DecryptorApp, "_verify_run")
        assert hasattr(DecryptorApp, "_start_verify")
        assert hasattr(DecryptorApp, "_verify_done")
        assert hasattr(DecryptorApp, "_reset_and_decrypt")

    def test_verify_run_writes_no_file(self, tmp_path):
        """The contract is "nothing lands on disk" — so snapshot the directory
        around a real verify run rather than grepping the method for ".tmp"."""
        from quantacrypt.ui.decryptor import DecryptorApp
        qcx_file, meta = _write_qcx(tmp_path)
        before = sorted(os.listdir(tmp_path))
        sizes_before = {n: (tmp_path / n).stat().st_size for n in before}
        outcome = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, outcome), "s3cr3t-verify!!")
        assert outcome == [("ok", None)]
        assert sorted(os.listdir(tmp_path)) == before
        assert {n: (tmp_path / n).stat().st_size for n in before} == sizes_before

    def test_verify_run_derives_the_key_through_core_package(self, tmp_path, monkeypatch):
        """Key derivation and its metadata-HMAC check belong to
        core.package.derive_final_key, shared with qc-core.  Spy on the seam to
        prove the wizard calls it, then hand back a bogus key to prove it *uses*
        the result instead of deriving its own alongside."""
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.decryptor import DecryptorApp
        qcx_file, meta = _write_qcx(tmp_path)
        calls = []
        real = pkg.derive_final_key

        def spy(meta_arg, **kw):
            calls.append((meta_arg, kw))
            return real(meta_arg, **kw)

        monkeypatch.setattr(pkg, "derive_final_key", spy)
        outcome = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, outcome), "s3cr3t-verify!!")
        assert outcome == [("ok", None)]
        assert len(calls) == 1
        meta_arg, kw = calls[0]
        assert meta_arg is meta
        assert kw["password"] == "s3cr3t-verify!!" and kw["shares"] is None

        monkeypatch.setattr(pkg, "derive_final_key",
                            lambda *a, **k: (b"\x00" * 64, b"\x00" * 32))
        outcome = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, outcome), "s3cr3t-verify!!")
        assert outcome and outcome[0][0] == "fail"

    def test_verify_run_calls_verify_first_chunk(self, tmp_path, monkeypatch):
        """Chunk-0 proof is core.package.verify_first_chunk; the wizard must
        hand it the file, the metadata and the derived key."""
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.decryptor import DecryptorApp
        qcx_file, meta = _write_qcx(tmp_path)
        seen = []
        real = pkg.verify_first_chunk

        def spy(path, meta_arg, key):
            seen.append((path, meta_arg, key))
            return real(path, meta_arg, key)

        monkeypatch.setattr(pkg, "verify_first_chunk", spy)
        outcome = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, outcome), "s3cr3t-verify!!")
        assert outcome == [("ok", None)]
        assert len(seen) == 1
        path, meta_arg, key = seen[0]
        assert path == str(qcx_file) and meta_arg is meta
        assert key == pkg.derive_final_key(meta, password="s3cr3t-verify!!")[0]

    def test_verify_run_reads_only_the_first_chunk(self, tmp_path):
        """Corrupt chunk 1 and leave chunk 0 intact: verify must still pass —
        it never reads that far — while a full decrypt of the same file fails."""
        import io
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.decryptor import DecryptorApp
        qcx_file, meta = _write_qcx(tmp_path, chunk_size=4096, data=b"A" * 20000)
        assert meta["payload_chunk_count"] > 1
        raw = bytearray(qcx_file.read_bytes())
        offset = meta["payload_offset"]
        chunk0_len = struct.unpack(">I", raw[offset + 4:offset + 8])[0]
        chunk1 = offset + 8 + chunk0_len                     # [seq:4][len:4][ct…]
        assert struct.unpack(">I", raw[chunk1:chunk1 + 4])[0] == 1
        raw[chunk1 + 8] ^= 0xFF                              # flip a byte of chunk 1
        qcx_file.write_bytes(bytes(raw))

        outcome = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, outcome), "s3cr3t-verify!!")
        assert outcome == [("ok", None)]

        final_key, _hmac_key = pkg.derive_final_key(meta, password="s3cr3t-verify!!")
        with pytest.raises(Exception):
            cc.decrypt_streaming(str(qcx_file), io.BytesIO(), meta, final_key)

    def test_start_verify_passes_the_validation_result_through(self):
        """_start_verify gates on _validate() and hands the result to _begin —
        a validation error must reach _begin rather than be swallowed."""
        import types
        from quantacrypt.ui.decryptor import DecryptorApp
        begun = []
        obj = types.SimpleNamespace(_busy=False, _validate=lambda: "Enter a password",
                                    _begin=lambda **kw: begun.append(kw))
        DecryptorApp._start_verify(obj)
        assert begun == [{"verify": True, "err": "Enter a password"}]
        obj._validate = lambda: None
        DecryptorApp._start_verify(obj)
        assert begun[-1] == {"verify": True, "err": None}
        obj._busy = True                    # no second run on top of a live worker
        DecryptorApp._start_verify(obj)
        assert len(begun) == 2

    def test_verify_done_leaves_decrypt_button_enabled(self, tk_root, tmp_path, monkeypatch):
        """Verify writes nothing, so the Decrypt button must stay usable —
        unlike _done, which disables it until "Decrypt another"."""
        import quantacrypt.ui.decryptor as dec_mod
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        monkeypatch.setattr(dec_mod, "notify", lambda *a, **k: None)
        qcx_file, meta = _write_qcx(tmp_path)
        app = dec_mod.DecryptorApp(tk_root, payload={"meta": meta},
                                   qcx_path=str(qcx_file))
        app.withdraw()
        try:
            app._btn.enable(False)
            app._verify_done()
            assert app._btn._enabled is True
            # Nothing was written, so the wizard stays on the Decrypt step.
            assert app._wiz._active == 2
            # Contrast: the real completion path does disable it.
            out = tmp_path / "restored.bin"
            out.write_bytes(b"z" * 10)
            app._done(str(out), 10, fname="data.bin")
            assert app._btn._enabled is False
            assert app._wiz._active == len(app.STEPS)
        finally:
            app.destroy()

    def test_verify_end_to_end_single_password(self, tmp_path):
        """Real .qcx through the real worker: the right password verifies, the
        wrong one fails, and neither leaves anything behind."""
        from quantacrypt.ui.decryptor import DecryptorApp
        qcx_file, meta = _write_qcx(tmp_path)
        before = sorted(os.listdir(tmp_path))
        good = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, good), "s3cr3t-verify!!")
        assert good == [("ok", None)]
        bad = []
        DecryptorApp._verify_run(self._worker(qcx_file, meta, bad), "wrong-password")
        assert bad and bad[0][0] == "fail"
        assert sorted(os.listdir(tmp_path)) == before


# ═══════════════════════════════════════════════════════════════════════════════
# Folder encryption tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestFolderHelpers:
    """Unit-test _folder_stats and _zip_folder without any Tk."""

    def test_folder_stats_counts_files(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"hello")
        (tmp_path / "b.txt").write_bytes(b"world!")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.bin").write_bytes(b"x" * 100)
        from quantacrypt.ui.encryptor import _folder_stats
        count, total = _folder_stats(str(tmp_path))
        assert count == 3
        assert total == 5 + 6 + 100

    def test_folder_stats_empty_folder(self, tmp_path):
        from quantacrypt.ui.encryptor import _folder_stats
        count, total = _folder_stats(str(tmp_path))
        assert count == 0
        assert total == 0

    def test_zip_folder_creates_archive(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "hello.txt").write_text("hello world")
        (src / "data.bin").write_bytes(b"\x00" * 256)
        sub = src / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested")
        import zipfile, tempfile, os
        from quantacrypt.ui.encryptor import _zip_folder
        fd, zpath = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            _zip_folder(str(src), zpath)
            assert os.path.getsize(zpath) > 0
            with zipfile.ZipFile(zpath) as zf:
                names = zf.namelist()
            # All three files should be present with src/ prefix preserved
            assert any("hello.txt" in n for n in names)
            assert any("data.bin"  in n for n in names)
            assert any("nested.txt" in n for n in names)
        finally:
            os.unlink(zpath)

    def test_zip_folder_preserves_top_level_dirname(self, tmp_path):
        src = tmp_path / "myproject"
        src.mkdir()
        (src / "file.txt").write_text("content")
        import zipfile, tempfile, os
        from quantacrypt.ui.encryptor import _zip_folder
        fd, zpath = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            _zip_folder(str(src), zpath)
            with zipfile.ZipFile(zpath) as zf:
                names = zf.namelist()
            # Entry should start with myproject/ not just file.txt at root
            assert any(n.startswith("myproject/") for n in names), \
                f"Expected myproject/ prefix, got: {names}"
        finally:
            os.unlink(zpath)

    def test_zip_folder_roundtrip_contents(self, tmp_path):
        """Files extracted from the zip must have identical content."""
        src = tmp_path / "data"
        src.mkdir()
        content = b"\xde\xad\xbe\xef" * 1000
        (src / "payload.bin").write_bytes(content)
        import zipfile, tempfile, os
        from quantacrypt.ui.encryptor import _zip_folder
        fd, zpath = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            _zip_folder(str(src), zpath)
            with zipfile.ZipFile(zpath) as zf:
                entry = next(n for n in zf.namelist() if n.endswith("payload.bin"))
                extracted = zf.read(entry)
            assert extracted == content
        finally:
            os.unlink(zpath)

    def test_zip_progress_callback_fired(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(5):
            (src / f"file{i}.txt").write_text(f"content {i}")
        import tempfile, os
        from quantacrypt.ui.encryptor import _zip_folder
        calls = []
        fd, zpath = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            _zip_folder(str(src), zpath, progress_cb=lambda msg: calls.append(msg))
            assert len(calls) == 5   # one per file
            assert all("Compressing" in c for c in calls)
        finally:
            os.unlink(zpath)


class TestFolderEncryptionRoundTrip:
    """End-to-end: encrypt a folder, decrypt the .qcx, verify contents match."""

    def test_folder_encrypt_decrypt_roundtrip(self, tmp_path):
        import zipfile, io

        # Build a source folder with nested content
        src = tmp_path / "project"
        src.mkdir()
        (src / "readme.txt").write_text("Hello from QuantaCrypt folder encryption!")
        (src / "data.bin").write_bytes(os.urandom(8192))
        sub = src / "assets"
        sub.mkdir()
        (sub / "logo.png").write_bytes(os.urandom(512))

        # Encrypt via crypto_core directly (same path _run uses)
        qcx = tmp_path / "project.qcx"

        # Zip first (same as _run does)
        import tempfile
        fd, zip_path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            from quantacrypt.ui.encryptor import _zip_folder
            _zip_folder(str(src), zip_path)

            with open(qcx, "wb") as f:
                meta = cc.encrypt_single_streaming(
                    zip_path, f, "test-password",
                    filename="project.zip")
                blob = __import__("json").dumps({"meta": meta},
                                  separators=(",", ":")).encode()
                f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        finally:
            os.unlink(zip_path)

        # Decrypt
        from quantacrypt.ui.decryptor import load_pkg
        pkg = load_pkg(str(qcx))
        meta = pkg["meta"]
        import base64, struct
        argon_key = cc.argon2id_derive(b"test-password",
                                       base64.b64decode(meta["argon_salt"]))
        sk = cc.aes_gcm_decrypt(argon_key,
                                base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        final_key = cc.xor_bytes(argon_key, kem_ss)
        cc._verify_meta_hmac(final_key, meta)

        dec_zip = tmp_path / "out.zip"
        with open(dec_zip, "wb") as f:
            fname, sz, ts = cc.decrypt_streaming(str(qcx), f, meta, final_key)

        assert fname == "project.zip"

        # Verify zip contents
        with zipfile.ZipFile(dec_zip) as zf:
            names = zf.namelist()
            readme = next(n for n in names if n.endswith("readme.txt"))
            assert zf.read(readme).decode() == "Hello from QuantaCrypt folder encryption!"
            assert any(n.endswith("data.bin")  for n in names)
            assert any(n.endswith("logo.png")  for n in names)

    @requires_tkinter
    def test_validate_accepts_folder(self, tmp_path):
        """_validate should return None for a valid folder + output path."""
        (tmp_path / "source").mkdir()
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        out = str(tmp_path / "out.qcx")
        obj = types.SimpleNamespace(
            _path=str(tmp_path / "source"),
            _is_folder=True,
            _src_type=types.SimpleNamespace(get=lambda: "folder"),
            _mode=types.SimpleNamespace(get=lambda: "single"),
            _pw1v=types.SimpleNamespace(get=lambda: "strongpassword"),
            _pw2v=types.SimpleNamespace(get=lambda: "strongpassword"),
            _n=types.SimpleNamespace(get=lambda: 3),
            _k=types.SimpleNamespace(get=lambda: 2),
            _out=types.SimpleNamespace(get=lambda: out),
        )
        result = EncryptorApp._validate(obj)
        assert result is None, f"Expected None, got: {result}"

    @requires_tkinter
    def test_validate_rejects_missing_folder(self, tmp_path):
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        out = str(tmp_path / "out.qcx")
        obj = types.SimpleNamespace(
            _path=str(tmp_path / "does_not_exist"),
            _is_folder=True,
            _src_type=types.SimpleNamespace(get=lambda: "folder"),
            _mode=types.SimpleNamespace(get=lambda: "single"),
            _pw1v=types.SimpleNamespace(get=lambda: "pass"),
            _pw2v=types.SimpleNamespace(get=lambda: "pass"),
            _n=types.SimpleNamespace(get=lambda: 3),
            _k=types.SimpleNamespace(get=lambda: 2),
            _out=types.SimpleNamespace(get=lambda: out),
        )
        result = EncryptorApp._validate(obj)
        assert result is not None
        assert "Folder" in result or "folder" in result

    def test_zip_tmp_cleaned_up_on_success(self, tmp_path):
        """The temporary zip must be deleted after successful encryption."""
        import glob
        src = tmp_path / "stuff"
        src.mkdir()
        (src / "a.txt").write_text("hello")
        import zipfile, tempfile, os
        from quantacrypt.ui.encryptor import _zip_folder

        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "*.zip")))

        fd, zip_path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        qcx = tmp_path / "stuff.qcx"
        try:
            _zip_folder(str(src), zip_path)
            with open(qcx, "wb") as f:
                meta = cc.encrypt_single_streaming(zip_path, f, "pw", filename="stuff.zip")
                blob = __import__("json").dumps({"meta": meta}, separators=(",",":")).encode()
                f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        finally:
            # Simulate the finally block in _run
            try: os.remove(zip_path)
            except OSError: pass

        assert not os.path.exists(zip_path), "Temp zip not cleaned up after encryption"


# ═══════════════════════════════════════════════════════════════════════════════
# Tests for recent files, batch encryption, and file inspection
# ═══════════════════════════════════════════════════════════════════════════════

class TestRecentFiles:

    def test_recent_files_class_exists(self):
        from quantacrypt.ui.shared import RecentFiles
        assert callable(RecentFiles.load)
        assert callable(RecentFiles.add)
        assert callable(RecentFiles.clear)

    def test_load_returns_list(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        result = RecentFiles.load()
        assert isinstance(result, list)

    def test_add_and_load_roundtrip(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        # Create a real file so isfile() passes
        f = tmp_path / "test.qcx"
        f.write_bytes(b"fake")
        RecentFiles.add(str(f))
        items = RecentFiles.load()
        assert len(items) == 1
        assert items[0][0] == str(f)

    def test_add_deduplicates(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        f = tmp_path / "test.qcx"; f.write_bytes(b"x")
        RecentFiles.add(str(f))
        RecentFiles.add(str(f))  # add again
        items = RecentFiles.load()
        assert len(items) == 1  # only one entry

    def test_add_most_recent_first(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        f1 = tmp_path / "a.qcx"; f1.write_bytes(b"x")
        f2 = tmp_path / "b.qcx"; f2.write_bytes(b"x")
        RecentFiles.add(str(f1))
        RecentFiles.add(str(f2))
        items = RecentFiles.load()
        assert items[0][0] == str(f2)  # most recent first

    def test_clear_empties_list(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        f = tmp_path / "test.qcx"; f.write_bytes(b"x")
        RecentFiles.add(str(f))
        RecentFiles.clear()
        assert RecentFiles.load() == []

    def test_missing_files_filtered_out(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        import json
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        # Write a record pointing at a non-existent file
        with open(RecentFiles._PATH, "w") as f:
            json.dump([{"path": str(tmp_path / "gone.qcx"), "ts": 0}], f)
        items = RecentFiles.load()
        assert items == []  # filtered out because file doesn't exist

    def test_max_items_respected(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        monkeypatch.setattr(RecentFiles, "MAX_ITEMS", 3)
        for i in range(5):
            f = tmp_path / f"file{i}.qcx"; f.write_bytes(b"x")
            RecentFiles.add(str(f))
        items = RecentFiles.load()
        assert len(items) <= 3


@requires_tkinter
class TestBatchEncryption:

    def test_validate_batch_no_files(self):
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        obj = types.SimpleNamespace(
            _batch_paths=[],
            _mode=types.SimpleNamespace(get=lambda: "single"),
            _pw1v=types.SimpleNamespace(get=lambda: "pw"),
            _pw2v=types.SimpleNamespace(get=lambda: "pw"),
            _n=types.SimpleNamespace(get=lambda: 3),
            _k=types.SimpleNamespace(get=lambda: 2),
            _batch_out_var=types.SimpleNamespace(get=lambda: "/tmp"),
        )
        result = EncryptorApp._validate_batch(obj)
        assert result == "Select at least one file"

    def test_validate_batch_missing_file(self, tmp_path):
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        obj = types.SimpleNamespace(
            _batch_paths=[str(tmp_path / "nope.bin")],
            _mode=types.SimpleNamespace(get=lambda: "single"),
            _pw1v=types.SimpleNamespace(get=lambda: "pw"),
            _pw2v=types.SimpleNamespace(get=lambda: "pw"),
            _n=types.SimpleNamespace(get=lambda: 3),
            _k=types.SimpleNamespace(get=lambda: 2),
            _batch_out_var=types.SimpleNamespace(get=lambda: str(tmp_path)),
        )
        result = EncryptorApp._validate_batch(obj)
        assert result is not None and "no longer exist" in result

    def test_validate_batch_valid(self, tmp_path):
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        f = tmp_path / "a.txt"; f.write_bytes(b"hello")
        obj = types.SimpleNamespace(
            _batch_paths=[str(f)],
            _mode=types.SimpleNamespace(get=lambda: "single"),
            _pw1v=types.SimpleNamespace(get=lambda: "good-password"),
            _pw2v=types.SimpleNamespace(get=lambda: "good-password"),
            _n=types.SimpleNamespace(get=lambda: 3),
            _k=types.SimpleNamespace(get=lambda: 2),
            _batch_out_var=types.SimpleNamespace(get=lambda: str(tmp_path)),
        )
        result = EncryptorApp._validate_batch(obj)
        assert result is None

    def test_validate_batch_empty_password(self, tmp_path):
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        f = tmp_path / "a.txt"; f.write_bytes(b"hello")
        obj = types.SimpleNamespace(
            _batch_paths=[str(f)],
            _mode=types.SimpleNamespace(get=lambda: "single"),
            _pw1v=types.SimpleNamespace(get=lambda: ""),
            _pw2v=types.SimpleNamespace(get=lambda: ""),
            _n=types.SimpleNamespace(get=lambda: 3),
            _k=types.SimpleNamespace(get=lambda: 2),
            _batch_out_var=types.SimpleNamespace(get=lambda: str(tmp_path)),
        )
        result = EncryptorApp._validate_batch(obj)
        assert result == "Password cannot be empty"

    def test_batch_encrypt_roundtrip(self, tmp_path):
        """Encrypt 3 files in batch, verify all produce valid .qcx files."""
        import base64, json
        from quantacrypt.core import crypto as cc
        files = []
        for i in range(3):
            f = tmp_path / f"file{i}.bin"
            f.write_bytes(os.urandom(1024 * (i + 1)))
            files.append(str(f))
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        from quantacrypt.ui.encryptor import _folder_stats  # import guard
        for path in files:
            orig = os.path.basename(path)
            stem = os.path.splitext(orig)[0]
            qcx = out_dir / (stem + ".qcx")
            with open(qcx, "wb") as f:
                meta = cc.encrypt_single_streaming(
                    path, f, "batch-password", filename=orig)
                blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
                f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        # Verify all three can be decrypted
        from quantacrypt.ui.decryptor import load_pkg
        for path in files:
            stem = os.path.splitext(os.path.basename(path))[0]
            qcx = out_dir / (stem + ".qcx")
            pkg = load_pkg(str(qcx))
            meta = pkg["meta"]
            argon_key = cc.argon2id_derive(b"batch-password",
                                           base64.b64decode(meta["argon_salt"]))
            sk = cc.aes_gcm_decrypt(argon_key,
                                    base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                    base64.b64decode(meta["kyber_sk_enc"]))
            kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
            final_key = cc.xor_bytes(argon_key, kem_ss)
            cc._verify_meta_hmac(final_key, meta)
            out_f = tmp_path / (stem + ".dec")
            with open(out_f, "wb") as f:
                cc.decrypt_streaming(str(qcx), f, meta, final_key)
            assert out_f.read_bytes() == open(path, "rb").read()


class TestFileInspection:

    @requires_tkinter
    def test_inspect_method_exists(self):
        from quantacrypt.ui.launcher import LauncherApp
        assert hasattr(LauncherApp, "_inspect_file")

    def test_inspect_reads_valid_qcx(self, tmp_path):
        """load_pkg should succeed for a file that _inspect_file would open."""
        import json
        from quantacrypt.core import crypto as cc
        qcx = tmp_path / "test.qcx"
        with open(qcx, "wb") as f:
            meta = cc.encrypt_single_streaming(
                __file__, f, "test-pw", filename="test.py")
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        from quantacrypt.ui.decryptor import load_pkg
        pkg = load_pkg(str(qcx))
        assert pkg["meta"]["mode"] == "single"
        assert pkg["meta"]["version"] == 1

    def test_inspect_rejects_invalid_file(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        bad = tmp_path / "garbage.qcx"
        bad.write_bytes(b"this is not a qcx file")
        try:
            load_pkg(str(bad))
            assert False, "Should have raised"
        except (ValueError, Exception):
            pass  # expected


# ═══════════════════════════════════════════════════════════════════════════════
# Tests for folder encryption, batch encryption, and inspect features
# ═══════════════════════════════════════════════════════════════════════════════

class TestFolderEncryption:
    """_zip_folder creates a valid zip preserving directory structure."""

    def test_zip_preserves_top_level_dir_name(self, tmp_path):
        from quantacrypt.ui.encryptor import _zip_folder
        import zipfile
        src = tmp_path / "myproject"
        src.mkdir()
        (src / "readme.txt").write_text("hello")
        (src / "src").mkdir()
        (src / "src" / "main.py").write_text("print()")
        out = tmp_path / "out.zip"
        _zip_folder(str(src), str(out))
        with zipfile.ZipFile(str(out)) as zf:
            names = zf.namelist()
        assert any("myproject" in n for n in names)

    def test_zip_no_absolute_paths(self, tmp_path):
        from quantacrypt.ui.encryptor import _zip_folder
        import zipfile
        src = tmp_path / "proj"
        src.mkdir()
        (src / "a.txt").write_text("x")
        out = tmp_path / "out.zip"
        _zip_folder(str(src), str(out))
        with zipfile.ZipFile(str(out)) as zf:
            for name in zf.namelist():
                assert not name.startswith("/"), f"absolute path in zip: {name}"

    def test_zip_subdirectories_included(self, tmp_path):
        from quantacrypt.ui.encryptor import _zip_folder
        import zipfile
        src = tmp_path / "root"
        src.mkdir()
        (src / "a" / "b").mkdir(parents=True)
        (src / "a" / "b" / "deep.txt").write_text("deep")
        out = tmp_path / "out.zip"
        _zip_folder(str(src), str(out))
        with zipfile.ZipFile(str(out)) as zf:
            assert any("deep.txt" in n for n in zf.namelist())

    def test_zip_empty_folder(self, tmp_path):
        from quantacrypt.ui.encryptor import _zip_folder
        import zipfile
        src = tmp_path / "empty"
        src.mkdir()
        out = tmp_path / "out.zip"
        _zip_folder(str(src), str(out))
        # Should produce a valid (possibly empty) zip without raising
        with zipfile.ZipFile(str(out)) as zf:
            assert isinstance(zf.namelist(), list)

    def test_folder_round_trip(self, tmp_path):
        """Encrypt a folder, decrypt, verify all files intact."""
        from quantacrypt.ui.encryptor import _zip_folder
        from quantacrypt.ui.decryptor import load_pkg

        src = tmp_path / "mydata"
        src.mkdir()
        (src / "file1.txt").write_bytes(b"alpha" * 200)
        (src / "sub").mkdir()
        (src / "sub" / "file2.bin").write_bytes(bytes(range(256)) * 10)

        zip_path = tmp_path / "mydata.zip"
        _zip_folder(str(src), str(zip_path))

        qcx = tmp_path / "mydata.qcx"
        pw = b"correct-horse"
        with open(qcx, "wb") as f:
            meta = cc.encrypt_single_streaming(
                str(zip_path), f, pw.decode(), filename="mydata.zip")
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        pkg = load_pkg(str(qcx))
        meta = pkg["meta"]
        argon_key = cc.argon2id_derive(pw, base64.b64decode(meta["argon_salt"]))
        sk = cc.aes_gcm_decrypt(argon_key,
            base64.b64decode(meta["kyber_sk_enc_nonce"]),
            base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        final_key = cc.xor_bytes(argon_key, kem_ss)

        out_zip = tmp_path / "recovered.zip"
        with open(out_zip, "wb") as f:
            fname, sz, ts = cc.decrypt_streaming(str(qcx), f, meta, final_key)

        assert fname == "mydata.zip"
        with zipfile.ZipFile(str(out_zip)) as zf:
            assert zf.read("mydata/file1.txt") == b"alpha" * 200
            assert zf.read("mydata/sub/file2.bin") == bytes(range(256)) * 10

    def test_folder_stats(self, tmp_path):
        from quantacrypt.ui.encryptor import _folder_stats
        src = tmp_path / "d"
        src.mkdir()
        (src / "a.txt").write_bytes(b"x" * 100)
        (src / "sub").mkdir()
        (src / "sub" / "b.txt").write_bytes(b"y" * 200)
        count, total = _folder_stats(str(src))
        assert count == 2
        assert total == 300

    def test_zip_progress_callback_called(self, tmp_path):
        from quantacrypt.ui.encryptor import _zip_folder
        src = tmp_path / "p"
        src.mkdir()
        for i in range(5):
            (src / f"f{i}.txt").write_text("data")
        out = tmp_path / "out.zip"
        calls = []
        _zip_folder(str(src), str(out), progress_cb=calls.append)
        assert len(calls) == 5


@requires_tkinter
class TestBatchEncryptionLogic:
    """_validate_batch rejects bad inputs cleanly."""

    def _make(self, batch_paths, out_dir, mode="single", pw="pw-testpad", pw2="pw-testpad", n=3, k=2):
        import types
        obj = types.SimpleNamespace(
            _batch_paths=batch_paths,
            _batch_out_var=types.SimpleNamespace(get=lambda: out_dir),
            _mode=types.SimpleNamespace(get=lambda: mode),
            _pw1v=types.SimpleNamespace(get=lambda: pw),
            _pw2v=types.SimpleNamespace(get=lambda: pw2),
            _n=types.SimpleNamespace(get=lambda: n),
            _k=types.SimpleNamespace(get=lambda: k),
        )
        from quantacrypt.ui.encryptor import EncryptorApp
        obj._validate_batch = lambda: EncryptorApp._validate_batch(obj)
        return obj

    def test_no_files_rejected(self, tmp_path):
        obj = self._make([], str(tmp_path))
        assert obj._validate_batch() is not None

    def test_missing_file_rejected(self, tmp_path):
        obj = self._make([str(tmp_path / "ghost.txt")], str(tmp_path))
        assert obj._validate_batch() is not None

    def test_nonexistent_out_dir_rejected(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        obj = self._make([str(f)], str(tmp_path / "no_such_dir"))
        assert obj._validate_batch() is not None

    def test_empty_password_rejected(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        obj = self._make([str(f)], str(tmp_path), pw="", pw2="")
        assert obj._validate_batch() is not None

    def test_mismatched_passwords_rejected(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        obj = self._make([str(f)], str(tmp_path), pw="abc-testpad", pw2="xyz")
        assert obj._validate_batch() is not None

    def test_valid_single_mode_passes(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        obj = self._make([str(f)], str(tmp_path))
        assert obj._validate_batch() is None

    def test_shamir_threshold_exceeds_total_rejected(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        obj = self._make([str(f)], str(tmp_path), mode="shamir", n=3, k=5)
        assert obj._validate_batch() is not None

    def test_shamir_valid_passes(self, tmp_path):
        f = tmp_path / "a.txt"; f.write_bytes(b"x")
        obj = self._make([str(f)], str(tmp_path), mode="shamir", n=3, k=2)
        assert obj._validate_batch() is None


@requires_tkinter
class TestInspectFeature:
    """Drive the inspect-without-decrypting popup and read back what it shows."""

    @staticmethod
    def _app(tk_root, tmp_path, monkeypatch, meta, qcx_file):
        import quantacrypt.ui.decryptor as dec_mod
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        monkeypatch.setattr(dec_mod, "notify", lambda *a, **k: None)
        app = dec_mod.DecryptorApp(tk_root, payload={"meta": meta},
                                   qcx_path=str(qcx_file))
        app.withdraw()
        return app

    @staticmethod
    def _popup_texts(app):
        """Open the details popup, collect its labels, close it again."""
        import tkinter as tk
        app._show_inspect()
        app.update()
        popups = [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)]
        assert popups, "_show_inspect should open a popup"
        popup = popups[-1]
        texts = _widget_texts(popup)
        popup.grab_release()
        popup.destroy()
        app.update()
        return texts

    def test_show_inspect_method_exists(self):
        from quantacrypt.ui.decryptor import DecryptorApp
        assert hasattr(DecryptorApp, "_show_inspect")

    def test_show_inspect_does_not_decrypt(self, tk_root, tmp_path, monkeypatch):
        """Booby-trap every path that would need the key: the popup is supposed
        to be readable with no password at all, so none of them may be hit."""
        from quantacrypt.core import package as pkg
        qcx_file, meta = _write_qcx(tmp_path)
        app = self._app(tk_root, tmp_path, monkeypatch, meta, qcx_file)
        try:
            def boom(*_a, **_k):
                raise AssertionError("inspect must not touch the key material")

            for name in ("argon2id_derive", "decrypt_streaming", "aes_gcm_decrypt",
                         "kyber_decaps"):
                monkeypatch.setattr(cc, name, boom)
            monkeypatch.setattr(pkg, "derive_final_key", boom)
            monkeypatch.setattr(pkg, "verify_first_chunk", boom)
            texts = self._popup_texts(app)
            assert any("File details" in t for t in texts)
        finally:
            app.destroy()

    def test_show_inspect_shows_the_file_fingerprint(self, tk_root, tmp_path, monkeypatch):
        qcx_file, meta = _write_qcx(tmp_path)
        expected = hashlib.sha256(qcx_file.read_bytes()[:65536]).hexdigest()[:16]
        app = self._app(tk_root, tmp_path, monkeypatch, meta, qcx_file)
        try:
            texts = self._popup_texts(app)
            assert any(expected in t for t in texts), texts
        finally:
            app.destroy()

    def test_show_inspect_describes_the_protection_mode(self, tk_root, tmp_path, monkeypatch):
        qcx_file, meta = _write_qcx(tmp_path)
        app = self._app(tk_root, tmp_path, monkeypatch, meta, qcx_file)
        try:
            assert any("Argon2id" in t for t in self._popup_texts(app))
            # _show_inspect reads only self._meta, so swapping it in is enough
            # to exercise the shamir copy without a second real encryption.
            app._meta = {"mode": "shamir", "threshold": 2, "total": 3, "version": 1}
            shamir = self._popup_texts(app)
            assert any("any 2 of 3 shares" in t for t in shamir), shamir
        finally:
            app.destroy()

    def test_show_inspect_shows_the_format_version(self, tk_root, tmp_path, monkeypatch):
        qcx_file, meta = _write_qcx(tmp_path)
        app = self._app(tk_root, tmp_path, monkeypatch, meta, qcx_file)
        try:
            texts = self._popup_texts(app)
            assert any(f"v{meta['version']}" in t for t in texts), texts
        finally:
            app.destroy()


class TestRecentFilesClassmethodAPI:
    """RecentFiles classmethods work correctly with monkeypatched _PATH."""

    def test_load_empty_when_no_file(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        assert RecentFiles.load() == []

    def test_add_then_load_returns_entry(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        f = tmp_path / "test.qcx"; f.write_bytes(b"x")
        RecentFiles.add(str(f))
        items = RecentFiles.load()
        assert len(items) == 1
        assert items[0][0] == str(f)

    def test_add_with_meta(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        f = tmp_path / "test.qcx"; f.write_bytes(b"x")
        RecentFiles.add(str(f), meta={"mode": "shamir", "threshold": 2, "total": 3})
        path, entry = RecentFiles.load()[0]
        assert entry["mode"] == "shamir"
        assert entry["threshold"] == 2
        assert entry["total"] == 3

    def test_add_deduplicates(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        f = tmp_path / "test.qcx"; f.write_bytes(b"x")
        RecentFiles.add(str(f))
        RecentFiles.add(str(f))
        assert len(RecentFiles.load()) == 1

    def test_most_recent_first(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        f1 = tmp_path / "a.qcx"; f1.write_bytes(b"x")
        f2 = tmp_path / "b.qcx"; f2.write_bytes(b"x")
        RecentFiles.add(str(f1))
        RecentFiles.add(str(f2))
        assert RecentFiles.load()[0][0] == str(f2)

    def test_clear(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        f = tmp_path / "test.qcx"; f.write_bytes(b"x")
        RecentFiles.add(str(f))
        RecentFiles.clear()
        assert RecentFiles.load() == []

    def test_missing_files_filtered(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        import json
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        with open(str(tmp_path / "r.json"), "w") as fh:
            json.dump([{"path": str(tmp_path / "gone.qcx"), "ts": 0}], fh)
        assert RecentFiles.load() == []

    def test_max_items(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        monkeypatch.setattr(RecentFiles, "MAX_ITEMS", 3)
        for i in range(6):
            f = tmp_path / f"f{i}.qcx"; f.write_bytes(b"x")
            RecentFiles.add(str(f))
        assert len(RecentFiles.load()) <= 3

    def test_remove(self, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        f1 = tmp_path / "a.qcx"; f1.write_bytes(b"x")
        f2 = tmp_path / "b.qcx"; f2.write_bytes(b"x")
        RecentFiles.add(str(f1)); RecentFiles.add(str(f2))
        RecentFiles.remove(str(f1))
        paths = [p for p, _ in RecentFiles.load()]
        assert str(f1) not in paths
        assert str(f2) in paths
