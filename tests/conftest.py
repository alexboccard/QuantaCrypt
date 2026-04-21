"""Shared pytest fixtures for QuantaCrypt test suite."""

import base64
import io
import json
import os
import struct
import sys
import tempfile

import pytest

# Stub tkinter on headless systems so tests that import UI modules don't fail.
# This must run before any test module triggers `import tkinter`.
HAS_TKINTER = False
try:
    import tkinter  # noqa: F401
    HAS_TKINTER = True
except (ImportError, ModuleNotFoundError):
    from unittest.mock import MagicMock
    for _mod in ("tkinter", "tkinter.ttk", "tkinter.filedialog",
                 "tkinter.messagebox", "tkinterdnd2"):
        sys.modules.setdefault(_mod, MagicMock())

requires_tkinter = pytest.mark.skipif(
    not HAS_TKINTER,
    reason="Needs real tkinter (UI classes are MagicMock on headless systems)",
)

from quantacrypt.core import crypto as cc

MAGIC = cc.MAGIC


def make_pkg_bytes(meta, original_name="test.bin"):
    """Create a QuantaCrypt package bytestring from metadata."""
    pkg = {"meta": meta, "original_name": original_name}
    blob = json.dumps(pkg, separators=(",", ":")).encode()
    return MAGIC + len(blob).to_bytes(4, "big") + blob


def load_pkg(data):
    """Load package metadata from QuantaCrypt bytestring."""
    i = data.rfind(MAGIC)
    if i < 0:
        raise ValueError("Not a QuantaCrypt file")
    o = i + len(MAGIC)
    n = struct.unpack(">I", data[o : o + 4])[0]
    return json.loads(data[o + 4 : o + 4 + n])


def _make_qcx(tmp_path, data, password="pw", filename="test.bin", n=None, k=None):
    """Write a .qcx and return (path, meta, shares, final_key)."""
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
        sk  = cc.aes_gcm_decrypt(mk, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                  base64.b64decode(meta["kyber_sk_enc"]))
        ks  = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        fk  = cc.xor_bytes(mk, ks)
    else:
        ak  = cc.argon2id_derive(password.encode(), base64.b64decode(meta["argon_salt"]))
        sk  = cc.aes_gcm_decrypt(ak, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                  base64.b64decode(meta["kyber_sk_enc"]))
        ks  = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        fk  = cc.xor_bytes(ak, ks)
    return enc, meta, shares, fk


def _decrypt_qcx(enc_path, meta, final_key):
    """Decrypt a .qcx and return (data, fname, sz, ts)."""
    buf = io.BytesIO()
    fname, sz, ts = cc.decrypt_streaming(str(enc_path), buf, meta, final_key)
    return buf.getvalue(), fname, sz, ts


def pytest_terminal_summary(terminalreporter, config):
    """Print a clickable file:// link to the HTML coverage report."""
    cov_dir = os.path.join(config.rootdir, "htmlcov", "index.html")
    if os.path.isfile(cov_dir):
        url = f"file://{os.path.abspath(cov_dir)}"
        terminalreporter.write_sep("=", "coverage report")
        terminalreporter.write_line(f"  HTML: {url}")


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def sample_file(tmp_dir):
    """Create a small sample file for encryption tests."""
    path = os.path.join(tmp_dir, "sample.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(256))
    return path
