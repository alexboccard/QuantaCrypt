"""Tests for the qc-core JSON-lines service and the core.package helpers."""

import io
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core import service as svc_mod
from quantacrypt.core.errors import classify_error, friendly_error
from quantacrypt.core.service import Service, stage_for


# ── Harness ──────────────────────────────────────────────────────────────────

class Harness:
    """Drive a Service in-process and collect its events."""

    def __init__(self):
        self.out = io.StringIO()
        self.exited = threading.Event()
        self.svc = Service(io.StringIO(), self.out, exit_fn=self.exited.set)
        self._n = 0

    def send(self, op, params=None, rid=None):
        self._n += 1
        rid = rid or f"r{self._n}"
        self.svc.handle_line(json.dumps({"id": rid, "op": op, "params": params or {}}))
        return rid

    def raw(self, line):
        self.svc.handle_line(line)

    def events(self, rid=None):
        self.svc.wait_idle()
        evs = [json.loads(l) for l in self.out.getvalue().splitlines() if l.strip()]
        return [e for e in evs if rid is None or e.get("id") == rid]

    def final(self, rid):
        evs = [e for e in self.events(rid) if e["event"] in ("done", "error")]
        assert evs, f"no terminal event for {rid}"
        return evs[-1]

    def result(self, rid):
        ev = self.final(rid)
        assert ev["event"] == "done", ev
        return ev["result"]

    def error(self, rid):
        ev = self.final(rid)
        assert ev["event"] == "error", ev
        return ev


@pytest.fixture
def h():
    return Harness()


@pytest.fixture
def src_file(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"quantum-safe " * 4000)
    return str(p)


@pytest.fixture
def out_dir(tmp_path):
    d = tmp_path / "out"
    d.mkdir()
    return str(d)


# ── stage_for / errors ──────────────────────────────────────────────────────

def test_stage_for_maps_core_messages():
    assert stage_for("Deriving 512-bit password key (Argon2id)...")[:2] == ("kdf", "Securing password")
    assert stage_for("Encrypting Kyber private key...")[0] == "lock"
    assert stage_for("Generating Kyber-768 keypair...")[0] == "kem"
    assert stage_for("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")[0] == "kem"
    s, _, pct = stage_for("Encrypting payload (AES-256-GCM)... 47%")
    assert s == "payload" and pct == 0.47
    assert stage_for("Compressing folder… 100% (3/3 files)") == ("compress", "Compressing folder", 1.0)
    assert stage_for("Decrypting payload... 12%")[1] == "Decrypting file"
    s, label, pct = stage_for("Something new")
    assert s == "work" and label == "Something new" and pct is None
    assert stage_for("x 250%")[2] == 1.0


def test_classify_error_codes():
    from cryptography.exceptions import InvalidTag
    assert classify_error(InvalidTag())[0] == "wrong_credentials"
    assert classify_error(cc.CancelledOperation("x"))[0] == "cancelled"
    assert classify_error(FileNotFoundError("nope"))[0] == "not_found"
    assert classify_error(PermissionError("denied"))[0] == "permission_denied"
    assert classify_error(OSError(5, "io error"))[0] == "io"
    assert classify_error(ValueError("File appears truncated"))[0] == "format"
    assert classify_error(ValueError("created with a newer version"))[0] == "unsupported"
    assert classify_error(RuntimeError("Volume already mounted at /x"))[0] == "busy"
    assert classify_error(RuntimeError("fuse backend missing"))[0] == "unsupported"
    assert classify_error(KeyError("boom"))[0] == "internal"
    code, message, detail = classify_error(ValueError(""))
    assert detail == "ValueError" and "ValueError" in message
    assert friendly_error(IsADirectoryError()) == "That path is a folder, not a file."
    import errno
    assert "full" in friendly_error(OSError(errno.ENOSPC, "x"))
    assert "failing" in friendly_error(OSError(errno.EIO, "x"))
    assert "read-only" in friendly_error(OSError(errno.EROFS, "x"))
    assert "older" in friendly_error(ValueError("older format version"))
    assert "integrity" in friendly_error(ValueError("HMAC mismatch"))


# ── Request framing ─────────────────────────────────────────────────────────

def test_invalid_json_and_shape(h):
    h.raw("{not json")
    h.raw(json.dumps({"id": "a", "params": {}}))
    h.raw(json.dumps(["list"]))
    h.raw(json.dumps({"id": "b", "op": "inspect", "params": "nope"}))
    h.raw(json.dumps({"id": "c", "op": "does_not_exist"}))
    h.raw("   \n")
    evs = h.events()
    codes = [e["code"] for e in evs]
    assert codes == ["invalid_request"] * 5
    assert evs[0]["id"] is None
    assert evs[1]["id"] == "a"
    assert evs[3]["id"] == "b"
    assert "does_not_exist" in evs[4]["message"]


def test_ping_version_and_auto_ids(h):
    h.send("ping", rid="p")
    assert h.result("p") == {}
    h.raw(json.dumps({"op": "version"}))
    evs = h.events()
    ver = [e for e in evs if e["event"] == "done" and "version" in e["result"]][0]
    assert ver["id"].startswith("auto-")
    assert ver["result"]["format_version"] == cc.MAX_FORMAT_VERSION
    assert ver["result"]["platform"] == sys.platform


def test_duplicate_running_id_rejected(h):
    stop = threading.Event()

    def sleepy(params, ctx):
        stop.wait(5)
        return {"ok": True}

    h.svc.ops["sleepy"] = sleepy
    h.send("sleepy", rid="same")
    h.send("sleepy", rid="same")
    time.sleep(0.05)
    dup = [e for e in json.loads("[" + ",".join(h.out.getvalue().splitlines()) + "]")
           if e.get("event") == "error"]
    assert dup and "already running" in dup[0]["message"]
    stop.set()
    assert h.result("same") == {"ok": True}


def test_cancel_flow(h):
    stop = threading.Event()

    def sleepy(params, ctx):
        while not ctx.cancelled():
            time.sleep(0.01)
        stop.set()
        return {"finished": True}

    h.svc.ops["sleepy"] = sleepy
    h.send("sleepy", rid="job")
    h.send("cancel", {"target": "job"}, rid="c1")
    assert h.result("c1") == {"cancelled": True}
    assert stop.wait(2)
    # Handler returned normally but the token was set → reported as cancelled
    assert h.error("job")["code"] == "cancelled"
    h.send("cancel", {"target": "ghost"}, rid="c2")
    assert h.result("c2") == {"cancelled": False}


def test_ctx_check_raises_when_cancelled(h):
    def checker(params, ctx):
        ctx.progress("Reading volume...")
        h.svc._reqs["k"].cancelled.set()
        ctx.check()
        return {}

    h.svc.ops["checker"] = checker
    h.send("checker", rid="k")
    evs = h.events("k")
    assert evs[0]["event"] == "progress" and evs[0]["stage"] == "read"
    assert evs[-1]["code"] == "cancelled"


def test_missing_params_reported_as_format_error(h):
    h.send("inspect", {}, rid="i")
    err = h.error("i")
    assert err["code"] == "format" and "path" in err["message"]
    h.send("encrypt", {"source": "x"}, rid="e")
    assert "output" in h.error("e")["message"]
    h.send("decrypt", {"path": "x"}, rid="d")
    assert "output_dir" in h.error("d")["message"]


# ── Encrypt / decrypt round trips ───────────────────────────────────────────

def test_password_round_trip_with_progress(h, src_file, out_dir, tmp_path):
    out = str(tmp_path / "notes.qcx")
    h.send("encrypt", {"source": src_file, "output": out, "mode": "password",
                       "password": "correct horse"}, rid="enc")
    res = h.result("enc")
    assert res["output"] == out and res["mode"] == "single" and res["shares"] == []
    assert res["filename"] == "notes.txt" and os.path.exists(out)
    assert not os.path.exists(out + ".tmp")
    stages = {e["stage"] for e in h.events("enc") if e["event"] == "progress"}
    assert {"kdf", "kem", "payload", "write"} <= stages

    h.send("inspect", {"path": out}, rid="ins")
    info = h.result("ins")
    assert info["mode"] == "single" and info["argon2"] and not info["embedded"]

    h.send("decrypt", {"path": out, "output_dir": out_dir, "password": "correct horse"}, rid="dec")
    d = h.result("dec")
    assert d["filename"] == "notes.txt" and d["renamed"] is False
    assert open(d["output"], "rb").read() == open(src_file, "rb").read()
    assert d["size"] == d["original_size"]

    # Second decrypt must not overwrite: report_2 naming
    h.send("decrypt", {"path": out, "output_dir": out_dir, "password": "correct horse"}, rid="dec2")
    d2 = h.result("dec2")
    assert d2["renamed"] is True and d2["output"].endswith("notes_2.txt")


def test_wrong_password_and_verify_only(h, src_file, tmp_path):
    out = str(tmp_path / "n.qcx")
    h.send("encrypt", {"source": src_file, "output": out, "mode": "single", "password": "pw"}, rid="e")
    h.result("e")
    h.send("decrypt", {"path": out, "output_dir": str(tmp_path), "password": "nope"}, rid="bad")
    err = h.error("bad")
    assert err["code"] == "wrong_credentials"
    assert "incorrect" in err["message"]
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".qc-decrypt-")]
    h.send("decrypt", {"path": out, "password": "pw", "verify_only": True}, rid="v")
    assert h.result("v") == {"verified": True, "mode": "single"}
    h.send("decrypt", {"path": out, "password": "nope", "verify_only": True}, rid="v2")
    assert h.error("v2")["code"] == "wrong_credentials"


def test_shamir_round_trip_codes_and_mnemonics(h, src_file, out_dir, tmp_path):
    out = str(tmp_path / "s.qcx")
    h.send("encrypt", {"source": src_file, "output": out, "mode": "shamir", "k": 2, "n": 3}, rid="e")
    res = h.result("e")
    assert res["threshold"] == 2 and res["total"] == 3 and len(res["shares"]) == 3
    assert res["shares"][0]["code"].startswith("QCSHARE-")
    assert len(res["shares"][0]["mnemonic"].split()) == cc.MNEMONIC_WORDS_PER_SHARE

    # codes, with a duplicate and a blank thrown in
    codes = [res["shares"][0]["code"], "", res["shares"][0]["code"], res["shares"][2]["code"]]
    h.send("decrypt", {"path": out, "output_dir": out_dir, "shares": codes}, rid="d1")
    assert open(h.result("d1")["output"], "rb").read() == open(src_file, "rb").read()

    # mnemonics
    mn = [res["shares"][1]["mnemonic"], res["shares"][2]["mnemonic"]]
    h.send("decrypt", {"path": out, "password": None, "shares": mn, "verify_only": True}, rid="d2")
    assert h.result("d2")["verified"] is True

    # too few distinct shares
    h.send("decrypt", {"path": out, "output_dir": out_dir,
                       "shares": [codes[0], codes[0]]}, rid="d3")
    err = h.error("d3")
    assert err["code"] == "format" and "Need 2" in err["message"]

    # unreadable share names its position
    h.send("decrypt", {"path": out, "output_dir": out_dir,
                       "shares": [codes[0], "QCSHARE-garbage"]}, rid="d4")
    assert "Share 2" in h.error("d4")["message"]


def test_folder_round_trip_and_guards(h, tmp_path, out_dir):
    folder = tmp_path / "docs"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_text("alpha")
    (folder / "sub" / "b.txt").write_text("beta")
    out = str(tmp_path / "docs.qcx")
    h.send("encrypt", {"source": str(folder), "output": out, "mode": "password", "password": "p"}, rid="e")
    res = h.result("e")
    assert res["filename"] == "docs.zip"
    assert not [f for f in os.listdir(tmp_path) if "qc-staging" in f]
    assert any(e["stage"] == "compress" for e in h.events("e") if e["event"] == "progress")

    h.send("decrypt", {"path": out, "output_dir": out_dir, "password": "p"}, rid="d")
    zpath = h.result("d")["output"]
    import zipfile
    with zipfile.ZipFile(zpath) as zf:
        assert sorted(zf.namelist()) == ["docs/a.txt", "docs/sub/b.txt"]

    # output inside the source folder is refused
    h.send("encrypt", {"source": str(folder), "output": str(folder / "x.qcx"),
                       "mode": "password", "password": "p"}, rid="bad")
    assert "inside" in h.error("bad")["message"]


def test_encrypt_param_validation_and_missing_source(h, src_file, tmp_path):
    out = str(tmp_path / "x.qcx")
    h.send("encrypt", {"source": src_file, "output": out, "mode": "weird", "password": "p"}, rid="m")
    assert "Unknown mode" in h.error("m")["message"]
    h.send("encrypt", {"source": src_file, "output": out, "mode": "password"}, rid="np")
    assert "password" in h.error("np")["message"]
    h.send("encrypt", {"source": src_file, "output": out, "mode": "shamir", "k": 5, "n": 3}, rid="kn")
    assert "2 <= k <= n" in h.error("kn")["message"]
    h.send("encrypt", {"source": str(tmp_path / "missing"), "output": out,
                       "mode": "password", "password": "p"}, rid="nf")
    assert h.error("nf")["code"] == "not_found"
    assert not os.path.exists(out) and not os.path.exists(out + ".tmp")


def test_encrypt_cancel_leaves_no_tmp(h, tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(6 * 1024 * 1024))
    out = str(tmp_path / "big.qcx")
    h.send("encrypt", {"source": str(big), "output": out, "mode": "password", "password": "p"}, rid="e")
    h.send("cancel", {"target": "e"}, rid="c")
    ev = h.final("e")
    assert ev["event"] == "error" and ev["code"] == "cancelled"
    assert not os.path.exists(out + ".tmp") and not os.path.exists(out)


def test_embed_binary_and_decrypt_to_bad_dir(h, src_file, tmp_path):
    fake_bin = tmp_path / "decryptor.bin"
    fake_bin.write_bytes(b"#!/bin/sh\necho hi\n" + os.urandom(2048))
    out = str(tmp_path / "e.qcx")
    h.send("encrypt", {"source": src_file, "output": out, "mode": "password", "password": "p",
                       "embed_binary": str(fake_bin)}, rid="e")
    h.result("e")
    assert os.stat(out).st_mode & 0o100
    h.send("inspect", {"path": out}, rid="i")
    assert h.result("i")["embedded"] is True
    h.send("decrypt", {"path": out, "output_dir": str(tmp_path / "nope"), "password": "p"}, rid="d")
    assert h.error("d")["code"] == "io"


# ── package helpers ─────────────────────────────────────────────────────────

def test_safe_output_name_and_batch_paths(tmp_path):
    assert pkg.safe_output_name("../../etc/passwd") == "passwd"
    assert pkg.safe_output_name("bad\x00name\n.txt") == "badname.txt"
    assert pkg.safe_output_name("...") == "decrypted"
    assert pkg.safe_output_name(None) == "decrypted"
    outs = pkg.batch_output_paths(["/a/report.txt", "/b/report.md", "/c/other.bin"], "/o")
    assert [os.path.basename(o) for o in outs] == ["report.qcx", "report_2.qcx", "other.qcx"]
    (tmp_path / "f.txt").write_text("x")
    p, renamed = pkg.unique_path(str(tmp_path), "f.txt")
    assert renamed and p.endswith("f_2.txt")


def test_derive_final_key_requires_password(src_file, tmp_path):
    out = str(tmp_path / "k.qcx")
    pkg.encrypt_to_qcx(src_file, out, mode="password", password="p")
    meta = pkg.load_pkg(out)["meta"]
    with pytest.raises(ValueError, match="password"):
        pkg.derive_final_key(meta)
    with pytest.raises(cc.CancelledOperation):
        pkg.derive_final_key(meta, password="p", cancel_check=lambda: True)


def test_verify_first_chunk_detects_corruption(src_file, tmp_path):
    out = str(tmp_path / "c.qcx")
    pkg.encrypt_to_qcx(src_file, out, mode="password", password="p")
    meta = pkg.load_pkg(out)["meta"]
    key, _ = pkg.derive_final_key(meta, password="p")
    pkg.verify_first_chunk(out, meta, key)
    # Corrupt the sequence number of chunk 0
    with open(out, "r+b") as f:
        f.seek(meta.get("payload_offset", 0))
        f.write(b"\x00\x00\x00\x09")
    with pytest.raises(ValueError, match="sequence"):
        pkg.verify_first_chunk(out, meta, key)
    # Implausible chunk length
    with open(out, "r+b") as f:
        f.seek(meta.get("payload_offset", 0))
        f.write(b"\x00\x00\x00\x00\xff\xff\xff\xff")
    with pytest.raises(ValueError, match="implausible"):
        pkg.verify_first_chunk(out, meta, key)
    # Truncated
    with open(out, "r+b") as f:
        f.truncate(meta.get("payload_offset", 0) + 2)
    with pytest.raises(ValueError, match="truncated"):
        pkg.verify_first_chunk(out, meta, key)


def test_load_pkg_rejections(tmp_path):
    p = tmp_path / "x.qcx"
    p.write_bytes(b"nothing here")
    with pytest.raises(ValueError, match="Not a QuantaCrypt"):
        pkg.load_pkg(str(p))
    p.write_bytes(cc.MAGIC + b"\x00\x00\x00\x99")
    with pytest.raises(ValueError, match="truncated"):
        pkg.load_pkg(str(p))
    for blob, msg in [
        (b"[1]", "envelope"),
        (json.dumps({"meta": 3}).encode(), "not a valid dictionary"),
        (json.dumps({"meta": {"mode": "single", "version": 99}}).encode(), "newer"),
        (json.dumps({"meta": {"mode": "single", "version": 0}}).encode(), "older"),
        (json.dumps({"meta": {}}).encode(), "'mode'"),
        (json.dumps({"meta": {"mode": "x"}}).encode(), "Unknown encryption mode"),
        (json.dumps({"meta": {"mode": "shamir", "threshold": 2}}).encode(), "'total'"),
        (json.dumps({"meta": {"mode": "shamir", "threshold": 9, "total": 2}}).encode(), "Invalid Shamir"),
    ]:
        p.write_bytes(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        with pytest.raises(ValueError, match=msg):
            pkg.load_pkg(str(p))
    with pytest.raises(ValueError, match="truncated"):
        p.write_bytes(cc.MAGIC + b"\x00")
        pkg.load_pkg(str(p))


def test_zip_folder_cancel_and_stats(tmp_path):
    folder = tmp_path / "f"
    folder.mkdir()
    (folder / "a").write_bytes(b"12345")
    (folder / "b").write_bytes(b"12")
    assert pkg.folder_stats(str(folder)) == (2, 7)
    with pytest.raises(cc.CancelledOperation):
        pkg.zip_folder(str(folder), str(tmp_path / "z.zip"), cancel_check=lambda: True)


# ── Volumes (FUSE mocked) ───────────────────────────────────────────────────

class _FakeVol:
    def __init__(self, suspicious=False, boom=False):
        self.journal_suspicious = suspicious
        self._boom = boom

    def stat(self):
        if self._boom:
            raise RuntimeError("no stats")
        return {"file_count": 1, "container_size": 4096}


class _FakeFuse:
    def __init__(self, vol):
        self.volume = vol


def test_volume_create_mount_list_unmount(h, tmp_path, monkeypatch):
    import quantacrypt.core.fuse_ops as fo
    mounted = {}

    def fake_mount(path, key, mp):
        assert isinstance(key, bytes) and len(key) == cc.KEY_BYTES
        mounted[mp] = {"volume_path": path, "volume": _FakeVol(suspicious=(mp.endswith("sus")))}
        return _FakeFuse(mounted[mp]["volume"])

    monkeypatch.setattr(fo, "mount_volume", fake_mount)
    monkeypatch.setattr(fo, "get_mounted_volumes", lambda: dict(mounted))
    monkeypatch.setattr(fo, "unmount_volume", lambda mp: mounted.pop(mp))

    vpath = str(tmp_path / "vault")  # extension appended
    h.send("volume_create", {"path": vpath, "mode": "password", "password": "pw"}, rid="c")
    res = h.result("c")
    assert res["path"].endswith("vault.qcv") and os.path.exists(res["path"])
    h.send("volume_create", {"path": res["path"], "mode": "password", "password": "pw"}, rid="c2")
    assert h.error("c2")["code"] == "io"
    h.send("volume_create", {"path": str(tmp_path / "s.qcv"), "mode": "shamir", "k": 3, "n": 2}, rid="c3")
    assert "2 <= k <= n" in h.error("c3")["message"]
    h.send("volume_create", {"path": str(tmp_path / "s.qcv"), "mode": "shamir", "k": 2, "n": 3}, rid="c4")
    sres = h.result("c4")
    assert len(sres["shares"]) == 3 and sres["threshold"] == 2

    h.send("volume_inspect", {"path": res["path"]}, rid="vi")
    vi = h.result("vi")
    assert vi["mode"] == "single" and vi["size"] > 0 and vi["threshold"] is None
    h.send("volume_inspect", {"path": sres["path"]}, rid="vi2")
    vi2 = h.result("vi2")
    assert vi2["mode"] == "shamir" and (vi2["threshold"], vi2["total"]) == (2, 3)
    h.send("volume_inspect", {"path": str(tmp_path / "nope.qcv")}, rid="vi3")
    assert h.error("vi3")["code"] == "not_found"

    mp = str(tmp_path / "mnt")
    h.send("volume_mount", {"path": res["path"], "mount_point": mp, "password": "pw"}, rid="m")
    mres = h.result("m")
    assert mres == {"mount_point": mp, "volume_path": res["path"], "journal_suspicious": False}
    stages = [e["stage"] for e in h.events("m") if e["event"] == "progress"]
    assert stages[0] == "read" and "kdf" in stages and stages[-1] == "mount"

    h.send("volume_mount", {"path": res["path"], "mount_point": mp + "2", "password": "wrong"}, rid="mw")
    assert h.error("mw")["code"] == "wrong_credentials"

    sh = [s["mnemonic"] for s in sres["shares"][:2]]
    h.send("volume_mount", {"path": sres["path"], "mount_point": mp + "sus", "shares": sh}, rid="ms")
    assert h.result("ms")["journal_suspicious"] is True
    h.send("volume_mount", {"path": sres["path"], "mount_point": mp + "3",
                            "shares": [sres["shares"][0]["code"]]}, rid="mf")
    assert "Need 2" in h.error("mf")["message"]

    h.send("volume_list", rid="l")
    vols = h.result("l")["volumes"]
    assert {v["mount_point"] for v in vols} == {mp, mp + "sus"}
    assert vols[0]["stats"]["file_count"] == 1

    h.send("volume_unmount", {"mount_point": mp}, rid="u")
    assert h.result("u") == {"mount_point": mp}
    assert mp not in mounted

    # shutdown unmounts what is left and calls exit_fn
    h.send("shutdown", rid="s")
    assert h.result("s") == {}
    assert mounted == {} and h.exited.is_set()


def test_volume_list_stats_failure_and_no_fuse(h, monkeypatch):
    import quantacrypt.core.fuse_ops as fo
    monkeypatch.setattr(fo, "get_mounted_volumes",
                        lambda: {"/m": {"volume_path": "/v.qcv", "volume": _FakeVol(boom=True)}})
    h.send("volume_list", rid="l")
    assert h.result("l")["volumes"][0]["stats"] is None

    def broken():
        raise ImportError("no fusepy")

    monkeypatch.setattr(fo, "get_mounted_volumes", broken)
    h.send("volume_list", rid="l2")
    assert h.result("l2") == {"volumes": []}
    monkeypatch.setattr(fo, "unmount_volume", lambda mp: (_ for _ in ()).throw(RuntimeError("busy")))
    h.svc.shutdown()  # must not raise even when unmount fails
    assert h.exited.is_set()


def test_fuse_check(h, monkeypatch):
    import quantacrypt.core.fuse_ops as fo
    monkeypatch.setattr(fo, "check_fuse_components", lambda: {
        "fusepy": {"ok": True, "detail": "x"}, "fuse_backend": {"ok": False, "detail": "y"}})
    h.send("fuse_check", rid="f")
    res = h.result("f")
    assert res["ok"] is False and res["fusepy"]["ok"]

    def broken():
        raise RuntimeError("no")

    monkeypatch.setattr(fo, "check_fuse_components", broken)
    h.send("fuse_check", rid="f2")
    assert h.result("f2")["fusepy"]["detail"] == "no"


# ── CLI ─────────────────────────────────────────────────────────────────────

def test_cli_version_and_stdio_session(tmp_path):
    from quantacrypt.cli import main
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert main(["--version"]) == 0
    from quantacrypt import __version__
    assert buf.getvalue().strip() == __version__

    script = "\n".join([
        json.dumps({"id": "1", "op": "ping"}),
        json.dumps({"id": "2", "op": "version"}),
        json.dumps({"id": "3", "op": "shutdown"}),
    ]) + "\n"
    proc = subprocess.run([sys.executable, "-m", "quantacrypt.cli"], input=script,
                          capture_output=True, text=True, timeout=60)
    diag = f"rc={proc.returncode}\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    assert proc.returncode == 0, diag
    lines = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    assert [l["id"] for l in lines] == ["1", "2", "3"], diag
    assert lines[1]["result"]["version"] == __version__, diag


def test_run_loop_stops_at_eof(monkeypatch):
    out = io.StringIO()
    exited = []
    s = Service(io.StringIO(json.dumps({"id": "x", "op": "ping"}) + "\n"), out,
                exit_fn=lambda: exited.append(True))
    s.run()
    assert json.loads(out.getvalue().splitlines()[0])["id"] == "x"
    assert exited == [True]


def test_eof_lets_inflight_work_finish():
    out = io.StringIO()
    exited = []
    s = Service(io.StringIO(json.dumps({"id": "slow", "op": "slow"}) + "\n"), out,
                exit_fn=lambda: exited.append(True))

    def slow(params, ctx):
        time.sleep(0.2)
        return {"finished": True, "cancelled": ctx.cancelled()}

    s.ops["slow"] = slow
    s.run()
    ev = json.loads(out.getvalue().splitlines()[-1])
    assert ev["event"] == "done" and ev["result"] == {"finished": True, "cancelled": False}
    assert exited == [True]
