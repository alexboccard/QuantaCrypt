"""Tests for the qc-core JSON-lines service and the core.package helpers."""

import io
import json
import os
import secrets
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
    assert classify_error(RuntimeError("No FUSE backend found (macFUSE or FUSE-T)"))[0] == "unsupported"
    assert classify_error(RuntimeError("Volume appears to be mounted by another process"))[0] == "busy"
    assert classify_error(RuntimeError("FUSE mount failed: mount point does not exist"))[0] == "io"
    from quantacrypt.core.errors import InvalidRequest
    assert classify_error(InvalidRequest("Missing parameter(s): path"))[0] == "invalid_request"
    code, msg, _ = classify_error(FileExistsError(17, "exists", "/v/x.qcv"))
    assert code == "already_exists" and msg.startswith("/v/x.qcv already exists")
    code, msg, _ = classify_error(KeyError("payload_nonce"))
    assert code == "format" and "payload_nonce" in msg and "corrupt" in msg
    assert classify_error(TypeError("boom"))[0] == "internal"
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
    # The handler saw the token but chose to finish: its output exists, so
    # it is reported as done — "cancelled" must mean "nothing was written".
    assert h.result("job") == {"finished": True}
    h.send("cancel", {"target": "ghost"}, rid="c2")
    assert h.result("c2") == {"cancelled": False}

    def bails(params, ctx):
        while not ctx.cancelled():
            time.sleep(0.01)
        ctx.check()  # raises CancelledOperation → nothing written
        return {}

    h.svc.ops["bails"] = bails
    h.send("bails", rid="job2")
    h.send("cancel", {"target": "job2"}, rid="c3")
    assert h.error("job2")["code"] == "cancelled"


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
    assert err["code"] == "invalid_request" and "path" in err["message"]
    h.send("inspect", {"path": 42}, rid="i2")
    assert h.error("i2")["code"] == "invalid_request"
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
    assert err["code"] == "invalid_input" and "Need 2" in err["message"]

    # unreadable share names its position
    h.send("decrypt", {"path": out, "output_dir": out_dir,
                       "shares": [codes[0], "QCSHARE-garbage"]}, rid="d4")
    d4 = h.error("d4")
    assert d4["code"] == "invalid_input" and "Share 2" in d4["message"]


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
    assert h.error("np")["code"] == "invalid_request"  # client omitted a required param
    h.send("encrypt", {"source": src_file, "output": out, "mode": "shamir", "k": 5, "n": 3}, rid="kn")
    assert "2 <= k <= n" in h.error("kn")["message"]
    h.send("encrypt", {"source": src_file, "output": out, "mode": "shamir", "k": 2.5, "n": 3}, rid="kf")
    assert h.error("kf")["code"] == "invalid_request"
    h.send("encrypt", {"source": src_file, "output": out, "mode": "password", "password": ["x"]}, rid="pt")
    assert h.error("pt")["code"] == "invalid_request"
    h.send("encrypt", {"source": str(tmp_path / "missing"), "output": out,
                       "mode": "password", "password": "p"}, rid="nf")
    assert h.error("nf")["code"] == "not_found"
    assert not os.path.exists(out) and not os.path.exists(out + ".tmp")


def test_encrypt_cancel_leaves_no_tmp(h, tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(secrets.token_bytes(6 * 1024 * 1024))
    out = str(tmp_path / "big.qcx")
    h.send("encrypt", {"source": str(big), "output": out, "mode": "password", "password": "p"}, rid="e")
    h.send("cancel", {"target": "e"}, rid="c")
    ev = h.final("e")
    assert ev["event"] == "error" and ev["code"] == "cancelled"
    assert not os.path.exists(out + ".tmp") and not os.path.exists(out)


def test_embed_binary_and_decrypt_to_bad_dir(h, src_file, tmp_path):
    fake_bin = tmp_path / "decryptor.bin"
    fake_bin.write_bytes(b"#!/bin/sh\necho hi\n" + secrets.token_bytes(2048))
    out = str(tmp_path / "e.qcx")
    h.send("encrypt", {"source": src_file, "output": out, "mode": "password", "password": "p",
                       "embed_binary": str(fake_bin)}, rid="e")
    h.result("e")
    assert os.stat(out).st_mode & 0o100
    h.send("inspect", {"path": out}, rid="i")
    assert h.result("i")["embedded"] is True
    h.send("decrypt", {"path": out, "output_dir": str(tmp_path / "nope"), "password": "p"}, rid="d")
    err = h.error("d")
    assert err["code"] == "invalid_input" and "doesn't exist" in err["message"]


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
    c2 = h.error("c2")
    assert c2["code"] == "already_exists" and "already exists" in c2["message"]
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

    # shutdown unmounts what is left BEFORE acknowledging, and reports failures
    monkeypatch.setattr(fo, "unmount_volume",
                        lambda mp: (_ for _ in ()).throw(RuntimeError("busy")) if mp.endswith("sus") else mounted.pop(mp))
    h.send("shutdown", rid="s")
    assert h.result("s") == {"unmount_failed": [mp + "sus"]}
    assert not h.exited.is_set()  # exit is run()'s job, after the ack is flushed


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
    assert lines[2]["result"] == {"unmount_failed": []}, diag


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


def test_shutdown_op_exits_loop_without_eof():
    """The shutdown op must end run() even when the client keeps stdin open."""
    r, w = os.pipe()
    reader = os.fdopen(r, "r")
    writer = os.fdopen(w, "w")
    out = io.StringIO()
    exited = []
    s = Service(reader, out, exit_fn=lambda: exited.append(True))
    t = threading.Thread(target=s.run, daemon=True)
    t.start()
    writer.write(json.dumps({"id": "s", "op": "shutdown"}) + "\n"); writer.flush()
    t.join(5)
    assert not t.is_alive(), "run() did not return after shutdown with stdin still open"
    assert exited == [True]
    assert json.loads(out.getvalue().splitlines()[-1]) == {"id": "s", "event": "done",
                                                            "result": {"unmount_failed": []}}
    writer.close()


def test_shutdown_is_idempotent(h):
    assert h.svc.shutdown(exit_after=False) == []
    assert h.svc.shutdown(exit_after=False) == []
    h.svc.shutdown()  # third call: guard returns before exit_fn
    assert not h.exited.is_set()


def test_sigterm_stops_helper_cleanly(tmp_path):
    """SIGTERM mid-request: the handler must not tear down inside the signal
    handler; the loop unwinds and the process exits 0 with no .tmp left."""
    import signal
    big = tmp_path / "big.bin"
    big.write_bytes(secrets.token_bytes(8 * 1024 * 1024))
    out = str(tmp_path / "big.qcx")
    proc = subprocess.Popen([sys.executable, "-m", "quantacrypt.cli"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    proc.stdin.write(json.dumps({"id": "e", "op": "encrypt", "params": {
        "source": str(big), "output": out, "mode": "password", "password": "p"}}) + "\n")
    proc.stdin.flush()
    # Deterministic: wait for the first progress event, which proves the
    # handler is installed and the encrypt is in flight, then signal.
    first = json.loads(proc.stdout.readline())
    assert first["event"] == "progress", first
    proc.send_signal(signal.SIGTERM)
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("helper did not exit after SIGTERM")
    assert proc.returncode == 0, stderr
    assert not os.path.exists(out + ".tmp")
    evs = [json.loads(l) for l in stdout.splitlines() if l.strip()]
    terminal = [e for e in evs if e["event"] in ("error", "done")]
    assert terminal, "the in-flight request got no terminal event"
    assert terminal[-1]["event"] == "error" and terminal[-1]["code"] == "cancelled"
    assert not os.path.exists(out)


def test_verify_only_on_empty_payload(h, tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    out = str(tmp_path / "empty.qcx")
    h.send("encrypt", {"source": str(empty), "output": out, "mode": "password", "password": "p"}, rid="e")
    h.result("e")
    h.send("decrypt", {"path": out, "password": "p", "verify_only": True}, rid="v")
    assert h.result("v") == {"verified": True, "mode": "single"}
    h.send("decrypt", {"path": out, "password": "wrong", "verify_only": True}, rid="w")
    assert h.error("w")["code"] == "wrong_credentials"


def test_volume_create_cancel_removes_partial_file(h, tmp_path, monkeypatch):
    import quantacrypt.core.volume as vol
    path = str(tmp_path / "half.qcv")

    def fake_create(p, pw, progress_cb=None, cancel_check=None):
        open(p, "wb").write(b"partial")
        raise cc.CancelledOperation("Volume creation cancelled")

    monkeypatch.setattr(vol, "create_volume_single", fake_create)
    h.send("volume_create", {"path": path, "mode": "password", "password": "pw"}, rid="c")
    assert h.error("c")["code"] == "cancelled"
    assert not os.path.exists(path)


def test_create_volume_polls_cancel(tmp_path):
    from quantacrypt.core import volume as vol
    with pytest.raises(cc.CancelledOperation):
        vol.create_volume_single(str(tmp_path / "x.qcv"), "pw", cancel_check=lambda: True)
    assert not os.path.exists(tmp_path / "x.qcv")
    with pytest.raises(cc.CancelledOperation):
        vol.create_volume_shamir(str(tmp_path / "y.qcv"), 3, 2, cancel_check=lambda: True)


# ── Coverage for the lifecycle and validation branches ──────────────────────

def test_request_stop_unblocks_run_and_cancels_workers():
    r, w = os.pipe()
    reader = os.fdopen(r, "r")
    writer = os.fdopen(w, "w")
    out = io.StringIO()
    exited = []
    s = Service(reader, out, exit_fn=lambda: exited.append(True))
    seen = threading.Event()

    def sleepy(params, ctx):
        seen.set()
        while not ctx.cancelled():
            time.sleep(0.01)
        ctx.check()
        return {}

    s.ops["sleepy"] = sleepy
    t = threading.Thread(target=s.run, daemon=True)
    t.start()
    writer.write(json.dumps({"id": "j", "op": "sleepy"}) + "\n"); writer.flush()
    assert seen.wait(2)
    s.request_stop()          # what the SIGTERM handler does before raising
    writer.write("\n"); writer.flush()   # wake the blocked read (cross-thread)
    t.join(5)
    assert not t.is_alive() and exited == [True]
    evs = [json.loads(l) for l in out.getvalue().splitlines()]
    assert evs[-1]["id"] == "j" and evs[-1]["code"] == "cancelled"
    writer.close()


def test_optional_param_types_and_unknown_volume_mode(h, tmp_path, src_file):
    h.send("decrypt", {"path": src_file, "output_dir": 3, "password": "x"}, rid="od")
    assert h.error("od")["code"] == "invalid_request"
    h.send("decrypt", {"path": src_file, "output_dir": str(tmp_path), "shares": "not-a-list"}, rid="sl")
    assert h.error("sl")["code"] == "invalid_request"
    h.send("volume_create", {"path": str(tmp_path / "v.qcv"), "mode": "weird", "password": "p"}, rid="vm")
    assert h.error("vm")["code"] == "invalid_request"
    h.send("volume_create", {"path": str(tmp_path / "v2.qcv"), "mode": "password"}, rid="np")
    assert h.error("np")["code"] == "invalid_request"


def test_package_validation_and_cleanup(tmp_path, src_file):
    from quantacrypt.core.errors import InvalidRequest
    out = str(tmp_path / "o.qcx")
    with pytest.raises(InvalidRequest):
        pkg.encrypt_to_qcx(src_file, out, mode="nope", password="p")
    with pytest.raises(InvalidRequest):
        pkg.encrypt_to_qcx(src_file, out, mode="shamir", k=1, n=1)
    # Failure after the tmp file exists removes it (embed source unreadable)
    with pytest.raises(FileNotFoundError):
        pkg.encrypt_to_qcx(src_file, out, mode="password", password="p",
                           embed_binary=str(tmp_path / "missing.bin"))
    assert not os.path.exists(out + ".tmp") and not os.path.exists(out)
    # chmod failure on the embed path is tolerated
    fake_bin = tmp_path / "bin"; fake_bin.write_bytes(b"x" * 10)
    import quantacrypt.core.package as pmod
    real_chmod = os.chmod
    pmod.os.chmod = lambda *a, **k: (_ for _ in ()).throw(OSError("ro"))
    try:
        res = pkg.encrypt_to_qcx(src_file, out, mode="password", password="p",
                                 embed_binary=str(fake_bin))
    finally:
        pmod.os.chmod = real_chmod
    assert os.path.exists(res["output"])
    # decrypt failure after the tmp file exists removes it (wrong password
    # is caught before; force a failure inside the stream by truncating)
    with open(out, "r+b") as f:
        f.truncate(os.path.getsize(out) - 200)
    with pytest.raises(Exception):
        pkg.decrypt_qcx(out, str(tmp_path), password="p")
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".qc-decrypt-")]


def test_folder_stats_tolerates_vanishing_files(tmp_path, monkeypatch):
    d = tmp_path / "f"; d.mkdir(); (d / "a").write_bytes(b"12")
    import quantacrypt.core.package as pmod
    monkeypatch.setattr(pmod.os.path, "getsize", lambda p: (_ for _ in ()).throw(OSError("gone")))
    assert pkg.folder_stats(str(d)) == (1, 0)


def test_zip_folder_skips_its_own_archive(tmp_path):
    d = tmp_path / "f"; d.mkdir(); (d / "a").write_bytes(b"12")
    dst = d / "inner.zip"   # archive inside the tree being zipped
    pkg.zip_folder(str(d), str(dst), progress_cb=lambda m: None)
    import zipfile
    with zipfile.ZipFile(dst) as zf:
        assert zf.namelist() == ["f/a"]


def test_verify_first_chunk_truncated_length_field(src_file, tmp_path):
    out = str(tmp_path / "t.qcx")
    pkg.encrypt_to_qcx(src_file, out, mode="password", password="p")
    meta = pkg.load_pkg(out)["meta"]
    key, _ = pkg.derive_final_key(meta, password="p")
    with open(out, "r+b") as f:
        f.truncate(meta.get("payload_offset", 0) + 6)
    with pytest.raises(ValueError, match="truncated"):
        pkg.verify_first_chunk(out, meta, key)


def test_friendly_error_newer_version():
    assert "newer version" in friendly_error(ValueError("unsupported format version 9"))


def test_extract_share_codes_tolerates_headers_and_prose(src_file, tmp_path):
    out = str(tmp_path / "s.qcx")
    res = pkg.encrypt_to_qcx(src_file, out, mode="shamir", k=2, n=3)
    sh = res["shares"]
    text = (f"QuantaCrypt share file for notes.txt\nShare 1 of 3:\n{sh[0]['code']}\n\n"
            f"Share 2 of 3 (50-word phrase):\n{sh[1]['mnemonic']}\n\nKeep this safe.\n"
            f"{sh[0]['code']}\n")  # duplicate collapses
    codes = pkg.extract_share_codes(text)
    assert codes == [sh[0]["code"], sh[1]["code"]]
    assert pkg.extract_share_codes("nothing here") == []
    # A mnemonic wrapped across lines still counts
    words = sh[2]["mnemonic"].split()
    wrapped = "\n".join(" ".join(words[i:i + 7]) for i in range(0, 50, 7))
    assert pkg.extract_share_codes("Share 3:\n" + wrapped) == [sh[2]["code"]]


def test_corrupt_payload_is_not_a_wrong_password(h, src_file, tmp_path, out_dir):
    out = str(tmp_path / "c.qcx")
    pkg.encrypt_to_qcx(src_file, out, mode="password", password="p")
    meta = pkg.load_pkg(out)["meta"]
    off = meta.get("payload_offset", 0) + 8 + 5  # inside chunk 0's ciphertext
    with open(out, "r+b") as f:
        f.seek(off); b = f.read(1); f.seek(off); f.write(bytes([b[0] ^ 0xFF]))
    h.send("decrypt", {"path": out, "password": "p", "verify_only": True}, rid="v")
    err = h.error("v")
    assert err["code"] == "format" and "damaged" in err["message"]
    h.send("decrypt", {"path": out, "output_dir": out_dir, "password": "p"}, rid="d")
    err = h.error("d")
    assert err["code"] == "format" and "damaged" in err["message"]
    assert not [f for f in os.listdir(out_dir) if f.startswith(".qc-decrypt-")]
    # A genuinely wrong password is still reported as such
    h.send("decrypt", {"path": out, "password": "nope", "verify_only": True}, rid="w")
    assert h.error("w")["code"] == "wrong_credentials"


def test_place_without_clobber_survives_a_race(tmp_path, monkeypatch):
    import quantacrypt.core.package as pmod
    (tmp_path / "f.txt").write_text("old")
    tmp = tmp_path / ".t"; tmp.write_text("new")
    real_link = os.link
    calls = []

    def racy_link(src, dst):
        # Someone creates f_2.txt between the existence check and our link
        if dst.endswith("f_2.txt") and not calls:
            calls.append(1)
            open(dst, "w").write("intruder")
        return real_link(src, dst)

    monkeypatch.setattr(pmod.os, "link", racy_link)
    out, renamed = pmod._place_without_clobber(str(tmp), str(tmp_path), "f.txt")
    assert renamed and out.endswith("f_3.txt")
    assert (tmp_path / "f.txt").read_text() == "old"
    assert (tmp_path / "f_2.txt").read_text() == "intruder"
    assert open(out).read() == "new" and not tmp.exists()
    # Filesystems without hard links fall back to replace
    tmp2 = tmp_path / ".t2"; tmp2.write_text("v2")
    monkeypatch.setattr(pmod.os, "link", lambda s, d: (_ for _ in ()).throw(OSError(1, "no links")))
    out2, _ = pmod._place_without_clobber(str(tmp2), str(tmp_path), "g.txt")
    assert open(out2).read() == "v2"


def test_encrypt_failure_leaves_no_temp(src_file, tmp_path, monkeypatch):
    import quantacrypt.core.package as pmod
    monkeypatch.setattr(pmod.cc, "encrypt_single_streaming",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        pkg.encrypt_to_qcx(src_file, str(tmp_path / "x.qcx"), mode="password", password="p")
    assert not [f for f in os.listdir(tmp_path) if ".qc-enc-" in f]


def test_run_request_always_emits_a_terminal_event(h):
    def bad(params, ctx):
        raise KeyError()  # no args: str(exc) is "" — the classifier must cope

    h.svc.ops["bad"] = bad
    h.send("bad", rid="b")
    assert h.final("b")["event"] == "error"
