"""JSON-lines service that drives the core for any front end.

See docs/design/core-service-protocol.md.  One request per stdin line, one
event per stdout line; long operations run on worker threads and report
``progress`` events; ``cancel`` flips the request's token.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from typing import Any, Callable, IO

from quantacrypt import __version__
from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core.errors import classify_error

CONTROL_OPS = ("cancel", "shutdown", "ping", "version")

# (keyword, stage id, label) — first match wins, so put specific before broad.
_STAGE_MAP = [
    ("compress",       "compress", "Compressing folder"),
    ("argon2",         "kdf",      "Securing password"),
    ("private key",    "lock",     "Locking key"),
    ("keypair",        "kem",      "Generating protection"),
    ("kyber",          "kem",      "Generating protection"),
    ("encapsulat",     "kem",      "Generating protection"),
    ("master key",     "kem",      "Generating protection"),
    ("splitting",      "split",    "Splitting key"),
    ("combining",      "split",    "Combining shares"),
    ("decrypting payload", "payload", "Decrypting file"),
    ("payload",        "payload",  "Encrypting file"),
    ("integrity",      "verify",   "Checking integrity"),
    ("writing",        "write",    "Saving"),
    ("reading",        "read",     "Reading volume"),
    ("mount",          "mount",    "Mounting"),
]
_PCT_RE = re.compile(r"(\d{1,3})%")


def stage_for(message: str) -> tuple[str, str, float | None]:
    """Map a raw core progress string to (stage, label, pct-or-None)."""
    low = message.lower()
    stage, label = "work", message
    for kw, sid, lbl in _STAGE_MAP:
        if kw in low:
            stage, label = sid, lbl
            break
    m = _PCT_RE.search(message)
    pct = min(int(m.group(1)), 100) / 100.0 if m else None
    return stage, label, pct


class _Request:
    __slots__ = ("id", "op", "params", "cancelled", "thread")

    def __init__(self, rid: str, op: str, params: dict):
        self.id = rid
        self.op = op
        self.params = params
        self.cancelled = threading.Event()
        self.thread: threading.Thread | None = None


class Service:
    """Dispatcher.  Construct with text streams; call ``run()`` to serve
    until EOF/shutdown, or ``handle_line()`` from tests."""

    def __init__(self, reader: IO[str], writer: IO[str], *,
                 exit_fn: Callable[[], None] | None = None):
        self._in = reader
        self._out = writer
        self._wlock = threading.Lock()
        self._reqs: dict[str, _Request] = {}
        self._rlock = threading.Lock()
        self._stopping = False
        self._exit_fn = exit_fn
        self.ops: dict[str, Callable[[dict, "_Ctx"], dict]] = {
            "fuse_check": op_fuse_check,
            "inspect": op_inspect,
            "encrypt": op_encrypt,
            "decrypt": op_decrypt,
            "volume_inspect": op_volume_inspect,
            "volume_create": op_volume_create,
            "volume_mount": op_volume_mount,
            "volume_unmount": op_volume_unmount,
            "volume_list": op_volume_list,
        }

    # ── I/O ──────────────────────────────────────────────────────────────────

    def emit(self, obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        with self._wlock:
            self._out.write(line + "\n")
            self._out.flush()

    def _error(self, rid: Any, code: str, message: str, detail: str = "") -> None:
        self.emit({"id": rid, "event": "error", "code": code,
                   "message": message, "detail": detail})

    # ── Loop ─────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Serve until EOF or ``shutdown``.

        EOF means "no more requests": in-flight work is allowed to finish
        (a one-shot client may write its request and close the pipe), then
        volumes are unmounted and the process exits.  The ``shutdown`` op
        is the abrupt form: it cancels in-flight work first.
        """
        try:
            for line in self._in:
                if self._stopping:
                    break
                self.handle_line(line)
        finally:
            if not self._stopping:
                self.wait_idle(timeout=None)
            self.shutdown()

    def handle_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            req = json.loads(line)
        except ValueError as exc:
            self._error(None, "invalid_request", "Request is not valid JSON.", str(exc))
            return
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            self._error(req.get("id") if isinstance(req, dict) else None,
                        "invalid_request", "Request needs an 'op' string.")
            return
        rid = req.get("id")
        if rid is None:
            rid = f"auto-{len(self._reqs) + 1}"
        rid = str(rid)
        op = req["op"]
        params = req.get("params") or {}
        if not isinstance(params, dict):
            self._error(rid, "invalid_request", "'params' must be an object.")
            return

        if op in CONTROL_OPS:
            self._control(rid, op, params)
            return
        handler = self.ops.get(op)
        if handler is None:
            self._error(rid, "invalid_request", f"Unknown op {op!r}.")
            return
        with self._rlock:
            if rid in self._reqs:
                self._error(rid, "invalid_request", f"Request id {rid!r} is already running.")
                return
            r = _Request(rid, op, params)
            self._reqs[rid] = r
        t = threading.Thread(target=self._run_request, args=(r, handler),
                             name=f"qc-{op}-{rid}", daemon=True)
        r.thread = t
        t.start()

    def _control(self, rid: str, op: str, params: dict) -> None:
        if op == "ping":
            self.emit({"id": rid, "event": "done", "result": {}})
        elif op == "version":
            self.emit({"id": rid, "event": "done", "result": {
                "version": __version__,
                "format_version": cc.MAX_FORMAT_VERSION,
                "platform": sys.platform,
                "python": ".".join(map(str, sys.version_info[:3])),
            }})
        elif op == "cancel":
            target = str(params.get("target", ""))
            with self._rlock:
                r = self._reqs.get(target)
            if r is not None:
                r.cancelled.set()
            self.emit({"id": rid, "event": "done", "result": {"cancelled": r is not None}})
        elif op == "shutdown":
            self.emit({"id": rid, "event": "done", "result": {}})
            self._stopping = True
            self.shutdown()

    def _run_request(self, r: _Request, handler) -> None:
        ctx = _Ctx(self, r)
        try:
            result = handler(r.params, ctx)
            if r.cancelled.is_set():
                raise cc.CancelledOperation("Cancelled")
            self.emit({"id": r.id, "event": "done", "result": result})
        except BaseException as exc:  # noqa: BLE001 — every failure becomes an event
            code, message, detail = classify_error(exc)
            self._error(r.id, code, message, detail)
        finally:
            with self._rlock:
                self._reqs.pop(r.id, None)

    def wait_idle(self, timeout: float | None = 30.0) -> None:
        """Block until every worker has finished (``None`` = no limit)."""
        with self._rlock:
            threads = [r.thread for r in self._reqs.values() if r.thread]
        for t in threads:
            t.join(timeout)

    def shutdown(self) -> None:
        """Cancel running work, save and unmount every volume, exit."""
        self._stopping = True
        with self._rlock:
            reqs = list(self._reqs.values())
        for r in reqs:
            r.cancelled.set()
        for r in reqs:
            if r.thread:
                r.thread.join(5)
        try:
            from quantacrypt.core.fuse_ops import get_mounted_volumes, unmount_volume
            for mp in list(get_mounted_volumes()):
                try:
                    unmount_volume(mp)
                except Exception as exc:  # noqa: BLE001 — best effort at exit
                    print(f"qc-core: unmount {mp} failed: {exc}", file=sys.stderr)
        except Exception:  # fusepy absent — nothing to unmount
            pass
        if self._exit_fn:
            self._exit_fn()


class _Ctx:
    """What a handler gets: progress emitter + cancel predicate."""

    def __init__(self, svc: Service, req: _Request):
        self._svc = svc
        self._req = req

    def progress(self, message: str) -> None:
        stage, label, pct = stage_for(message)
        self._svc.emit({"id": self._req.id, "event": "progress", "stage": stage,
                        "label": label, "pct": pct, "message": message})

    def cancelled(self) -> bool:
        return self._req.cancelled.is_set()

    def check(self) -> None:
        if self.cancelled():
            raise cc.CancelledOperation("Cancelled")


# ── Handlers ─────────────────────────────────────────────────────────────────

def _need(params: dict, *keys: str) -> None:
    missing = [k for k in keys if not params.get(k)]
    if missing:
        raise ValueError(f"Missing parameter(s): {', '.join(missing)}")


def op_fuse_check(params: dict, ctx: _Ctx) -> dict:
    try:
        from quantacrypt.core.fuse_ops import check_fuse_components
        comps = check_fuse_components()
    except Exception as exc:  # noqa: BLE001 — report, don't crash the service
        comps = {"fusepy": {"ok": False, "detail": str(exc)},
                 "fuse_backend": {"ok": False, "detail": "not checked"}}
    return {**comps, "ok": all(c.get("ok") for c in comps.values())}


def op_inspect(params: dict, ctx: _Ctx) -> dict:
    _need(params, "path")
    return pkg.inspect_summary(params["path"])


def op_encrypt(params: dict, ctx: _Ctx) -> dict:
    _need(params, "source", "output", "mode")
    return pkg.encrypt_to_qcx(
        params["source"], params["output"], mode=params["mode"],
        password=params.get("password"), k=params.get("k"), n=params.get("n"),
        progress=ctx.progress, cancel_check=ctx.cancelled,
        embed_binary=params.get("embed_binary"))


def op_decrypt(params: dict, ctx: _Ctx) -> dict:
    _need(params, "path")
    verify_only = bool(params.get("verify_only"))
    if not verify_only:
        _need(params, "output_dir")
    return pkg.decrypt_qcx(
        params["path"], params.get("output_dir", ""),
        password=params.get("password"), shares=params.get("shares"),
        verify_only=verify_only, progress=ctx.progress, cancel_check=ctx.cancelled)


def op_volume_inspect(params: dict, ctx: _Ctx) -> dict:
    """What can be said about a .qcv without any credential — lets the
    client pick password vs split-key entry before asking."""
    from quantacrypt.core import volume as vol
    _need(params, "path")
    path = params["path"]
    header, auth = vol.read_volume_auth_params(path)
    mode = auth.get("mode", "single")
    return {
        "path": path,
        "size": os.path.getsize(path),
        "format_version": header.get("format_version"),
        "mode": mode,
        "threshold": auth.get("threshold"),
        "total": auth.get("total"),
    }


def op_volume_create(params: dict, ctx: _Ctx) -> dict:
    from quantacrypt.core import volume as vol
    _need(params, "path", "mode")
    path = params["path"]
    if not path.lower().endswith(".qcv"):
        path += ".qcv"
    if os.path.exists(path):
        raise FileExistsError(f"{path} already exists")
    mode = params["mode"]
    if mode in ("password", "single"):
        _need(params, "password")
        vol.create_volume_single(path, params["password"], progress_cb=ctx.progress)
        return {"path": path, "mode": "single", "shares": []}
    k, n = params.get("k"), params.get("n")
    if not (k and n and 2 <= k <= n <= 255):
        raise ValueError("Split-key mode needs 2 <= k <= n <= 255")
    _meta, shares = vol.create_volume_shamir(path, n, k, progress_cb=ctx.progress)
    return {"path": path, "mode": "shamir", "threshold": k, "total": n,
            "shares": pkg.shares_with_mnemonics(shares, k)}


def op_volume_mount(params: dict, ctx: _Ctx) -> dict:
    from quantacrypt.core import volume as vol
    from quantacrypt.core.fuse_ops import mount_volume
    _need(params, "path", "mount_point")
    path, mp = params["path"], params["mount_point"]
    ctx.progress("Reading volume...")
    _header, auth = vol.read_volume_auth_params(path)
    ctx.check()
    if auth.get("mode") == "single":
        _need(params, "password")
        ctx.progress("Deriving 512-bit password key (Argon2id)...")
        key = vol.derive_volume_key_single(params["password"], auth)
    else:
        codes = pkg.normalize_shares(params.get("shares") or [])
        k = auth.get("threshold") or len(codes)
        if len(codes) < k:
            raise ValueError(f"Need {k} different shares to unlock this volume, got {len(codes)}")
        ctx.progress(f"Combining {k} shares to recover the key...")
        key = vol.derive_volume_key_shamir(codes[:k], auth)
    ctx.check()
    ctx.progress("Mounting...")
    fuse_obj = mount_volume(path, key, mp)
    suspicious = bool(getattr(getattr(fuse_obj, "volume", None), "journal_suspicious", False))
    return {"mount_point": mp, "volume_path": path, "journal_suspicious": suspicious}


def op_volume_unmount(params: dict, ctx: _Ctx) -> dict:
    from quantacrypt.core.fuse_ops import unmount_volume
    _need(params, "mount_point")
    unmount_volume(params["mount_point"])
    return {"mount_point": params["mount_point"]}


def op_volume_list(params: dict, ctx: _Ctx) -> dict:
    try:
        from quantacrypt.core.fuse_ops import get_mounted_volumes
        mounted = get_mounted_volumes()
    except Exception:  # fusepy absent
        mounted = {}
    out = []
    for mp, info in mounted.items():
        entry = {"mount_point": mp, "volume_path": info.get("volume_path")}
        vc = info.get("volume")
        try:
            entry["stats"] = vc.stat() if vc is not None else None
        except Exception:  # noqa: BLE001 — stats are best-effort
            entry["stats"] = None
        out.append(entry)
    return {"volumes": out}
