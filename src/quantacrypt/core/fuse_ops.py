"""FUSE filesystem for mounting QuantaCrypt encrypted volumes (.qcv).

Requires FUSE-T (macOS) or libfuse (Linux) and the ``fusepy`` Python package.
Install FUSE-T:  brew install --cask macfuse   (or brew install fuse-t)
Install fusepy:  pip install fusepy

Usage (programmatic):
    from quantacrypt.core.fuse_ops import mount_volume, unmount_volume
    mount_volume("/path/to/vault.qcv", final_key, "/Volumes/MyVault")

The module exposes a QuantaCryptFUSE class implementing fusepy's Operations
interface. All filesystem operations decrypt/encrypt on-the-fly through a
VolumeContainer instance from volume.py.
"""

from __future__ import annotations

import atexit
import errno
import logging
import os
import signal
import stat
import threading
import time
from collections import OrderedDict
from typing import Any

logger = logging.getLogger(__name__)

from quantacrypt.core.volume import VolumeContainer


# ── FUSE availability check ─────────────────────────────────────────────────

def check_fuse_available() -> tuple[bool, str]:
    """Check whether fusepy and a FUSE backend are available.

    Returns (available, message).
    """
    try:
        import fuse  # noqa: F401
        return True, "fusepy is available"
    except ImportError:
        return False, (
            "fusepy is not installed. Install it with:\n"
            "  pip install fusepy\n\n"
            "You also need a FUSE backend:\n"
            "  macOS: brew install --cask macfuse  (or brew install fuse-t)\n"
            "  Linux: sudo apt install libfuse-dev"
        )


def check_fuse_components() -> dict[str, dict[str, Any]]:
    """Return per-component availability for FUSE setup.

    Returns a dict with keys ``fusepy`` and ``fuse_backend``, each containing:
      - ``ok``      (bool): True if the component is available
      - ``detail``  (str):  Human-readable status message
    """
    import shutil
    import sys

    result: dict[str, dict[str, Any]] = {}

    # 1. fusepy Python package
    try:
        import fuse  # noqa: F401
        result["fusepy"] = {"ok": True, "detail": "fusepy is installed"}
    except ImportError:
        result["fusepy"] = {"ok": False, "detail": "fusepy is not installed"}

    # 2. System FUSE backend
    if sys.platform == "darwin":
        # Check for FUSE-T or macFUSE.  Homebrew installs to /opt/homebrew
        # on Apple Silicon (M1+) and /usr/local on Intel; check both.
        has_fuse_t = (
            os.path.isfile("/opt/homebrew/lib/libfuse-t.dylib")
            or os.path.isfile("/usr/local/lib/libfuse-t.dylib")
        )
        has_macfuse = os.path.isdir("/Library/Filesystems/macfuse.fs")
        has_osxfuse = os.path.isdir("/Library/Filesystems/osxfuse.fs")
        if has_fuse_t:
            result["fuse_backend"] = {"ok": True, "detail": "FUSE-T detected"}
        elif has_macfuse:
            result["fuse_backend"] = {"ok": True, "detail": "macFUSE detected"}
        elif has_osxfuse:
            result["fuse_backend"] = {"ok": True, "detail": "osxfuse detected"}
        else:
            result["fuse_backend"] = {
                "ok": False,
                "detail": "No FUSE backend found (macFUSE or FUSE-T)",
            }
    else:
        # Linux: check for fusermount or /dev/fuse
        has_fusermount = shutil.which("fusermount") is not None
        has_fusermount3 = shutil.which("fusermount3") is not None
        has_dev_fuse = os.path.exists("/dev/fuse")
        if has_fusermount or has_fusermount3 or has_dev_fuse:
            result["fuse_backend"] = {"ok": True, "detail": "FUSE detected"}
        else:
            result["fuse_backend"] = {
                "ok": False,
                "detail": "No FUSE backend found (libfuse)",
            }

    return result


# ── LRU Cache ───────────────────────────────────────────────────────────────

class LRUCache:
    """Simple LRU cache with max size in bytes."""

    def __init__(self, max_bytes: int = 100 * 1024 * 1024):
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._sizes: dict[str, int] = {}
        self._current_bytes = 0
        self._max_bytes = max_bytes

    def get(self, key: str) -> bytes | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, data: bytes) -> None:
        if key in self._cache:
            self._current_bytes -= self._sizes[key]
            del self._cache[key]

        self._cache[key] = data
        self._sizes[key] = len(data)
        self._current_bytes += len(data)
        self._cache.move_to_end(key)

        # Evict oldest entries if over limit
        while self._current_bytes > self._max_bytes and self._cache:
            oldest_key, _ = self._cache.popitem(last=False)
            self._current_bytes -= self._sizes.pop(oldest_key, 0)

    def invalidate(self, key: str) -> None:
        if key in self._cache:
            self._current_bytes -= self._sizes.pop(key, 0)
            del self._cache[key]

    def clear(self) -> None:
        self._cache.clear()
        self._sizes.clear()
        self._current_bytes = 0

    @property
    def size(self) -> int:
        return self._current_bytes

    def __len__(self) -> int:
        return len(self._cache)


# ── FUSE Operations ─────────────────────────────────────────────────────────

class QuantaCryptFUSE:
    """FUSE filesystem backed by an encrypted .qcv volume.

    Implements the fusepy Operations interface. All methods translate
    POSIX filesystem calls into VolumeContainer operations with
    on-the-fly encryption/decryption.
    """

    def __init__(self, volume: VolumeContainer, cache_mb: int = 100):
        self.volume = volume
        self.cache = LRUCache(max_bytes=cache_mb * 1024 * 1024)
        self._lock = threading.Lock()
        self._fd_counter = 0
        self._open_files: dict[int, str] = {}  # fd → vpath
        self._dirty_files: set[str] = set()
        self._file_buffers: dict[str, bytearray] = {}
        # POSIX unlink-while-open semantics: if a path is unlinked while an
        # fd is still open, the dir_index entry sticks around and the data
        # stays readable via that fd until the last close.  This set tracks
        # paths in that limbo state; release() performs the real delete
        # when the last fd closes.
        self._pending_unlink: set[str] = set()

    def _vpath(self, path: str) -> str:
        """Normalize FUSE path to volume path format."""
        if not path.startswith("/"):
            path = "/" + path
        return path

    def _dir_vpath(self, path: str) -> str:
        """Normalize path as a directory key (trailing slash)."""
        vp = self._vpath(path)
        if vp != "/" and not vp.endswith("/"):
            vp += "/"
        return vp

    def _next_fd(self) -> int:
        self._fd_counter += 1
        return self._fd_counter

    # ── Filesystem info ─────────────────────────────────────────────────

    def statfs(self, path: str) -> dict:
        """Return filesystem statistics."""
        stats = self.volume.stat()
        total = max(stats.get("container_size", 1 << 30), 1 << 30)
        used = stats.get("total_plaintext_size", 0)
        bsize = 4096
        total_blocks = total // bsize
        free_blocks = max(total_blocks - (used // bsize), 0)
        return {
            "f_bsize": bsize,
            "f_frsize": bsize,
            "f_blocks": total_blocks,
            "f_bfree": free_blocks,
            "f_bavail": free_blocks,
            "f_files": stats.get("file_count", 0) + stats.get("dir_count", 0),
            "f_ffree": 1000000,
            "f_favail": 1000000,
            "f_namemax": 255,
        }

    # ── Attributes ──────────────────────────────────────────────────────

    def getattr(self, path: str, fh: int | None = None) -> dict:
        """Return file/directory attributes (stat)."""
        vpath = self._vpath(path)

        # Root directory
        if vpath == "/":
            now = int(time.time())
            return {
                "st_mode": stat.S_IFDIR | 0o755,
                "st_nlink": 2,
                "st_size": 0,
                "st_uid": os.getuid(),
                "st_gid": os.getgid(),
                "st_atime": now,
                "st_mtime": now,
                "st_ctime": now,
            }

        # Check as file first, then as directory
        entry = self.volume.get_entry(vpath)
        if entry is None:
            entry = self.volume.get_entry(vpath + "/")
        if entry is None:
            raise OSError(errno.ENOENT, "No such file or directory", path)

        is_dir = entry.get("type") == "dir"
        mode = entry.get("mode", 0o40755 if is_dir else 0o100644)
        mtime = entry.get("mtime", int(time.time()))

        # If the file has been modified in a buffer, report buffer size
        size = entry.get("size", 0)
        if vpath in self._file_buffers:
            size = len(self._file_buffers[vpath])

        return {
            "st_mode": mode,
            "st_nlink": 2 if is_dir else 1,
            "st_size": size,
            "st_uid": os.getuid(),
            "st_gid": os.getgid(),
            "st_atime": mtime,
            "st_mtime": mtime,
            "st_ctime": mtime,
        }

    # ── Directory operations ────────────────────────────────────────────

    def readdir(self, path: str, fh: int | None = None) -> list[str]:
        """List directory contents."""
        vpath = self._vpath(path)
        entries = [".", ".."]
        entries.extend(self.volume.list_dir(vpath))
        return entries

    def mkdir(self, path: str, mode: int) -> None:
        """Create a directory."""
        with self._lock:
            self.volume.mkdir(self._vpath(path))

    def rmdir(self, path: str) -> None:
        """Remove an empty directory."""
        with self._lock:
            dir_vp = self._dir_vpath(path)
            children = self.volume.list_dir(dir_vp.rstrip("/"))
            if children:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", path)
            self.volume.delete(dir_vp)

    # ── File operations ─────────────────────────────────────────────────

    def create(self, path: str, mode: int, fi: Any = None) -> int:
        """Create a new file and return a file descriptor."""
        vpath = self._vpath(path)
        with self._lock:
            self.volume.write_file(vpath, b"")
            self._file_buffers[vpath] = bytearray()
            fd = self._next_fd()
            self._open_files[fd] = vpath
        return fd

    def open(self, path: str, flags: int) -> int:
        """Open a file and return a file descriptor."""
        vpath = self._vpath(path)
        entry = self.volume.get_entry(vpath)
        if entry is None:
            raise OSError(errno.ENOENT, "No such file", path)

        fd = self._next_fd()
        with self._lock:
            self._open_files[fd] = vpath

            # Load file data into buffer if not already cached.
            # Skip whole-plaintext SHA-256 on the FUSE hot path — per-chunk
            # AES-GCM already authenticates the data.  Explicit integrity
            # verification remains available via VolumeContainer.read_file(
            # vpath, verify_hash=True) for callers that want it.
            if vpath not in self._file_buffers:
                cached = self.cache.get(vpath)
                if cached is not None:
                    self._file_buffers[vpath] = bytearray(cached)
                else:
                    data = self.volume.read_file(vpath, verify_hash=False)
                    self._file_buffers[vpath] = bytearray(data)
                    self.cache.put(vpath, data)

        return fd

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        """Read data from a file."""
        vpath = self._vpath(path)
        with self._lock:
            buf = self._file_buffers.get(vpath)
            if buf is None:
                # Lazy load; verify_hash=False on the hot path (see open()).
                data = self.volume.read_file(vpath, verify_hash=False)
                buf = bytearray(data)
                self._file_buffers[vpath] = buf
        return bytes(buf[offset:offset + size])

    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        """Write data to a file."""
        vpath = self._vpath(path)
        with self._lock:
            buf = self._file_buffers.get(vpath)
            if buf is None:
                buf = bytearray()
                self._file_buffers[vpath] = buf

            # Extend buffer if writing past end
            end = offset + len(data)
            if end > len(buf):
                buf.extend(b"\x00" * (end - len(buf)))
            buf[offset:end] = data
            self._dirty_files.add(vpath)
        return len(data)

    def truncate(self, path: str, length: int, fh: int | None = None) -> None:
        """Truncate or extend a file to the given length."""
        vpath = self._vpath(path)
        with self._lock:
            buf = self._file_buffers.get(vpath)
            if buf is None:
                # Lazy load; verify_hash=False on the hot path (see open()).
                data = self.volume.read_file(vpath, verify_hash=False)
                buf = bytearray(data)
                self._file_buffers[vpath] = buf

            if length < len(buf):
                del buf[length:]
            elif length > len(buf):
                buf.extend(b"\x00" * (length - len(buf)))
            self._dirty_files.add(vpath)

    def flush(self, path: str, fh: int) -> None:
        """Flush dirty data to the volume container."""
        vpath = self._vpath(path)
        with self._lock:
            if vpath in self._dirty_files:
                # If the file was unlink()ed while still open, a write to
                # its fd goes to the inode-that-no-longer-has-a-name and
                # should NOT be persisted — the last close will drop it.
                if vpath not in self._pending_unlink:
                    buf = self._file_buffers.get(vpath, bytearray())
                    # One materialisation of the bytes — write_file takes the
                    # same object the cache gets, instead of allocating twice.
                    snapshot = bytes(buf)
                    self.volume.write_file(vpath, snapshot)
                    self.cache.put(vpath, snapshot)
                self._dirty_files.discard(vpath)

    def release(self, path: str, fh: int) -> None:
        """Close a file descriptor."""
        vpath = self._vpath(path)
        with self._lock:
            # Flush if dirty (but skip the persist for unlink-while-open;
            # see flush() for why).
            if vpath in self._dirty_files:
                if vpath not in self._pending_unlink:
                    buf = self._file_buffers.get(vpath, bytearray())
                    snapshot = bytes(buf)
                    self.volume.write_file(vpath, snapshot)
                    self.cache.put(vpath, snapshot)
                self._dirty_files.discard(vpath)

            self._open_files.pop(fh, None)

            # Keep buffer in cache but remove from active buffers
            # if no other FDs have it open
            still_open = any(
                v == vpath for v in self._open_files.values()
            )
            if not still_open:
                self._file_buffers.pop(vpath, None)
                # If the last open fd for a deferred-unlink path just
                # closed, perform the real delete now.
                if vpath in self._pending_unlink:
                    self._pending_unlink.discard(vpath)
                    try:
                        self.volume.delete(vpath)
                    except FileNotFoundError:
                        pass
                    self.cache.invalidate(vpath)
                    self._dirty_files.discard(vpath)

    def unlink(self, path: str) -> None:
        """Delete a file.

        POSIX requires that an unlinked file remain accessible through any
        still-open file descriptor until the last close ("delete on last
        close").  Many editors and tools rely on this — they create a
        temp file, unlink it immediately, then continue writing to the
        fd to get automatic cleanup on crash.  If we eagerly delete on
        every unlink we'd break that pattern AND (worse) silently
        resurrect the file on the next release() when the still-open fd
        flushes its buffer.
        """
        vpath = self._vpath(path)
        with self._lock:
            has_open_fd = any(v == vpath for v in self._open_files.values())
            if has_open_fd:
                # Defer — the last release() will do the actual delete.
                self._pending_unlink.add(vpath)
                return
            self.volume.delete(vpath)
            self._file_buffers.pop(vpath, None)
            self.cache.invalidate(vpath)
            self._dirty_files.discard(vpath)

    def rename(self, old: str, new: str) -> None:
        """Rename a file or directory."""
        old_vp = self._vpath(old)
        new_vp = self._vpath(new)
        with self._lock:
            self.volume.rename(old_vp, new_vp)
            if old_vp in self._file_buffers:
                self._file_buffers[new_vp] = self._file_buffers.pop(old_vp)
            self.cache.invalidate(old_vp)
            if old_vp in self._dirty_files:
                self._dirty_files.discard(old_vp)
                self._dirty_files.add(new_vp)

    def save_all_dirty(self) -> None:
        """Flush all dirty FUSE buffers to the volume, then persist the volume.

        Acquires the FUSE ops lock so this cannot race with an in-flight
        flush(), release(), write(), or other FS operation.  Used by
        unmount_volume() and _emergency_save_all() to ensure the volume on
        disk reflects the latest buffered writes.  Without this, an unmount
        or signal-driven shutdown could persist stale volume data even though
        the user's writes had already been accepted.
        """
        with self._lock:
            for vpath in list(self._dirty_files):
                buf = self._file_buffers.get(vpath, bytearray())
                snapshot = bytes(buf)
                self.volume.write_file(vpath, snapshot)
                self.cache.put(vpath, snapshot)
            self._dirty_files.clear()
            if self.volume.is_dirty:
                self.volume.save()


# ── Mount / Unmount API ─────────────────────────────────────────────────────

_mounted_volumes: dict[str, dict] = {}  # mount_point → {thread, volume, fuse_obj}
# Serialises mount_volume() / unmount_volume() mutations of _mounted_volumes
# so concurrent UI clicks or scripted mounts can't observe torn state.
_mount_lock = threading.Lock()

# How long mount_volume() waits for the FUSE worker to either successfully
# start serving or fail synchronously.  If FUSE() raises (missing backend,
# unwritable mount point, busy target) the thread dies inside this window
# and we propagate the exception instead of registering a zombie mount.
_FUSE_STARTUP_TIMEOUT = 2.0

# ── Graceful shutdown ──────────────────────────────────────────────────────

_shutdown_registered = False
_shutdown_lock = threading.Lock()


def _emergency_save_all() -> None:
    """Save all dirty mounted volumes.

    Called by atexit and signal handlers to prevent data loss on
    app exit or crash.  Routes through QuantaCryptFUSE.save_all_dirty()
    so that buffered writes not yet flushed are still persisted.
    Errors are logged but never raised so that the shutdown sequence
    is not interrupted.
    """
    for mp in list(_mounted_volumes):
        info = _mounted_volumes.get(mp)
        if info is None:
            continue
        try:
            fuse_obj = info.get("fuse")
            if fuse_obj is not None:
                logger.info("Shutdown: saving dirty state for volume at %s", mp)
                fuse_obj.save_all_dirty()
            else:
                vc = info["volume"]
                if vc.is_dirty:
                    vc.save()
        except Exception:
            logger.exception("Shutdown: failed to save volume at %s", mp)


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM / SIGINT by saving volumes then re-raising."""
    _emergency_save_all()
    # Re-raise with default handler so the process actually exits
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def _ensure_shutdown_handlers() -> None:
    """Register atexit + signal handlers (once)."""
    global _shutdown_registered  # noqa: PLW0603
    with _shutdown_lock:
        if _shutdown_registered:
            return
        atexit.register(_emergency_save_all)
        # Only install signal handlers on the main thread
        try:
            signal.signal(signal.SIGTERM, _signal_handler)
            signal.signal(signal.SIGINT, _signal_handler)
        except ValueError:
            # Can only set signal handlers from the main thread
            pass
        _shutdown_registered = True


def mount_volume(
    volume_path: str,
    final_key: bytes,
    mount_point: str,
    foreground: bool = False,
    cache_mb: int = 100,
) -> QuantaCryptFUSE:
    """Mount a .qcv volume at the given mount point.

    If foreground=True, blocks until unmounted. Otherwise starts a
    background thread and returns immediately.

    Raises RuntimeError if fusepy is not available or if the volume
    (by real path) is already mounted.
    """
    _ensure_shutdown_handlers()

    real_vol = os.path.realpath(volume_path)

    # Fast-path double-mount guard (the lock-held re-check below is the
    # race-safe guarantee).  Match the historical error order: this check
    # runs before we touch fusepy, so a callers-reliable RuntimeError fires
    # even in test environments where the FUSE backend isn't present.
    for mp, info in _mounted_volumes.items():
        if os.path.realpath(info["volume_path"]) == real_vol:
            raise RuntimeError(
                f"Volume is already mounted at {mp}. "
                "Unmount it first before mounting again."
            )

    available, msg = check_fuse_available()
    if not available:
        raise RuntimeError(msg)

    from fuse import FUSE  # type: ignore[import-untyped]

    # Open the volume
    vc = VolumeContainer(volume_path, final_key)
    vc.open()

    # Create mount point if needed
    os.makedirs(mount_point, exist_ok=True)

    fuse_obj = QuantaCryptFUSE(vc, cache_mb=cache_mb)

    if foreground:
        FUSE(fuse_obj, mount_point, foreground=True, nothreads=True,
             allow_other=False, volname="QuantaCrypt")
        return fuse_obj

    # Background mount: wait for FUSE to either start serving or fail
    # synchronously, and only register _mounted_volumes on success.
    # Previously we registered unconditionally; a failed FUSE startup
    # (missing FUSE-T, busy mount point, permission denied) left a zombie
    # entry, and a later unmount_volume() would run diskutil / fusermount
    # against a path we never actually mounted.
    startup_error: list[BaseException] = []
    ready = threading.Event()

    def _run():
        try:
            FUSE(fuse_obj, mount_point, foreground=True, nothreads=True,
                 allow_other=False, volname="QuantaCrypt")
        except BaseException as exc:  # noqa: BLE001
            startup_error.append(exc)
        finally:
            ready.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # A live FUSE() blocks serving requests; the thread staying alive past
    # this window means the mount is up.  If the thread has already exited,
    # FUSE() raised synchronously and we propagate.
    ready.wait(timeout=_FUSE_STARTUP_TIMEOUT)
    if not t.is_alive():
        if startup_error:
            raise RuntimeError(
                f"FUSE mount failed: {startup_error[0]}"
            ) from startup_error[0]
        raise RuntimeError(
            "FUSE worker thread exited before the mount was established"
        )

    # Atomic registration: re-check double-mount under the lock so two
    # concurrent callers can't both pass the early guard and each install
    # a tracker entry for the same volume file.
    with _mount_lock:
        for mp, info in _mounted_volumes.items():
            if os.path.realpath(info["volume_path"]) == real_vol:
                raise RuntimeError(
                    f"Volume is already mounted at {mp}. "
                    "Unmount it first before mounting again."
                )
        _mounted_volumes[mount_point] = {
            "thread": t,
            "volume": vc,
            "fuse": fuse_obj,
            "volume_path": volume_path,
        }

    return fuse_obj


def unmount_volume(mount_point: str) -> None:
    """Unmount a volume and save any pending changes.

    Saves dirty data (including buffered FUSE writes) **before** removing
    from the tracking dict so that ``_emergency_save_all`` can still reach
    the volume if save() fails.  The external unmount subprocess is only
    invoked for paths we actually own — we do not run diskutil/fusermount
    against an arbitrary path passed in by a caller.
    """
    import subprocess
    import sys

    with _mount_lock:
        info = _mounted_volumes.get(mount_point)
        if info is None:
            raise ValueError(
                f"No QuantaCrypt volume is tracked at {mount_point!r} — "
                "refusing to run unmount against a path we do not own"
            )

    # Save state *before* removing from the dict so that if save_all_dirty()
    # fails, _emergency_save_all can still find the volume for a retry.
    fuse_obj = info.get("fuse")
    if fuse_obj is not None:
        fuse_obj.save_all_dirty()
    elif info["volume"].is_dirty:
        info["volume"].save()
    with _mount_lock:
        _mounted_volumes.pop(mount_point, None)

    # Use platform-appropriate unmount
    if sys.platform == "darwin":
        subprocess.run(["diskutil", "unmount", mount_point],
                       capture_output=True)
    else:
        subprocess.run(["fusermount", "-u", mount_point],
                       capture_output=True)


def get_mounted_volumes() -> dict[str, dict]:
    """Return dict of currently mounted volumes: mount_point → info."""
    return dict(_mounted_volumes)
