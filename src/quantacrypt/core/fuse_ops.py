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
import hashlib
import logging
import os
import signal
import stat
import threading
import time
from collections import OrderedDict
from typing import Any

logger = logging.getLogger(__name__)

from quantacrypt.core.volume import VOLUME_CHUNK_SIZE, VolumeContainer


# ── FUSE availability check ─────────────────────────────────────────────────

def _prepare_fuse_environment() -> None:
    """Point fusepy at FUSE-T's libfuse when nothing else would be found.

    fusepy's Darwin loader resolves the library via find_library('fuse')
    or the FUSE_LIBRARY_PATH env var — it never looks for
    ``libfuse-t.dylib``, so a FUSE-T-only machine (our recommended
    install) would fail with "Unable to find libfuse" despite having a
    working backend.  macFUSE registers itself with find_library, so we
    only intervene when it is absent.
    """
    import sys
    if sys.platform != "darwin" or os.environ.get("FUSE_LIBRARY_PATH"):
        return
    if os.path.isdir("/Library/Filesystems/macfuse.fs"):
        return
    for cand in ("/opt/homebrew/lib/libfuse-t.dylib",
                 "/usr/local/lib/libfuse-t.dylib"):
        if os.path.isfile(cand):
            os.environ["FUSE_LIBRARY_PATH"] = cand
            return


def check_fuse_available() -> tuple[bool, str]:
    """Check whether fusepy and a FUSE backend are available.

    Returns (available, message).

    fusepy raises ImportError when the package is missing but
    EnvironmentError (an OSError) when the package imports and no libfuse
    backend can be loaded — both must be caught or the "helpful error"
    path itself crashes on machines without a backend.
    """
    try:
        _prepare_fuse_environment()
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
    except OSError as exc:
        return False, (
            f"fusepy is installed but could not load a FUSE backend ({exc}).\n\n"
            "Install a backend:\n"
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

    # 1. fusepy Python package (OSError = installed but backend unloadable;
    # see check_fuse_available)
    try:
        _prepare_fuse_environment()
        import fuse  # noqa: F401
        result["fusepy"] = {"ok": True, "detail": "fusepy is installed"}
    except ImportError:
        result["fusepy"] = {"ok": False, "detail": "fusepy is not installed"}
    except OSError as exc:
        result["fusepy"] = {
            "ok": False,
            "detail": f"fusepy cannot load a FUSE backend: {exc}",
        }

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

    def invalidate_prefix(self, prefix: str) -> None:
        """Drop every entry whose key starts with ``prefix`` (dir renames)."""
        for key in [k for k in self._cache if k.startswith(prefix)]:
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

# fusepy dispatches every kernel op by CALLING the operations object —
# self.operations('getattr', path, fh) — a protocol only fuse.Operations
# provides via __call__ (plus sane defaults for the ~20 ops we don't
# implement).  Subclassing it is therefore mandatory for a real mount to
# work; a plain class "mounts" fine and then fails every op with EINVAL.
# The import is guarded so this module (and the direct-call test suite)
# stays importable when fusepy is absent — mount_volume() re-checks
# availability before any real mount.
# OSError too: fusepy raises EnvironmentError at import time when no
# libfuse backend loads — the module must stay importable on such machines
# so check_fuse_components can show the guided-setup screen.
try:
    _prepare_fuse_environment()
    from fuse import Operations as _FuseOperations
except (ImportError, OSError):  # pragma: no cover — dev/CI installs fusepy
    class _FuseOperations:
        """Stand-in base so the module imports without fusepy/libfuse."""


class QuantaCryptFUSE(_FuseOperations):
    """FUSE filesystem backed by an encrypted .qcv volume.

    Implements the fusepy Operations interface. All methods translate
    POSIX filesystem calls into VolumeContainer operations with
    on-the-fly encryption/decryption.
    """

    def __init__(self, volume: VolumeContainer, cache_mb: int = 100):
        self.volume = volume
        self.cache = LRUCache(max_bytes=cache_mb * 1024 * 1024)
        # RLock, not Lock: SIGTERM/SIGINT handlers run _emergency_save_all
        # on the main thread; if the signal lands while the main thread is
        # already inside save_all_dirty (e.g. via unmount_volume), a plain
        # Lock would self-deadlock and no volume would get its emergency
        # save.
        self._lock = threading.RLock()
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
        """Return filesystem statistics.

        Free space is the HOST filesystem's: the container grows on the
        host disk, so that is the true bound on what can still be
        written (the approach gocryptfs/Cryptomator take).  The old
        ``max(container, 1 GB) − plaintext`` formula collapsed to ~zero
        free once a volume held ≈1 GB — Finder's free-space pre-flight
        then refused every copy into the mount — and journal dead space
        inflated the number after deletes.
        """
        with self._lock:
            stats = self.volume.stat()
        used = stats.get("total_plaintext_size", 0)
        bsize = 4096
        try:
            host = os.statvfs(
                os.path.dirname(os.path.abspath(self.volume.path)) or "/")
            host_free = host.f_bavail * host.f_frsize
        except OSError:
            host_free = 1 << 40  # host unstat-able: claim 1 TB free
        # NB: the write path's memory ceiling is deliberately NOT applied
        # here. It bounds a single file, not the filesystem, and folding it
        # into f_bavail made a volume on a 274 GB disk report 2 GB total and
        # 2 GB free — a worse lie than the one it set out to fix, and a
        # return of the very "full disk" symptom R8 F-001 removed. The bound
        # is enforced in write(), where it actually applies, as EFBIG.
        total_blocks = (used + host_free) // bsize
        free_blocks = host_free // bsize
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

        # POSIX: once a file has been unlinked, the pathname is no longer
        # resolvable even if fds remain open on it.  The still-open fd can
        # access data via its fh (FUSE read/write), but a fresh getattr
        # against the name must fail.
        # One acquisition for the whole read: the unlink set, the index
        # lookup and the buffer size are all mutated by other FUSE workers,
        # and a torn read across them reports a size for a file that is no
        # longer there. _lock is an RLock, so nesting inside callers is free.
        with self._lock:
            if vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)

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
        """List directory contents.

        Filters out paths that have been unlinked-with-fds-still-open —
        POSIX says they must not show up in the namespace, even though
        dir_index still carries the entry until the last close.
        """
        vpath = self._vpath(path)
        entries = [".", ".."]
        with self._lock:
            # Both reads under one acquisition: list_dir() walks dir_index,
            # which other FUSE workers mutate.
            raw = self.volume.list_dir(vpath)
            pending = set(self._pending_unlink)
        if pending:
            prefix = vpath if vpath.endswith("/") else vpath + "/"
            if vpath == "/":
                prefix = "/"
            raw = [n for n in raw if (prefix + n) not in pending]
        entries.extend(raw)
        return entries

    def mkdir(self, path: str, mode: int) -> None:
        """Create a directory."""
        with self._lock:
            self.volume.mkdir(self._vpath(path))
            self._persist_locked()

    def rmdir(self, path: str) -> None:
        """Remove an empty directory."""
        with self._lock:
            dir_vp = self._dir_vpath(path)
            children = self.volume.list_dir(dir_vp.rstrip("/"))
            if children:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", path)
            self.volume.delete(dir_vp)
            self._persist_locked()

    def _persist_locked(self) -> None:
        """Persist volume state if dirty.  Caller must hold ``_lock``.

        save() is a journal append — O(size of the change) — so calling it
        on every metadata op and flush is cheap.  Deferring persistence to
        unmount (the pre-fix behavior) meant a crash, SIGKILL, or power
        loss silently discarded every write since mount.
        """
        if self.volume.is_dirty:
            self.volume.save()

    # ── File operations ─────────────────────────────────────────────────

    def create(self, path: str, mode: int, fi: Any = None) -> int:
        """Create a new file and return a file descriptor.

        If the path is still in ``_pending_unlink`` (unlinked while other
        fds remain open), refuse with EEXIST: our buffers are vpath-keyed,
        so allowing the create would corrupt the old fds' view.  The POSIX-
        correct alternative (per-fd buffers as separate inodes) is a bigger
        refactor; for our use case (editor swap, tempfile) it's safer to
        ask the caller to wait for the old fds to close.
        """
        vpath = self._vpath(path)
        with self._lock:
            if vpath in self._pending_unlink:
                raise OSError(
                    errno.EEXIST,
                    "Path was unlinked but still has open fds",
                    path,
                )
            self.volume.write_file(vpath, b"")
            self._file_buffers[vpath] = bytearray()
            fd = self._next_fd()
            self._open_files[fd] = vpath
        return fd

    def _chunk_key(self, vpath: str, chunk_index: int) -> str:
        """LRU cache key for one decrypted chunk of *vpath*.

        NUL never appears in a validated vpath, so the key space can't
        collide with another path — and every chunk key of a path (or of
        a whole directory subtree) is droppable via invalidate_prefix.
        """
        return f"{vpath}\x00{chunk_index}"

    def _invalidate_cached(self, vpath: str) -> None:
        """Drop all cached decrypted chunks for *vpath*."""
        self.cache.invalidate_prefix(vpath + "\x00")

    def open(self, path: str, flags: int) -> int:
        """Open a file and return a file descriptor.

        Does NOT materialize the plaintext: reads decrypt only the chunks
        they touch (read_file_range), so opening a 500 MB file is O(1)
        instead of a multi-second stall.  The full buffer is created
        lazily by the first write()/truncate() on the file.
        """
        vpath = self._vpath(path)
        # POSIX: after unlink(), the pathname is unusable even for new
        # opens — the existing fds keep their view of the inode via fh,
        # but a fresh open(path) must fail.  Without this guard a second
        # open() aliases the same vpath-keyed _file_buffers and the final
        # release() would discard the new fd's writes under volume.delete.
        with self._lock:
            if vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)
        entry = self.volume.get_entry(vpath)
        if entry is None:
            raise OSError(errno.ENOENT, "No such file", path)

        fd = self._next_fd()
        with self._lock:
            self._open_files[fd] = vpath
        return fd

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        """Read data from a file.

        A live write buffer (file being modified, or freshly created) is
        authoritative.  Otherwise decrypt just the chunks covering the
        range, through a chunk-granular LRU cache — sequential readers and
        seek-happy tools (media players, archive listers) hit the cache
        for re-read chunks without ever materializing the whole file.
        Per-chunk AES-GCM tags + AAD authenticate everything returned
        (whole-file SHA-256 stays available via read_file(verify_hash=True)).
        """
        vpath = self._vpath(path)
        with self._lock:
            buf = self._file_buffers.get(vpath)
            if buf is not None:
                return bytes(buf[offset:offset + size])

            entry = self.volume.get_entry(vpath)
            if entry is None:
                raise OSError(errno.ENOENT, "No such file", path)
            fsize = entry.get("size", 0)
            if size <= 0 or offset >= fsize:
                return b""
            end = min(offset + size, fsize)
            chunk_size = self.volume.metadata.get(
                "chunk_size", VOLUME_CHUNK_SIZE)
            first = offset // chunk_size
            last = (end - 1) // chunk_size
            parts: list[bytes] = []
            for ci in range(first, last + 1):
                key = self._chunk_key(vpath, ci)
                data = self.cache.get(key)
                if data is None:
                    data = self.volume.read_file_range(
                        vpath, ci * chunk_size, chunk_size)
                    self.cache.put(key, data)
                parts.append(data)
            plain = b"".join(parts)
            rel = offset - first * chunk_size
            return plain[rel:rel + (end - offset)]

    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        """Write data to a file."""
        vpath = self._vpath(path)
        with self._lock:
            buf = self._file_buffers.get(vpath)
            if buf is None:
                # First write on an untouched file: open() no longer
                # eagerly decrypts, so materialize the existing plaintext
                # here — starting from an empty buffer would zero
                # everything outside this write's range.
                entry = self.volume.get_entry(vpath)
                if entry is not None and entry.get("type") != "dir":
                    buf = bytearray(
                        self.volume.read_file(vpath, verify_hash=False))
                else:
                    buf = bytearray()
                self._file_buffers[vpath] = buf

            # Extend buffer if writing past end
            end = offset + len(data)
            # The write path holds roughly 4x the file in RAM (buffer,
            # bytes() snapshot, per-chunk ciphertext list, joined result), so
            # a large enough file dies with a MemoryError mid-write and
            # flush()'s journal append never happens. Refusing up front with
            # EFBIG is a real error the user's tools understand, and unlike a
            # statfs cap it does not misreport the size of the volume.
            # The durable fix is chunk-granular writes (format v3, queued).
            ceiling = _max_writable_bytes()
            if end > ceiling:
                raise OSError(
                    errno.EFBIG,
                    f"File would exceed this volume's {ceiling // (1 << 20)} MB "
                    "single-file limit (the encrypt path buffers it in memory)",
                    path,
                )
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
        if fh is None:
            # Path-based truncate (no open fd): nothing will flush this
            # buffer later, so persist it now like a flush would.
            self.flush(path, 0)

    def flush(self, path: str, fh: int) -> None:
        """Flush dirty data to the volume container and persist to disk."""
        vpath = self._vpath(path)
        with self._lock:
            if vpath in self._dirty_files:
                # If the file was unlink()ed while still open, a write to
                # its fd goes to the inode-that-no-longer-has-a-name and
                # should NOT be persisted — the last close will drop it.
                if vpath not in self._pending_unlink:
                    buf = self._file_buffers.get(vpath, bytearray())
                    snapshot = bytes(buf)
                    # A write that leaves the bytes identical to what the
                    # container already holds (editors re-saving unchanged
                    # files, periodic fsync from rsync/databases) must not
                    # re-encrypt and append the whole file to the journal
                    # again: compare the plaintext hash with the stored one.
                    entry = self.volume.get_entry(vpath)
                    unchanged = (
                        entry is not None
                        and entry.get("type") != "dir"
                        and entry.get("size") == len(snapshot)
                        and entry.get("content_hash")
                        and entry["content_hash"] == hashlib.sha256(snapshot).hexdigest()
                    )
                    if not unchanged:
                        self.volume.write_file(vpath, snapshot)
                        # Chunks cached from the previous content are stale now.
                        self._invalidate_cached(vpath)
                self._dirty_files.discard(vpath)
            self._persist_locked()

    def fsync(self, path: str, datasync: int, fh: int) -> int:
        """Force file data to stable storage (flush + journal append)."""
        self.flush(path, fh)
        return 0

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
                    self._invalidate_cached(vpath)
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
                    self._invalidate_cached(vpath)
                    self._dirty_files.discard(vpath)
            self._persist_locked()

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
            self._invalidate_cached(vpath)
            self._dirty_files.discard(vpath)
            self._persist_locked()

    def rename(self, old: str, new: str) -> None:
        """Rename a file or directory (subtree re-keyed for directories)."""
        old_vp = self._vpath(old)
        new_vp = self._vpath(new)
        with self._lock:
            # POSIX: the source pathname is unusable after unlink().
            # Rename of an unlinked-but-open path must behave like the
            # source doesn't exist.
            if old_vp in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", old)
            # POSIX no-op, mirroring the container-level guard.  Without
            # this, the file branch below pops the destination buffer —
            # which IS the source's — and discards its dirty flag before
            # re-keying, silently losing every unflushed write.
            if new_vp == old_vp:
                return
            # Destination held by an unlinked-but-still-open file: our
            # buffers are vpath-keyed (same reasoning as create()), so
            # letting the rename land would corrupt the old fds' view and
            # the deferred delete on their last close would destroy the
            # freshly renamed file.  Refuse until those fds close.
            if new_vp in self._pending_unlink:
                raise OSError(
                    errno.EBUSY,
                    "Destination was unlinked but still has open fds", new)
            is_dir = (
                self.volume.get_entry(old_vp) is None
                and self.volume.get_entry(self._dir_vpath(old)) is not None
            )
            if is_dir:
                old_prefix = self._dir_vpath(old)
                new_prefix = self._dir_vpath(new)
                # A pending-unlink child still has open fds whose deferred
                # delete is keyed to the old path — renaming the parent
                # would strand the entry under its new name.
                if any(vp.startswith(old_prefix)
                       for vp in self._pending_unlink):
                    raise OSError(
                        errno.EBUSY,
                        "Directory contains unlinked files with open fds",
                        old)
                self.volume.rename(old_vp, new_vp)
                for vp in [v for v in self._file_buffers
                           if v.startswith(old_prefix)]:
                    self._file_buffers[new_prefix + vp[len(old_prefix):]] = \
                        self._file_buffers.pop(vp)
                for vp in [v for v in self._dirty_files
                           if v.startswith(old_prefix)]:
                    self._dirty_files.discard(vp)
                    self._dirty_files.add(new_prefix + vp[len(old_prefix):])
                # fd → vpath tracking must follow too: release()/unlink()
                # compare these values against the path the kernel passes
                # AFTER the rename, and a stale value silently disables
                # the deferred-unlink machinery for open children.
                for fd_key, vp in self._open_files.items():
                    if vp.startswith(old_prefix):
                        self._open_files[fd_key] = \
                            new_prefix + vp[len(old_prefix):]
                self.cache.invalidate_prefix(old_prefix)
            else:
                self.volume.rename(old_vp, new_vp)
                # A replaced destination's buffered/cached content is gone;
                # drop it before re-keying the source's buffer into place.
                self._file_buffers.pop(new_vp, None)
                self._dirty_files.discard(new_vp)
                self._invalidate_cached(new_vp)
                if old_vp in self._file_buffers:
                    self._file_buffers[new_vp] = self._file_buffers.pop(old_vp)
                self._invalidate_cached(old_vp)
                if old_vp in self._dirty_files:
                    self._dirty_files.discard(old_vp)
                    self._dirty_files.add(new_vp)
                # Re-key open-fd tracking (see the dir branch for why).
                for fd_key, vp in self._open_files.items():
                    if vp == old_vp:
                        self._open_files[fd_key] = new_vp
            self._persist_locked()

    def chmod(self, path: str, mode: int) -> int:
        """Update mode, journaled so it survives unmount."""
        with self._lock:
            if not self.volume.set_attrs(self._vpath(path), mode=mode):
                raise OSError(errno.ENOENT, "No such file or directory", path)
        return 0

    def utimens(self, path: str, times: tuple | None = None) -> int:
        """Update mtime, journaled so it survives unmount.

        This is what cp -p, rsync -t, unzip, tar -x and Finder issue after
        writing a file, so dropping it silently re-stamped every copied file
        with its copy time and broke incremental sync.
        """
        mtime = int(times[1]) if times else int(time.time())
        with self._lock:
            if not self.volume.set_attrs(self._vpath(path), mtime=mtime):
                raise OSError(errno.ENOENT, "No such file or directory", path)
        return 0

    def save_all_dirty(self, apply_pending_unlink: bool = True,
                       lock_timeout: float | None = None) -> None:
        """Flush all dirty FUSE buffers to the volume, then persist the volume.

        Acquires the FUSE ops lock so this cannot race with an in-flight
        flush(), release(), write(), or other FS operation.  Used by
        unmount_volume() and _emergency_save_all() to ensure the volume on
        disk reflects the latest buffered writes.  Without this, an unmount
        or signal-driven shutdown could persist stale volume data even though
        the user's writes had already been accepted.

        Mirrors flush() / release(): writes to a path in ``_pending_unlink``
        are intentionally NOT persisted — the unlink-while-open semantics
        require the data to vanish on last close, and shutdown happens
        before release() has a chance to run the deferred delete.  Without
        this guard an editor's swap file (classic create + unlink + keep
        writing pattern) would be silently resurrected in the encrypted
        container on the next mount.

        ``apply_pending_unlink`` must be True only when shutdown is
        certain (exit/signal paths).  A caller that might CONTINUE serving
        afterwards — unmount_volume before its OS unmount, whose failure
        leaves the mount live — passes False: clearing the limbo set on a
        still-serving mount lets a later flush on the still-open fd write
        the deleted file straight back into the container.
        """
        if lock_timeout is None:
            self._lock.acquire()
        elif not self._lock.acquire(timeout=lock_timeout):
            # Signal path only. Skipping this volume leaves it exactly as a
            # SIGKILL would; hanging here would lose every other volume too.
            logger.warning(
                "Emergency save: could not acquire the lock for %s within "
                "%.1fs — skipping (a filesystem operation is still running)",
                self.volume.path, lock_timeout,
            )
            return
        try:
            for vpath in list(self._dirty_files):
                if vpath in self._pending_unlink:
                    continue
                buf = self._file_buffers.get(vpath, bytearray())
                snapshot = bytes(buf)
                self.volume.write_file(vpath, snapshot)
                self._invalidate_cached(vpath)
            self._dirty_files.clear()
            if apply_pending_unlink:
                self.apply_pending_unlinks()
            elif self.volume.is_dirty:
                self.volume.save()
        finally:
            self._lock.release()

    def apply_pending_unlinks(self) -> None:
        """Apply deferred unlinks whose fds will never see release().

        Call only once shutdown is certain (successful unmount, exit and
        signal paths).  The volume.delete() here is safe: if the path
        still has open fds, the kernel's subsequent release() will be a
        no-op for the delete (vpath already gone from dir_index).
        """
        with self._lock:
            for vpath in list(self._pending_unlink):
                try:
                    self.volume.delete(vpath)
                except FileNotFoundError:
                    pass
                self._invalidate_cached(vpath)
            self._pending_unlink.clear()
            if self.volume.is_dirty:
                self.volume.save()


# ── Mount / Unmount API ─────────────────────────────────────────────────────

_mounted_volumes: dict[str, dict] = {}  # mount_point → {thread, volume, fuse_obj}
# Serialises mount_volume() / unmount_volume() mutations of _mounted_volumes
# so concurrent UI clicks or scripted mounts can't observe torn state.
_mount_lock = threading.Lock()
# mount_point → fd holding the cross-process flock for that mount
_volume_locks: dict[str, int] = {}


def _acquire_volume_lock(volume_path: str) -> int:
    """Advisory cross-process lock held for the life of a mount.

    The in-process double-mount guard can't see a second app instance or
    a script: two processes appending to one journal truncate each
    other's records (both do seek(_journal_end); truncate() with
    diverging bookkeeping).  A sidecar ``<volume>.lock`` file is flocked
    LOCK_EX|LOCK_NB — the .qcv itself cannot carry the lock because
    compact() replaces its inode via os.replace(), which would silently
    release an flock held on the old inode.  The 0-byte sidecar is never
    deleted (unlinking it would race a concurrent locker onto a fresh,
    unlocked inode).

    Returns the open fd (closing it releases the lock; process exit
    releases it automatically).  Raises RuntimeError when another
    process holds it.
    """
    import fcntl
    # Canonicalize: a symlinked or differently-spelled path to the same
    # volume must contend for the SAME lock file, or the guard is
    # bypassable by aliasing.
    lock_path = os.path.realpath(volume_path) + ".lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise RuntimeError(
            "Volume appears to be mounted by another process "
            f"(lock held on {os.path.basename(lock_path)}). "
            "Unmount it there first."
        )
    return fd


def _release_volume_lock(mount_point: str) -> None:
    fd = _volume_locks.pop(mount_point, None)
    if fd is not None:
        try:
            os.close(fd)  # closing the fd releases the flock
        except OSError:
            pass


def _reap_dead_mounts_locked() -> None:
    """Drop tracking for mounts whose FUSE worker has exited.

    Caller must hold ``_mount_lock``.  An external eject (Finder,
    ``umount``, backend crash) ends the worker thread without ever going
    through unmount_volume(): the tracking entry and its cross-process
    flock would otherwise persist for the process lifetime — every
    remount of that volume fails with "mounted by another process" and
    the UI keeps listing a mount that no longer exists.  Best-effort
    save first: the kernel flushed on eject via release(), but buffered
    volume state may remain.  Entries with ``thread`` None (direct API /
    test injection) are left alone — liveness is unknowable for them.
    """
    for mp, info in list(_mounted_volumes.items()):
        t = info.get("thread")
        if t is None or t.is_alive():
            continue
        logger.warning(
            "Mount at %s ended outside unmount_volume (external eject?); "
            "reclaiming its tracking entry and lock", mp)
        try:
            fuse_obj = info.get("fuse")
            if fuse_obj is not None:
                fuse_obj.save_all_dirty(apply_pending_unlink=True)
            elif info["volume"].is_dirty:
                info["volume"].save()
        except Exception:
            logger.exception("Post-eject save failed for %s", mp)
        _mounted_volumes.pop(mp, None)
        _release_volume_lock(mp)

# How long mount_volume() waits for the FUSE worker to either successfully
# start serving or fail synchronously.  If FUSE() raises (missing backend,
# unwritable mount point, busy target) the thread dies inside this window
# and we propagate the exception instead of registering a zombie mount.
_FUSE_STARTUP_TIMEOUT = 2.0
# Bound on the external unmount tool. Held under _mount_lock, so an
# unbounded call here blocks every other mount operation in the process.
_UNMOUNT_TIMEOUT = 30.0

#: How much of a file the write path holds in RAM at once, as a multiple of
#: its size: the write buffer, the bytes() snapshot, the per-chunk ciphertext
#: list, and the joined result.
_WRITE_MEMORY_FACTOR = 4


def _max_writable_bytes() -> int:
    """Largest file the in-memory write path can be expected to handle."""
    try:
        total_ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 1 << 40      # unknown: do not constrain
    # Half of physical memory, divided by the copies the write path makes.
    return max(total_ram // 2 // _WRITE_MEMORY_FACTOR, 64 * 1024 * 1024)

# ── Graceful shutdown ──────────────────────────────────────────────────────

_atexit_registered = False
_signals_registered = False
_shutdown_lock = threading.Lock()


def _emergency_save_all(lock_timeout: float | None = None) -> None:
    """Save all dirty mounted volumes.

    Called by atexit and signal handlers to prevent data loss on
    app exit or crash.  Routes through QuantaCryptFUSE.save_all_dirty()
    so that buffered writes not yet flushed are still persisted.
    Errors are logged but never raised so that the shutdown sequence
    is not interrupted.

    ``lock_timeout`` bounds each volume's lock acquisition; the signal path
    passes one so a FUSE worker holding the lock cannot hang the process.
    atexit passes None, because there it is safe to wait.
    """
    for mp in list(_mounted_volumes):
        info = _mounted_volumes.get(mp)
        if info is None:
            continue
        try:
            fuse_obj = info.get("fuse")
            if fuse_obj is not None:
                logger.info("Shutdown: saving dirty state for volume at %s", mp)
                fuse_obj.save_all_dirty(lock_timeout=lock_timeout)
            else:
                vc = info["volume"]
                if vc.is_dirty:
                    vc.save()
        except Exception:
            logger.exception("Shutdown: failed to save volume at %s", mp)


#: How long the signal path waits for a volume's lock before giving up on
#: that volume. Python runs signal handlers on the main thread between
#: bytecodes, so an unbounded acquire here hangs the whole process when a
#: FUSE worker is mid-write — the caller then escalates to SIGKILL and the
#: buffer is lost, which is the exact outcome this handler exists to prevent.
_SIGNAL_SAVE_TIMEOUT = 2.0


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM / SIGINT by saving volumes then re-raising.

    Bounded, not best-effort-forever: see _SIGNAL_SAVE_TIMEOUT. A volume
    whose lock cannot be taken in time is skipped and logged rather than
    hanging the process; its data is no worse off than under SIGKILL.

    NOTE: qc-core never reaches this. `_ensure_shutdown_handlers` is only
    ever called from a worker thread there, so `signal.signal` raises
    ValueError and the signal half stays unlatched, leaving cli.py's own
    handler (which sets a flag and lets the main loop unmount) in charge.
    That is load-bearing — a future synchronous startup remount from the
    helper's main thread would silently replace it with this one.
    """
    _emergency_save_all(lock_timeout=_SIGNAL_SAVE_TIMEOUT)
    # Re-raise with default handler so the process actually exits
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def _ensure_shutdown_handlers() -> None:
    """Register atexit + signal handlers (each once, independently).

    The two halves latch separately: signal.signal() only works on the
    main thread, and mounts from the GUI always run on a worker.  With a
    single latch the worker's failed signal install was recorded as done
    and SIGTERM never saved anything (atexit does not run on SIGTERM).
    Now the signal half stays unlatched until a main-thread call — such
    as install_shutdown_handlers() at app startup — succeeds; every
    mount retries it, so script/CLI main-thread mounts self-heal too.
    """
    global _atexit_registered, _signals_registered  # noqa: PLW0603
    with _shutdown_lock:
        if not _atexit_registered:
            atexit.register(_emergency_save_all)
            _atexit_registered = True
        if not _signals_registered:
            try:
                signal.signal(signal.SIGTERM, _signal_handler)
                signal.signal(signal.SIGINT, _signal_handler)
                _signals_registered = True
            except ValueError:
                # Not the main thread — leave unlatched so a later
                # main-thread call can install the handlers.
                pass


def install_shutdown_handlers() -> None:
    """Install the emergency-save handlers from the main thread.

    Call once at app startup (the GUI's main() does).  Safe to call from
    any thread — off-main-thread the signal half simply stays pending.
    """
    _ensure_shutdown_handlers()


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

    # Fast-path double-mount guard.  Snapshot the dict under the lock so
    # we never iterate a dict that a concurrent mount / unmount might
    # resize ("RuntimeError: dictionary changed size during iteration").
    # The lock-held re-check below is the race-safe guarantee against
    # double-registration; this snapshot is just for the fast error.
    # Reap externally-ended mounts first so an ejected volume doesn't
    # block its own remount forever.
    with _mount_lock:
        _reap_dead_mounts_locked()
        _mounted_snapshot = list(_mounted_volumes.items())
    for mp, info in _mounted_snapshot:
        if os.path.realpath(info["volume_path"]) == real_vol:
            raise RuntimeError(
                f"Volume is already mounted at {mp}. "
                "Unmount it first before mounting again."
            )

    available, msg = check_fuse_available()
    if not available:
        raise RuntimeError(msg)

    from fuse import FUSE  # type: ignore[import-untyped]

    # Cross-process guard: acquire the flock BEFORE the container reads
    # its journal bookkeeping.  Opening first would let a mount racing
    # another process's unmount snapshot a stale _journal_end and, once
    # it wins the lock, truncate records the other process committed in
    # between.  Held from here until handed to _volume_locks (background
    # success) or closed (foreground return / any failure).
    lock_fd = _acquire_volume_lock(volume_path)
    lock_owned = True
    try:
        # Open the volume (under the cross-process lock)
        vc = VolumeContainer(volume_path, final_key)
        vc.open()

        # Create mount point if needed
        os.makedirs(mount_point, exist_ok=True)

        fuse_obj = QuantaCryptFUSE(vc, cache_mb=cache_mb)

        if foreground:
            FUSE(fuse_obj, mount_point, foreground=True, nothreads=True,
                 allow_other=False, volname="QuantaCrypt")
            return fuse_obj  # finally releases the lock post-unmount

        # Background mount: wait for FUSE to either start serving or fail
        # synchronously, and only register _mounted_volumes on success.
        # Registering unconditionally would leave a zombie entry after a
        # failed FUSE startup (missing FUSE-T, busy mount point), and a
        # later unmount_volume() would run diskutil / fusermount against
        # a path we never actually mounted.
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

        # The duplicate check, worker start, and registration must be one
        # atomic step under _mount_lock.  With the check outside the lock,
        # two racers could both pass it and both spawn live mounts on the
        # same .qcv — the loser's raise then left a serving, UNTRACKED
        # mount (unreachable by unmount / emergency save) whose journal
        # appends interleave with the winner's truncate+write sequences
        # and corrupt the container.  mount/unmount are already fully
        # serialised elsewhere; holding the lock for the ≤2 s startup
        # window is fine for a single-user app.
        with _mount_lock:
            for mp, info in _mounted_volumes.items():
                if os.path.realpath(info["volume_path"]) == real_vol:
                    raise RuntimeError(
                        f"Volume is already mounted at {mp}. "
                        "Unmount it first before mounting again."
                    )

            t = threading.Thread(target=_run, daemon=True)
            t.start()

            # A live FUSE() blocks serving requests, so `ready` — set in the
            # worker's finally — is the authoritative signal: if it fires
            # inside the startup window, FUSE() returned or raised and the
            # mount is NOT up.
            #
            # This used to test `t.is_alive()` instead, which is a race: the
            # worker sets `ready` and then still has to unwind before it
            # stops being alive, so the main thread could observe a live
            # thread for an already-failed mount and register it. macOS
            # happened to lose that scheduling race and Linux won it, which
            # is why two mount tests passed locally and failed on CI with
            # "DID NOT RAISE".
            failed_fast = ready.wait(timeout=_FUSE_STARTUP_TIMEOUT)
            if failed_fast:
                if startup_error:
                    raise RuntimeError(
                        f"FUSE mount failed: {startup_error[0]}"
                    ) from startup_error[0]
                raise RuntimeError(
                    "FUSE worker thread exited before the mount was "
                    "established"
                )

            _mounted_volumes[mount_point] = {
                "thread": t,
                "volume": vc,
                "fuse": fuse_obj,
                "volume_path": volume_path,
            }
            _volume_locks[mount_point] = lock_fd
            lock_owned = False

        return fuse_obj
    finally:
        if lock_owned:
            os.close(lock_fd)


def unmount_volume(mount_point: str) -> None:
    """Unmount a volume and save any pending changes.

    Saves dirty data (including buffered FUSE writes) **before** removing
    from the tracking dict so that ``_emergency_save_all`` can still reach
    the volume if save() fails.  The external unmount subprocess is only
    invoked for paths we actually own — we do not run diskutil/fusermount
    against an arbitrary path passed in by a caller.

    The whole body runs under ``_mount_lock``.  If we dropped the lock
    between ``pop`` and the ``diskutil`` / ``fusermount`` subprocess, a
    concurrent ``mount_volume()`` for a different volume at the same
    mount_point could slot in its fresh mount — and our still-in-flight
    subprocess would then tear down the new one.  Holding the lock makes
    mount/unmount fully serialised, which matches the UI's
    single-user-at-a-time intent.
    """
    import subprocess
    import sys

    with _mount_lock:
        _reap_dead_mounts_locked()
        info = _mounted_volumes.get(mount_point)
        if info is None:
            raise ValueError(
                f"No QuantaCrypt volume is tracked at {mount_point!r} — "
                "refusing to run unmount against a path we do not own"
            )

        # Save state *before* anything else so that if save_all_dirty()
        # fails, _emergency_save_all can still find the volume for a retry.
        # Deferred unlinks are NOT applied yet: if the OS unmount below
        # fails, the mount keeps serving, and a cleared limbo set would
        # let a later flush resurrect the deleted files.
        fuse_obj = info.get("fuse")
        if fuse_obj is not None:
            fuse_obj.save_all_dirty(apply_pending_unlink=False)
        elif info["volume"].is_dirty:
            info["volume"].save()

        # Use platform-appropriate unmount.  Still under the lock so a
        # concurrent remount at the same mount_point can't race our
        # subprocess into tearing down the new mount.
        if sys.platform == "darwin":
            cmd = ["diskutil", "unmount", mount_point]
        else:
            # Some distros ship only fusermount3 (libfuse3).
            import shutil
            tool = "fusermount3" if shutil.which("fusermount3") else "fusermount"
            cmd = [tool, "-u", mount_point]
        # Bounded: this runs while _mount_lock is held, so a diskutil that
        # never returns (wedged FUSE mount, busy filesystem) would pin the
        # lock forever and block every later mount, unmount, list and the
        # service's own shutdown loop. A timeout is treated as a failed
        # unmount, which is exactly the branch below.
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=_UNMOUNT_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Unmount of {mount_point} timed out after {_UNMOUNT_TIMEOUT}s — "
                "the volume may be in use by another application"
            ) from None
        if result.returncode != 0:
            # The volume is still mounted and serving — keep it tracked so
            # emergency save and a retry can reach it, and so the double-
            # mount guard keeps a second writer off this journal.
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                f"Unmount of {mount_point} failed"
                f"{': ' + detail if detail else ''} — "
                "the volume may be in use by another application"
            )

        # Shutdown of this mount is now certain: apply the deferred
        # unlinks the pre-unmount save intentionally skipped (a clean
        # unmount usually already ran them via release(); this covers
        # fds that never saw one).  Tracking and the flock are dropped in
        # a finally — a failure in the unlink application must not strand
        # a permanently-tracked, permanently-locked entry for a mount the
        # OS has already torn down.
        try:
            if fuse_obj is not None:
                fuse_obj.apply_pending_unlinks()
        finally:
            _mounted_volumes.pop(mount_point, None)
            _release_volume_lock(mount_point)


def get_mounted_volumes() -> dict[str, dict]:
    """Return dict of currently mounted volumes: mount_point → info.

    Reaps externally-ended mounts first so callers (the Volume Manager
    list, the create-guard) see reality, not stale tracking.
    """
    with _mount_lock:
        _reap_dead_mounts_locked()
        return dict(_mounted_volumes)
