"""Tests for QuantaCrypt encrypted volume (.qcv) feature."""

import base64
import hashlib
import json
import os
import struct
import tempfile

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import volume as vol


# ── Header tests ────────────────────────────────────────────────────────────

class TestVolumeHeader:

    def test_write_and_read_header(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.qcv")
        vid = os.urandom(16)
        mn = os.urandom(12)
        dn = os.urandom(12)

        with open(path, "wb") as f:
            vol.write_header(f, vid, mn, dn)
            # Pad to make a valid file
            f.write(b"\x00" * 100)

        with open(path, "rb") as f:
            h = vol.read_header(f)

        assert h["version"] == vol.VOLUME_FORMAT_VERSION
        assert h["volume_id"] == vid
        assert h["meta_nonce"] == mn
        assert h["dir_nonce"] == dn

    def test_bad_magic_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad.qcv")
        with open(path, "wb") as f:
            f.write(b"\x00" * vol.HEADER_SIZE)

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="bad magic"):
                vol.read_header(f)

    def test_too_small_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "tiny.qcv")
        with open(path, "wb") as f:
            f.write(b"QCVOL\x01")  # only 6 bytes

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="too small"):
                vol.read_header(f)

    def test_unsupported_version_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "future.qcv")
        header = bytearray(vol.HEADER_SIZE)
        header[0:6] = vol.VOLUME_MAGIC
        struct.pack_into(">I", header, 6, 999)  # future version
        with open(path, "wb") as f:
            f.write(bytes(header))

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="Unsupported volume format"):
                vol.read_header(f)


# ── Encrypted block tests ──────────────────────────────────────────────────

class TestEncryptedBlocks:

    def test_write_read_roundtrip(self, tmp_dir):
        path = os.path.join(tmp_dir, "block.bin")
        data = os.urandom(1024)
        with open(path, "wb") as f:
            written = vol._write_encrypted_block(f, data)
        assert written == 4 + len(data)

        with open(path, "rb") as f:
            result = vol._read_encrypted_block(f)
        assert result == data

    def test_read_truncated_length(self, tmp_dir):
        path = os.path.join(tmp_dir, "trunc.bin")
        with open(path, "wb") as f:
            f.write(b"\x00\x00")  # only 2 bytes instead of 4

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="block length"):
                vol._read_encrypted_block(f)

    def test_read_truncated_data(self, tmp_dir):
        path = os.path.join(tmp_dir, "trunc2.bin")
        with open(path, "wb") as f:
            f.write(struct.pack(">I", 1000))  # claims 1000 bytes
            f.write(b"\x00" * 10)  # only 10

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="block data"):
                vol._read_encrypted_block(f)


# ── Metadata encryption ────────────────────────────────────────────────────

class TestMetadataEncryption:

    def test_roundtrip(self):
        key = os.urandom(64)
        meta = {"mode": "single", "version": 1, "chunk_size": 65536}
        nonce, ct = vol.encrypt_metadata(key, meta)
        result = vol.decrypt_metadata(key, nonce, ct)
        assert result == meta

    def test_wrong_key_fails(self):
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        meta = {"test": "data"}
        nonce, ct = vol.encrypt_metadata(key1, meta)
        with pytest.raises(Exception):
            vol.decrypt_metadata(key2, nonce, ct)

    def test_tampered_ct_fails(self):
        key = os.urandom(64)
        meta = {"test": "data"}
        nonce, ct = vol.encrypt_metadata(key, meta)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            vol.decrypt_metadata(key, nonce, bytes(tampered))


# ── Directory index encryption ──────────────────────────────────────────────

class TestDirectoryEncryption:

    def test_roundtrip(self):
        key = os.urandom(64)
        dir_index = {
            "/hello.txt": {"type": "file", "size": 100, "mode": 0o100644},
            "/subdir/": {"type": "dir", "mode": 0o40755},
        }
        nonce, ct = vol.encrypt_directory(key, dir_index)
        result = vol.decrypt_directory(key, nonce, ct)
        assert result == dir_index

    def test_empty_directory(self):
        key = os.urandom(64)
        nonce, ct = vol.encrypt_directory(key, {})
        result = vol.decrypt_directory(key, nonce, ct)
        assert result == {}

    def test_nested_structure(self):
        key = os.urandom(64)
        deep = {
            "/a/b/c/d.txt": {"type": "file", "size": 1},
            "/a/b/c/": {"type": "dir", "mode": 0o40755},
            "/a/b/": {"type": "dir", "mode": 0o40755},
            "/a/": {"type": "dir", "mode": 0o40755},
        }
        nonce, ct = vol.encrypt_directory(key, deep)
        result = vol.decrypt_directory(key, nonce, ct)
        assert result == deep


# ── File data encryption ────────────────────────────────────────────────────

class TestFileDataEncryption:

    def test_roundtrip_small_file(self):
        key = os.urandom(64)
        data = b"Hello, encrypted volume!"
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 1
        assert sha == hashlib.sha256(data).hexdigest()
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_roundtrip_empty_file(self):
        key = os.urandom(64)
        data = b""
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 1
        assert sha == hashlib.sha256(b"").hexdigest()
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_roundtrip_multi_chunk(self):
        key = os.urandom(64)
        # Make data larger than VOLUME_CHUNK_SIZE (64 KB)
        data = os.urandom(vol.VOLUME_CHUNK_SIZE * 3 + 1234)
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 4  # 3 full chunks + 1 partial
        assert sha == hashlib.sha256(data).hexdigest()
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_roundtrip_exact_chunk_boundary(self):
        key = os.urandom(64)
        data = os.urandom(vol.VOLUME_CHUNK_SIZE * 2)
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 2
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_wrong_key_fails(self):
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        data = b"secret data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key1)
        with pytest.raises(ValueError, match="Authentication failed"):
            vol.decrypt_file_data(blob, key2, nonce, count)

    def test_tampered_blob_fails(self):
        key = os.urandom(64)
        data = b"secret data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key)
        tampered = bytearray(blob)
        tampered[12] ^= 0xFF
        with pytest.raises(ValueError):
            vol.decrypt_file_data(bytes(tampered), key, nonce, count)

    def test_truncated_blob_fails(self):
        key = os.urandom(64)
        data = b"test data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key)
        # Truncate to just the header of first chunk
        with pytest.raises(ValueError, match="truncated"):
            vol.decrypt_file_data(blob[:6], key, nonce, count)

    def test_truncated_header_fails(self):
        key = os.urandom(64)
        data = b"test data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key)
        with pytest.raises(ValueError, match="truncated"):
            vol.decrypt_file_data(blob[:4], key, nonce, count)

    def test_custom_chunk_size(self):
        key = os.urandom(64)
        data = os.urandom(500)
        nonce, blob, count, sha = vol.encrypt_file_data(data, key, chunk_size=100)
        assert count == 5
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data


# ── Volume creation (password mode) ────────────────────────────────────────

class TestCreateVolumeSingle:

    def test_create_and_open(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.qcv")
        password = "test-password-123"

        progress = []
        meta = vol.create_volume_single(path, password, progress_cb=progress.append)

        assert meta["mode"] == "single"
        assert meta["format_version"] == vol.VOLUME_FORMAT_VERSION
        assert os.path.isfile(path)
        assert len(progress) > 0

        # Derive key and open
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        assert vc.dir_index == {}
        assert vc.metadata["mode"] == "single"

    def test_wrong_password_fails(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.qcv")
        meta = vol.create_volume_single(path, "correct")

        with pytest.raises(Exception):
            vol.derive_volume_key_single("wrong", meta)


# ── Volume creation (Shamir mode) ──────────────────────────────────────────

class TestCreateVolumeShamir:

    def test_create_and_open(self, tmp_dir):
        path = os.path.join(tmp_dir, "shamir.qcv")
        progress = []
        meta, shares = vol.create_volume_shamir(path, n=3, k=2,
                                                 progress_cb=progress.append)

        assert meta["mode"] == "shamir"
        assert meta["threshold"] == 2
        assert meta["total"] == 3
        assert len(shares) == 3
        assert len(progress) > 0

        # Open with threshold shares
        final_key = vol.derive_volume_key_shamir(shares[:2], meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        assert vc.dir_index == {}

    def test_any_k_of_n_shares_work(self, tmp_dir):
        path = os.path.join(tmp_dir, "shamir.qcv")
        meta, shares = vol.create_volume_shamir(path, n=5, k=3)

        # Try shares 0,1,2
        key1 = vol.derive_volume_key_shamir(shares[:3], meta)
        # Try shares 2,3,4
        key2 = vol.derive_volume_key_shamir(shares[2:5], meta)
        assert key1 == key2

    def test_insufficient_shares_fail(self, tmp_dir):
        path = os.path.join(tmp_dir, "shamir.qcv")
        meta, shares = vol.create_volume_shamir(path, n=3, k=2)

        with pytest.raises(Exception):
            # Only 1 share when 2 needed — recovery gives wrong key
            key = vol.derive_volume_key_shamir(shares[:1], meta)
            vc = vol.VolumeContainer(path, key)
            vc.open()  # should fail on decrypt


# ── VolumeContainer operations ──────────────────────────────────────────────

class TestVolumeContainer:

    @pytest.fixture
    def open_volume(self, tmp_dir):
        """Create and return an open VolumeContainer."""
        path = os.path.join(tmp_dir, "vol.qcv")
        password = "testpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return vc

    def test_write_and_read_file(self, open_volume):
        vc = open_volume
        data = b"Hello, volume!"
        vc.write_file("/hello.txt", data)
        assert vc.read_file("/hello.txt") == data

    def test_write_and_persist(self, open_volume, tmp_dir):
        vc = open_volume
        vc.write_file("/persist.txt", b"persisted data")
        vc.save()

        # Reopen from disk
        password = "testpw"
        meta = vc.metadata
        final_key = vol.derive_volume_key_single(password, meta)
        vc2 = vol.VolumeContainer(vc.path, final_key)
        vc2.open()
        assert vc2.read_file("/persist.txt") == b"persisted data"

    def test_list_dir_root(self, open_volume):
        vc = open_volume
        vc.write_file("/a.txt", b"a")
        vc.write_file("/b.txt", b"b")
        vc.mkdir("/subdir")
        entries = vc.list_dir("/")
        assert "a.txt" in entries
        assert "b.txt" in entries
        assert "subdir" in entries

    def test_list_dir_subdirectory(self, open_volume):
        vc = open_volume
        vc.mkdir("/docs")
        vc.write_file("/docs/readme.md", b"# Hello")
        vc.write_file("/docs/notes.txt", b"notes")
        entries = vc.list_dir("/docs")
        assert sorted(entries) == ["notes.txt", "readme.md"]

    def test_mkdir_idempotent(self, open_volume):
        vc = open_volume
        vc.mkdir("/test")
        vc.mkdir("/test")  # should not raise

    def test_delete_file(self, open_volume):
        vc = open_volume
        vc.write_file("/delete-me.txt", b"bye")
        assert vc.get_entry("/delete-me.txt") is not None
        vc.delete("/delete-me.txt")
        assert vc.get_entry("/delete-me.txt") is None

    def test_delete_nonexistent_raises(self, open_volume):
        with pytest.raises(FileNotFoundError):
            open_volume.delete("/nope.txt")

    def test_delete_nonempty_dir_raises(self, open_volume):
        vc = open_volume
        vc.mkdir("/stuff")
        vc.write_file("/stuff/file.txt", b"data")
        with pytest.raises(OSError, match="not empty"):
            vc.delete("/stuff/")

    def test_delete_empty_dir(self, open_volume):
        vc = open_volume
        vc.mkdir("/empty")
        vc.delete("/empty/")
        assert vc.get_entry("/empty/") is None

    def test_rename_file(self, open_volume):
        vc = open_volume
        vc.write_file("/old.txt", b"data")
        vc.rename("/old.txt", "/new.txt")
        assert vc.get_entry("/old.txt") is None
        assert vc.get_entry("/new.txt") is not None
        assert vc.read_file("/new.txt") == b"data"

    def test_rename_nonexistent_raises(self, open_volume):
        with pytest.raises(FileNotFoundError):
            open_volume.rename("/nope.txt", "/also-nope.txt")

    def test_rename_to_existing_raises(self, open_volume):
        vc = open_volume
        vc.write_file("/a.txt", b"a")
        vc.write_file("/b.txt", b"b")
        with pytest.raises(FileExistsError):
            vc.rename("/a.txt", "/b.txt")

    def test_read_nonexistent_raises(self, open_volume):
        with pytest.raises(FileNotFoundError):
            open_volume.read_file("/nope.txt")

    def test_read_directory_raises(self, open_volume):
        vc = open_volume
        vc.mkdir("/mydir")
        with pytest.raises(IsADirectoryError):
            vc.read_file("/mydir/")

    def test_stat(self, open_volume):
        vc = open_volume
        vc.write_file("/a.txt", b"hello")
        vc.write_file("/b.txt", b"world!")
        vc.mkdir("/dir")
        stats = vc.stat()
        assert stats["file_count"] == 2
        assert stats["dir_count"] == 1
        assert stats["total_plaintext_size"] == 11  # 5 + 6

    def test_is_dirty_tracking(self, open_volume):
        vc = open_volume
        assert not vc.is_dirty
        vc.write_file("/test.txt", b"data")
        assert vc.is_dirty
        vc.save()
        assert not vc.is_dirty

    def test_multiple_files_persist(self, open_volume, tmp_dir):
        vc = open_volume
        files = {
            "/file1.txt": b"content one",
            "/file2.bin": os.urandom(1024),
            "/sub/file3.dat": os.urandom(vol.VOLUME_CHUNK_SIZE + 500),
        }
        vc.mkdir("/sub")
        for path, data in files.items():
            vc.write_file(path, data)
        vc.save()

        # Reopen
        password = "testpw"
        final_key = vol.derive_volume_key_single(password, vc.metadata)
        vc2 = vol.VolumeContainer(vc.path, final_key)
        vc2.open()
        for path, data in files.items():
            assert vc2.read_file(path) == data

    def test_overwrite_file(self, open_volume):
        vc = open_volume
        vc.write_file("/test.txt", b"version 1")
        assert vc.read_file("/test.txt") == b"version 1"
        vc.write_file("/test.txt", b"version 2")
        assert vc.read_file("/test.txt") == b"version 2"

    def test_large_file_integrity(self, open_volume):
        vc = open_volume
        # Multi-chunk file
        data = os.urandom(vol.VOLUME_CHUNK_SIZE * 5 + 42)
        vc.write_file("/big.bin", data)
        assert vc.read_file("/big.bin") == data

    def test_save_atomic_no_corruption(self, open_volume, tmp_dir):
        """Verify save writes to temp file then renames."""
        vc = open_volume
        vc.write_file("/test.txt", b"data")

        # Check no .tmp file lingers after save
        vc.save()
        assert not os.path.exists(vc.path + ".tmp")
        assert os.path.isfile(vc.path)


# ── Key derivation tests ───────────────────────────────────────────────────

class TestKeyDerivation:

    def test_single_key_deterministic(self, tmp_dir):
        """Same password + same metadata → same key."""
        path = os.path.join(tmp_dir, "det.qcv")
        meta = vol.create_volume_single(path, "pw123")
        k1 = vol.derive_volume_key_single("pw123", meta)
        k2 = vol.derive_volume_key_single("pw123", meta)
        assert k1 == k2

    def test_shamir_key_from_different_share_combos(self, tmp_dir):
        """Different threshold-size subsets of shares → same key."""
        path = os.path.join(tmp_dir, "sk.qcv")
        meta, shares = vol.create_volume_shamir(path, n=5, k=3)
        k1 = vol.derive_volume_key_shamir(shares[0:3], meta)
        k2 = vol.derive_volume_key_shamir(shares[1:4], meta)
        k3 = vol.derive_volume_key_shamir(shares[2:5], meta)
        assert k1 == k2 == k3


# ── LRU Cache tests ──────────────────────────────────────────────────────

from quantacrypt.core.fuse_ops import (
    LRUCache,
    QuantaCryptFUSE,
    check_fuse_available,
    check_fuse_components,
    get_mounted_volumes,
)


# ── Auth params tests ─────────────────────────────────────────────────────

class TestAuthParams:

    def test_read_auth_params_single(self, tmp_dir):
        """read_volume_auth_params returns auth params for password volumes."""
        path = os.path.join(tmp_dir, "auth.qcv")
        vol.create_volume_single(path, "testpw")
        header, auth = vol.read_volume_auth_params(path)
        assert auth["mode"] == "single"
        assert "argon_salt" in auth
        assert "kyber_kem_ct" in auth
        assert "kyber_sk_enc_nonce" in auth
        assert "kyber_sk_enc" in auth

    def test_read_auth_params_shamir(self, tmp_dir):
        """read_volume_auth_params returns auth params for shamir volumes."""
        path = os.path.join(tmp_dir, "auth_sh.qcv")
        vol.create_volume_shamir(path, n=3, k=2)
        header, auth = vol.read_volume_auth_params(path)
        assert auth["mode"] == "shamir"
        assert auth["threshold"] == 2
        assert auth["total"] == 3
        assert "kyber_kem_ct" in auth

    def test_derive_key_from_auth_params(self, tmp_dir):
        """Can derive key using auth params read from volume file."""
        path = os.path.join(tmp_dir, "derive.qcv")
        password = "derive-test"
        meta = vol.create_volume_single(path, password)

        # Read auth params from file (no key needed)
        header, auth = vol.read_volume_auth_params(path)

        # Derive key using auth params instead of returned meta
        key = vol.derive_volume_key_single(password, auth)

        # Should be able to open the volume
        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc.metadata["mode"] == "single"

    def test_auth_params_persist_through_save(self, tmp_dir):
        """Auth params survive volume save/reopen cycle."""
        path = os.path.join(tmp_dir, "persist.qcv")
        password = "persistpw"
        meta = vol.create_volume_single(path, password)
        key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/test.txt", b"data")
        vc.save()

        # Read auth params from saved file
        _, auth_after = vol.read_volume_auth_params(path)
        assert auth_after["mode"] == "single"
        assert "argon_salt" in auth_after

        # Derive key from auth params and reopen
        key2 = vol.derive_volume_key_single(password, auth_after)
        vc2 = vol.VolumeContainer(path, key2)
        vc2.open()
        assert vc2.read_file("/test.txt") == b"data"


class TestLRUCache:

    def test_put_and_get(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"hello")
        assert c.get("a") == b"hello"

    def test_get_missing_returns_none(self):
        c = LRUCache(max_bytes=1024)
        assert c.get("nope") is None

    def test_eviction_by_size(self):
        c = LRUCache(max_bytes=100)
        c.put("a", b"x" * 60)
        c.put("b", b"y" * 60)
        # "a" should have been evicted since 60+60 > 100
        assert c.get("a") is None
        assert c.get("b") == b"y" * 60

    def test_lru_order(self):
        c = LRUCache(max_bytes=100)
        c.put("a", b"x" * 40)
        c.put("b", b"y" * 40)
        # Access "a" to make it recently used
        c.get("a")
        # Now adding "c" should evict "b" (least recently used)
        c.put("c", b"z" * 40)
        assert c.get("b") is None
        assert c.get("a") == b"x" * 40
        assert c.get("c") == b"z" * 40

    def test_invalidate(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"hello")
        c.invalidate("a")
        assert c.get("a") is None
        assert c.size == 0

    def test_invalidate_missing_is_noop(self):
        c = LRUCache(max_bytes=1024)
        c.invalidate("nope")  # should not raise

    def test_clear(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"hello")
        c.put("b", b"world")
        c.clear()
        assert len(c) == 0
        assert c.size == 0

    def test_overwrite_updates_size(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"short")
        assert c.size == 5
        c.put("a", b"much longer value here")
        assert c.size == len(b"much longer value here")
        assert len(c) == 1

    def test_size_and_len(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"12345")
        c.put("b", b"678")
        assert len(c) == 2
        assert c.size == 8


# ── FUSE Operations tests ────────────────────────────────────────────────

class TestQuantaCryptFUSE:
    """Test FUSE operations through direct method calls (no actual mount)."""

    @pytest.fixture
    def fuse_fs(self, tmp_dir):
        """Create a volume and return a QuantaCryptFUSE instance."""
        path = os.path.join(tmp_dir, "fuse.qcv")
        password = "fusepw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return QuantaCryptFUSE(vc)

    # ── getattr ──

    def test_getattr_root(self, fuse_fs):
        attrs = fuse_fs.getattr("/")
        import stat as st
        assert st.S_ISDIR(attrs["st_mode"])
        assert attrs["st_nlink"] == 2

    def test_getattr_nonexistent(self, fuse_fs):
        with pytest.raises(OSError):
            fuse_fs.getattr("/nope.txt")

    def test_getattr_file(self, fuse_fs):
        fd = fuse_fs.create("/hello.txt", 0o100644)
        fuse_fs.write("/hello.txt", b"hello world", 0, fd)
        fuse_fs.flush("/hello.txt", fd)
        fuse_fs.release("/hello.txt", fd)

        attrs = fuse_fs.getattr("/hello.txt")
        import stat as st
        assert st.S_ISREG(attrs["st_mode"])
        assert attrs["st_size"] == 11

    def test_getattr_directory(self, fuse_fs):
        fuse_fs.mkdir("/mydir", 0o40755)
        attrs = fuse_fs.getattr("/mydir")
        import stat as st
        assert st.S_ISDIR(attrs["st_mode"])

    # ── readdir ──

    def test_readdir_empty(self, fuse_fs):
        entries = fuse_fs.readdir("/")
        assert "." in entries
        assert ".." in entries

    def test_readdir_with_files(self, fuse_fs):
        fd = fuse_fs.create("/a.txt", 0o100644)
        fuse_fs.release("/a.txt", fd)
        fd = fuse_fs.create("/b.txt", 0o100644)
        fuse_fs.release("/b.txt", fd)
        entries = fuse_fs.readdir("/")
        assert "a.txt" in entries
        assert "b.txt" in entries

    # ── mkdir / rmdir ──

    def test_mkdir_and_readdir(self, fuse_fs):
        fuse_fs.mkdir("/docs", 0o40755)
        entries = fuse_fs.readdir("/")
        assert "docs" in entries

    def test_rmdir_empty(self, fuse_fs):
        fuse_fs.mkdir("/empty", 0o40755)
        fuse_fs.rmdir("/empty")
        with pytest.raises(OSError):
            fuse_fs.getattr("/empty")

    def test_rmdir_notempty(self, fuse_fs):
        fuse_fs.mkdir("/stuff", 0o40755)
        fd = fuse_fs.create("/stuff/file.txt", 0o100644)
        fuse_fs.release("/stuff/file.txt", fd)
        with pytest.raises(OSError):
            fuse_fs.rmdir("/stuff")

    # ── create / open / read / write ──

    def test_create_returns_fd(self, fuse_fs):
        fd = fuse_fs.create("/new.txt", 0o100644)
        assert isinstance(fd, int)
        assert fd > 0
        fuse_fs.release("/new.txt", fd)

    def test_write_and_read(self, fuse_fs):
        fd = fuse_fs.create("/test.txt", 0o100644)
        written = fuse_fs.write("/test.txt", b"Hello FUSE!", 0, fd)
        assert written == 11

        data = fuse_fs.read("/test.txt", 100, 0, fd)
        assert data == b"Hello FUSE!"
        fuse_fs.release("/test.txt", fd)

    def test_read_with_offset(self, fuse_fs):
        fd = fuse_fs.create("/off.txt", 0o100644)
        fuse_fs.write("/off.txt", b"abcdefghij", 0, fd)
        data = fuse_fs.read("/off.txt", 3, 5, fd)
        assert data == b"fgh"
        fuse_fs.release("/off.txt", fd)

    def test_write_at_offset(self, fuse_fs):
        fd = fuse_fs.create("/patch.txt", 0o100644)
        fuse_fs.write("/patch.txt", b"AAAA", 0, fd)
        fuse_fs.write("/patch.txt", b"BB", 2, fd)
        data = fuse_fs.read("/patch.txt", 100, 0, fd)
        assert data == b"AABB"  # AA then BB at offset 2 overwrites last two
        fuse_fs.release("/patch.txt", fd)

    def test_open_existing_file(self, fuse_fs):
        # Create and close
        fd = fuse_fs.create("/exist.txt", 0o100644)
        fuse_fs.write("/exist.txt", b"data", 0, fd)
        fuse_fs.flush("/exist.txt", fd)
        fuse_fs.release("/exist.txt", fd)

        # Reopen
        fd2 = fuse_fs.open("/exist.txt", 0)
        data = fuse_fs.read("/exist.txt", 100, 0, fd2)
        assert data == b"data"
        fuse_fs.release("/exist.txt", fd2)

    def test_open_nonexistent(self, fuse_fs):
        with pytest.raises(OSError):
            fuse_fs.open("/nope.txt", 0)

    # ── truncate ──

    def test_truncate_shorter(self, fuse_fs):
        fd = fuse_fs.create("/trunc.txt", 0o100644)
        fuse_fs.write("/trunc.txt", b"long content here", 0, fd)
        fuse_fs.truncate("/trunc.txt", 4, fd)
        data = fuse_fs.read("/trunc.txt", 100, 0, fd)
        assert data == b"long"
        fuse_fs.release("/trunc.txt", fd)

    def test_truncate_longer(self, fuse_fs):
        fd = fuse_fs.create("/trunc2.txt", 0o100644)
        fuse_fs.write("/trunc2.txt", b"hi", 0, fd)
        fuse_fs.truncate("/trunc2.txt", 5, fd)
        data = fuse_fs.read("/trunc2.txt", 100, 0, fd)
        assert data == b"hi\x00\x00\x00"
        fuse_fs.release("/trunc2.txt", fd)

    # ── flush / release ──

    def test_flush_persists_to_volume(self, fuse_fs):
        fd = fuse_fs.create("/flushed.txt", 0o100644)
        fuse_fs.write("/flushed.txt", b"saved", 0, fd)
        fuse_fs.flush("/flushed.txt", fd)

        # Verify data made it to the volume
        data = fuse_fs.volume.read_file("/flushed.txt")
        assert data == b"saved"
        fuse_fs.release("/flushed.txt", fd)

    def test_release_flushes_dirty(self, fuse_fs):
        fd = fuse_fs.create("/rel.txt", 0o100644)
        fuse_fs.write("/rel.txt", b"dirty", 0, fd)
        # Release without explicit flush — should auto-flush
        fuse_fs.release("/rel.txt", fd)

        data = fuse_fs.volume.read_file("/rel.txt")
        assert data == b"dirty"

    def test_release_cleans_up_buffer(self, fuse_fs):
        fd = fuse_fs.create("/cleanup.txt", 0o100644)
        fuse_fs.write("/cleanup.txt", b"temp", 0, fd)
        fuse_fs.release("/cleanup.txt", fd)
        # Buffer should be cleared since no other FDs have it open
        assert "/cleanup.txt" not in fuse_fs._file_buffers

    # ── unlink ──

    def test_unlink(self, fuse_fs):
        fd = fuse_fs.create("/delete.txt", 0o100644)
        fuse_fs.write("/delete.txt", b"bye", 0, fd)
        fuse_fs.release("/delete.txt", fd)

        fuse_fs.unlink("/delete.txt")
        with pytest.raises(OSError):
            fuse_fs.getattr("/delete.txt")

    # ── rename ──

    def test_rename(self, fuse_fs):
        fd = fuse_fs.create("/old.txt", 0o100644)
        fuse_fs.write("/old.txt", b"moved", 0, fd)
        fuse_fs.flush("/old.txt", fd)
        fuse_fs.release("/old.txt", fd)

        fuse_fs.rename("/old.txt", "/new.txt")

        with pytest.raises(OSError):
            fuse_fs.getattr("/old.txt")

        fd2 = fuse_fs.open("/new.txt", 0)
        data = fuse_fs.read("/new.txt", 100, 0, fd2)
        assert data == b"moved"
        fuse_fs.release("/new.txt", fd2)

    def test_rename_with_dirty_buffer(self, fuse_fs):
        fd = fuse_fs.create("/src.txt", 0o100644)
        fuse_fs.write("/src.txt", b"buffered", 0, fd)
        # Don't flush — rename with dirty buffer
        fuse_fs.release("/src.txt", fd)
        fuse_fs.rename("/src.txt", "/dst.txt")

        fd2 = fuse_fs.open("/dst.txt", 0)
        data = fuse_fs.read("/dst.txt", 100, 0, fd2)
        assert data == b"buffered"
        fuse_fs.release("/dst.txt", fd2)

    # ── statfs ──

    def test_statfs(self, fuse_fs):
        stats = fuse_fs.statfs("/")
        assert "f_bsize" in stats
        assert stats["f_bsize"] == 4096
        assert stats["f_namemax"] == 255

    # ── Integration: full file lifecycle ──

    def test_full_lifecycle(self, fuse_fs):
        """Create → write → flush → close → reopen → read → rename → delete."""
        # Create and write
        fd = fuse_fs.create("/lifecycle.txt", 0o100644)
        fuse_fs.write("/lifecycle.txt", b"lifecycle data", 0, fd)
        fuse_fs.flush("/lifecycle.txt", fd)
        fuse_fs.release("/lifecycle.txt", fd)

        # Reopen and read
        fd2 = fuse_fs.open("/lifecycle.txt", 0)
        data = fuse_fs.read("/lifecycle.txt", 100, 0, fd2)
        assert data == b"lifecycle data"
        fuse_fs.release("/lifecycle.txt", fd2)

        # Rename
        fuse_fs.rename("/lifecycle.txt", "/renamed.txt")
        entries = fuse_fs.readdir("/")
        assert "renamed.txt" in entries
        assert "lifecycle.txt" not in entries

        # Delete
        fuse_fs.unlink("/renamed.txt")
        entries = fuse_fs.readdir("/")
        assert "renamed.txt" not in entries


# ── FUSE edge cases and coverage boosters ─────────────────────────────────

class TestFUSEEdgeCases:
    """Tests for uncovered branches in fuse_ops.py."""

    @pytest.fixture
    def fuse_fs(self, tmp_dir):
        path = os.path.join(tmp_dir, "edge.qcv")
        password = "edgepw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return QuantaCryptFUSE(vc)

    def test_check_fuse_available(self):
        """check_fuse_available returns (bool, str)."""
        available, msg = check_fuse_available()
        assert isinstance(available, bool)
        assert isinstance(msg, str)

    def test_get_mounted_volumes_empty(self):
        """get_mounted_volumes returns a dict."""
        result = get_mounted_volumes()
        assert isinstance(result, dict)

    def test_vpath_without_leading_slash(self, fuse_fs):
        """Paths without / prefix get normalized."""
        result = fuse_fs._vpath("no_slash.txt")
        assert result == "/no_slash.txt"

    def test_vpath_with_leading_slash(self, fuse_fs):
        result = fuse_fs._vpath("/has_slash.txt")
        assert result == "/has_slash.txt"

    def test_dir_vpath_root(self, fuse_fs):
        """Root path stays as /."""
        assert fuse_fs._dir_vpath("/") == "/"

    def test_dir_vpath_adds_trailing_slash(self, fuse_fs):
        assert fuse_fs._dir_vpath("/mydir") == "/mydir/"

    def test_dir_vpath_already_has_slash(self, fuse_fs):
        assert fuse_fs._dir_vpath("/mydir/") == "/mydir/"

    def test_read_lazy_load_without_buffer(self, fuse_fs):
        """read() lazily loads file data if not in buffer."""
        # Create file, flush, release (clears buffer)
        fd = fuse_fs.create("/lazy.txt", 0o100644)
        fuse_fs.write("/lazy.txt", b"lazy data", 0, fd)
        fuse_fs.flush("/lazy.txt", fd)
        fuse_fs.release("/lazy.txt", fd)

        # Manually clear the buffer to force lazy load path
        fuse_fs._file_buffers.pop("/lazy.txt", None)
        fuse_fs.cache.invalidate("/lazy.txt")

        # Read without opening (testing the lazy load in read())
        data = fuse_fs.read("/lazy.txt", 100, 0, 999)
        assert data == b"lazy data"

    def test_write_creates_buffer_if_missing(self, fuse_fs):
        """write() creates a new buffer if file not yet buffered."""
        # Create a file in the volume directly
        fuse_fs.volume.write_file("/direct.txt", b"original")
        fuse_fs.volume.save()

        # Write via FUSE with no buffer loaded
        written = fuse_fs.write("/direct.txt", b"overwritten", 0, 999)
        assert written == 11
        assert "/direct.txt" in fuse_fs._file_buffers

    def test_truncate_loads_from_volume(self, fuse_fs):
        """truncate() loads file from volume if not in buffer."""
        fd = fuse_fs.create("/trunc_load.txt", 0o100644)
        fuse_fs.write("/trunc_load.txt", b"truncate me please", 0, fd)
        fuse_fs.flush("/trunc_load.txt", fd)
        fuse_fs.release("/trunc_load.txt", fd)

        # Clear buffer
        fuse_fs._file_buffers.pop("/trunc_load.txt", None)

        # Truncate should load from volume first
        fuse_fs.truncate("/trunc_load.txt", 8)
        buf = fuse_fs._file_buffers.get("/trunc_load.txt")
        assert buf is not None
        assert bytes(buf) == b"truncate"

    def test_open_uses_cache(self, fuse_fs):
        """open() uses cached data when available."""
        fd = fuse_fs.create("/cached.txt", 0o100644)
        fuse_fs.write("/cached.txt", b"cached content", 0, fd)
        fuse_fs.flush("/cached.txt", fd)
        fuse_fs.release("/cached.txt", fd)

        # Data should be in cache from flush
        assert fuse_fs.cache.get("/cached.txt") is not None

        # Reopen — should hit cache path
        fd2 = fuse_fs.open("/cached.txt", 0)
        data = fuse_fs.read("/cached.txt", 100, 0, fd2)
        assert data == b"cached content"
        fuse_fs.release("/cached.txt", fd2)

    def test_getattr_reports_buffer_size(self, fuse_fs):
        """getattr reports buffer size for modified files."""
        fd = fuse_fs.create("/buf_size.txt", 0o100644)
        fuse_fs.write("/buf_size.txt", b"hello", 0, fd)
        # Don't flush — the buffer has 5 bytes but volume has 0
        attrs = fuse_fs.getattr("/buf_size.txt")
        assert attrs["st_size"] == 5
        fuse_fs.release("/buf_size.txt", fd)

    def test_rename_dirty_file_moves_dirty_flag(self, fuse_fs):
        """rename moves dirty tracking to new path."""
        fd = fuse_fs.create("/dirty_rename.txt", 0o100644)
        fuse_fs.write("/dirty_rename.txt", b"dirty", 0, fd)
        # File is dirty (not flushed)
        assert "/dirty_rename.txt" in fuse_fs._dirty_files

        fuse_fs.release("/dirty_rename.txt", fd)
        # After release, it was flushed, so create dirty state again
        fd2 = fuse_fs.open("/dirty_rename.txt", 0)
        fuse_fs.write("/dirty_rename.txt", b"dirty again", 0, fd2)
        assert "/dirty_rename.txt" in fuse_fs._dirty_files

        fuse_fs.rename("/dirty_rename.txt", "/dirty_moved.txt")
        assert "/dirty_rename.txt" not in fuse_fs._dirty_files
        assert "/dirty_moved.txt" in fuse_fs._dirty_files
        fuse_fs.release("/dirty_moved.txt", fd2)

    def test_flush_noop_for_clean_file(self, fuse_fs):
        """flush() is a no-op for non-dirty files."""
        fd = fuse_fs.create("/clean.txt", 0o100644)
        fuse_fs.write("/clean.txt", b"data", 0, fd)
        fuse_fs.flush("/clean.txt", fd)
        # Flush again — should be a no-op (not dirty)
        fuse_fs.flush("/clean.txt", fd)
        fuse_fs.release("/clean.txt", fd)

    def test_multiple_fds_same_file(self, fuse_fs):
        """Multiple file descriptors can open the same file."""
        fd1 = fuse_fs.create("/shared.txt", 0o100644)
        fuse_fs.write("/shared.txt", b"shared", 0, fd1)
        fuse_fs.flush("/shared.txt", fd1)

        fd2 = fuse_fs.open("/shared.txt", 0)

        # Release first fd — buffer should stay since fd2 is open
        fuse_fs.release("/shared.txt", fd1)
        assert "/shared.txt" in fuse_fs._file_buffers

        # Read via fd2 should work
        data = fuse_fs.read("/shared.txt", 100, 0, fd2)
        assert data == b"shared"

        # Release fd2 — now buffer should be cleaned
        fuse_fs.release("/shared.txt", fd2)
        assert "/shared.txt" not in fuse_fs._file_buffers


# ── check_fuse_components tests ──────────────────────────────────────────────

class TestCheckFuseComponents:
    """Tests for the granular FUSE dependency checker."""

    def test_returns_both_keys(self):
        result = check_fuse_components()
        assert "fusepy" in result
        assert "fuse_backend" in result

    def test_fusepy_key_has_ok_and_detail(self):
        result = check_fuse_components()
        assert "ok" in result["fusepy"]
        assert "detail" in result["fusepy"]
        assert isinstance(result["fusepy"]["ok"], bool)
        assert isinstance(result["fusepy"]["detail"], str)

    def test_fuse_backend_key_has_ok_and_detail(self):
        result = check_fuse_components()
        assert "ok" in result["fuse_backend"]
        assert "detail" in result["fuse_backend"]
        assert isinstance(result["fuse_backend"]["ok"], bool)
        assert isinstance(result["fuse_backend"]["detail"], str)

    def test_fusepy_not_installed(self, monkeypatch):
        """Simulate fusepy not being importable."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "fuse":
                raise ImportError("mock")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = check_fuse_components()
        assert result["fusepy"]["ok"] is False
        assert "not installed" in result["fusepy"]["detail"]

    def test_fusepy_installed(self, monkeypatch):
        """Simulate fusepy being importable (mock the import)."""
        import builtins
        import types
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "fuse":
                return types.ModuleType("fuse")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = check_fuse_components()
        assert result["fusepy"]["ok"] is True

    def test_no_fuse_backend_linux(self, monkeypatch):
        """Simulate Linux with no FUSE backend."""
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr("shutil.which", lambda _: None)
        monkeypatch.setattr("os.path.exists", lambda p: False)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is False

    def test_fuse_backend_linux_fusermount(self, monkeypatch):
        """Simulate Linux with fusermount available."""
        monkeypatch.setattr("sys.platform", "linux")

        def which(name):
            return "/usr/bin/fusermount" if name == "fusermount" else None

        monkeypatch.setattr("shutil.which", which)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True

    def test_fuse_backend_darwin_macfuse(self, monkeypatch):
        """Simulate macOS with macFUSE installed."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile
        real_isdir = os.path.isdir

        def mock_isfile(p):
            if p == "/usr/local/lib/libfuse-t.dylib":
                return False
            return real_isfile(p)

        def mock_isdir(p):
            if p == "/Library/Filesystems/macfuse.fs":
                return True
            if p == "/Library/Filesystems/osxfuse.fs":
                return False
            return real_isdir(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        monkeypatch.setattr("os.path.isdir", mock_isdir)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "macFUSE" in result["fuse_backend"]["detail"]

    def test_fuse_backend_darwin_fuse_t(self, monkeypatch):
        """Simulate macOS with FUSE-T installed."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile

        def mock_isfile(p):
            if p == "/usr/local/lib/libfuse-t.dylib":
                return True
            return real_isfile(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "FUSE-T" in result["fuse_backend"]["detail"]

    def test_fuse_backend_darwin_none(self, monkeypatch):
        """Simulate macOS with no FUSE backend."""
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr("os.path.isfile", lambda p: False)
        monkeypatch.setattr("os.path.isdir", lambda p: False)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is False

    def test_fuse_backend_darwin_osxfuse(self, monkeypatch):
        """Simulate macOS with legacy osxfuse installed."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile
        real_isdir = os.path.isdir

        def mock_isfile(p):
            if p == "/usr/local/lib/libfuse-t.dylib":
                return False
            return real_isfile(p)

        def mock_isdir(p):
            if p == "/Library/Filesystems/macfuse.fs":
                return False
            if p == "/Library/Filesystems/osxfuse.fs":
                return True
            return real_isdir(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        monkeypatch.setattr("os.path.isdir", mock_isdir)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "osxfuse" in result["fuse_backend"]["detail"]

    def test_fuse_backend_linux_fusermount3(self, monkeypatch):
        """Simulate Linux with fusermount3 available."""
        monkeypatch.setattr("sys.platform", "linux")

        def which(name):
            return "/usr/bin/fusermount3" if name == "fusermount3" else None

        monkeypatch.setattr("shutil.which", which)
        monkeypatch.setattr("os.path.exists", lambda p: False)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True

    def test_fuse_backend_linux_dev_fuse(self, monkeypatch):
        """Simulate Linux with /dev/fuse present."""
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr("shutil.which", lambda _: None)

        def mock_exists(p):
            return p == "/dev/fuse"

        monkeypatch.setattr("os.path.exists", mock_exists)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True


# ── Content hash verification tests ─────────────────────────────────────────

class TestContentHashVerification:
    """Tests for read_file content hash verification."""

    @pytest.fixture
    def open_volume(self, tmp_dir):
        path = os.path.join(tmp_dir, "hash_vol.qcv")
        password = "hashpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return vc

    def test_hash_verified_on_read(self, open_volume):
        """read_file verifies content hash by default."""
        vc = open_volume
        data = b"verified content"
        vc.write_file("/verified.txt", data)
        # Normal read should succeed
        assert vc.read_file("/verified.txt") == data

    def test_hash_mismatch_raises(self, open_volume):
        """read_file raises on tampered content_hash."""
        vc = open_volume
        data = b"tampered content"
        vc.write_file("/tampered.txt", data)
        # Corrupt the stored hash
        vc.dir_index["/tampered.txt"]["content_hash"] = "0" * 64
        with pytest.raises(ValueError, match="Content hash mismatch"):
            vc.read_file("/tampered.txt")

    def test_hash_skip_verification(self, open_volume):
        """read_file with verify_hash=False skips check."""
        vc = open_volume
        data = b"skip hash check"
        vc.write_file("/skip.txt", data)
        vc.dir_index["/skip.txt"]["content_hash"] = "0" * 64
        # Should not raise even with bad hash
        result = vc.read_file("/skip.txt", verify_hash=False)
        assert result == data

    def test_hash_missing_no_error(self, open_volume):
        """read_file works when content_hash is absent from entry."""
        vc = open_volume
        data = b"no hash entry"
        vc.write_file("/nohash.txt", data)
        # Remove the hash field
        del vc.dir_index["/nohash.txt"]["content_hash"]
        # Should still read fine (no hash to check)
        assert vc.read_file("/nohash.txt") == data


# ── Double-mount prevention tests ────────────────────────────────────────────

from quantacrypt.core.fuse_ops import mount_volume, unmount_volume, _mounted_volumes


class TestDoubleMountPrevention:
    """Tests for mount_volume refusing to double-mount."""

    def test_double_mount_raises(self, tmp_dir):
        """mount_volume raises if the same volume file is already mounted."""
        path = os.path.join(tmp_dir, "double.qcv")
        password = "dblpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        # Simulate an existing mount entry
        mp = os.path.join(tmp_dir, "mnt1")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vol.VolumeContainer(path, final_key),
            "thread": None,
            "fuse": None,
        }
        try:
            mp2 = os.path.join(tmp_dir, "mnt2")
            with pytest.raises(RuntimeError, match="already mounted"):
                mount_volume(path, final_key, mp2)
        finally:
            _mounted_volumes.pop(mp, None)

    def test_different_volumes_allowed(self, tmp_dir):
        """mount_volume allows mounting different volume files."""
        path1 = os.path.join(tmp_dir, "vol1.qcv")
        path2 = os.path.join(tmp_dir, "vol2.qcv")
        password = "volpw"
        meta1 = vol.create_volume_single(path1, password)
        meta2 = vol.create_volume_single(path2, password)
        key1 = vol.derive_volume_key_single(password, meta1)

        mp1 = os.path.join(tmp_dir, "mnt1")
        _mounted_volumes[mp1] = {
            "volume_path": path1,
            "volume": vol.VolumeContainer(path1, key1),
            "thread": None,
            "fuse": None,
        }
        try:
            # Different volume should not trigger double-mount check
            # (will fail at FUSE import, which is expected — we just verify
            # it gets past the double-mount check)
            key2 = vol.derive_volume_key_single(password, meta2)
            mp2 = os.path.join(tmp_dir, "mnt2")
            # This will raise RuntimeError from check_fuse_available (no fusepy),
            # NOT from double-mount prevention
            with pytest.raises(RuntimeError, match="fusepy"):
                mount_volume(path2, key2, mp2)
        finally:
            _mounted_volumes.pop(mp1, None)


# ── Unmount tests ────────────────────────────────────────────────────────────

class TestUnmountVolume:
    """Tests for unmount_volume."""

    def test_unmount_saves_dirty_volume(self, tmp_dir):
        """unmount_volume saves a dirty volume."""
        path = os.path.join(tmp_dir, "unmount.qcv")
        password = "umpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/test.txt", b"unsaved")

        mp = os.path.join(tmp_dir, "umnt")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vc,
            "thread": None,
            "fuse": None,
        }
        assert vc.is_dirty
        unmount_volume(mp)
        assert not vc.is_dirty
        assert mp not in _mounted_volumes

    def test_unmount_unknown_mount_point(self, tmp_dir):
        """unmount_volume refuses to operate on untracked mount points.

        Running diskutil/fusermount against an arbitrary path would risk
        tearing down another app's FUSE mount, so unmount_volume now raises
        ValueError when the caller passes a path we do not own.
        """
        with pytest.raises(ValueError, match="No QuantaCrypt volume is tracked"):
            unmount_volume("/nonexistent/mount/point")

    def test_unmount_clean_volume(self, tmp_dir):
        """unmount_volume works for clean (non-dirty) volumes."""
        path = os.path.join(tmp_dir, "clean_unmount.qcv")
        password = "cleanpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()

        mp = os.path.join(tmp_dir, "cmnt")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vc,
            "thread": None,
            "fuse": None,
        }
        assert not vc.is_dirty
        unmount_volume(mp)
        assert mp not in _mounted_volumes

    def test_unmount_save_failure_keeps_tracking(self, tmp_dir):
        """If save() fails during unmount, volume stays in tracking dict."""
        path = os.path.join(tmp_dir, "fail_save.qcv")
        password = "failpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/test.txt", b"data")

        mp = os.path.join(tmp_dir, "failmnt")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vc,
            "thread": None,
            "fuse": None,
        }
        # Make save raise
        from unittest.mock import MagicMock
        vc.save = MagicMock(side_effect=OSError("disk full"))
        vc._dirty = True
        with pytest.raises(OSError, match="disk full"):
            unmount_volume(mp)
        # Volume should still be tracked so _emergency_save_all can retry
        assert mp in _mounted_volumes
        _mounted_volumes.pop(mp, None)


# ── Mount volume with no FUSE tests ──────────────────────────────────────────

class TestMountVolumeNoFuse:
    """Test mount_volume behavior when fusepy is unavailable."""

    def test_mount_without_fusepy_raises(self, tmp_dir):
        """mount_volume raises RuntimeError when fusepy is not installed."""
        path = os.path.join(tmp_dir, "nofuse.qcv")
        password = "nfpw"
        meta = vol.create_volume_single(path, password)
        key = vol.derive_volume_key_single(password, meta)
        mp = os.path.join(tmp_dir, "nfmnt")
        with pytest.raises(RuntimeError):
            mount_volume(path, key, mp)


# ── Auth params truncation tests ─────────────────────────────────────────────

class TestAuthParamsTruncation:
    """Test error handling for truncated auth params."""

    def test_truncated_auth_params_length(self, tmp_dir):
        """Truncated auth params length field raises ValueError."""
        path = os.path.join(tmp_dir, "trunc_auth.qcv")
        with open(path, "wb") as f:
            vid = os.urandom(16)
            mn = os.urandom(12)
            dn = os.urandom(12)
            vol.write_header(f, vid, mn, dn)
            f.write(b"\x00\x00")  # only 2 bytes for auth params length

        with pytest.raises(ValueError, match="auth params length"):
            vol.read_volume_auth_params(path)

    def test_truncated_auth_params_data(self, tmp_dir):
        """Truncated auth params data raises ValueError."""
        path = os.path.join(tmp_dir, "trunc_auth2.qcv")
        with open(path, "wb") as f:
            vid = os.urandom(16)
            mn = os.urandom(12)
            dn = os.urandom(12)
            vol.write_header(f, vid, mn, dn)
            f.write(struct.pack(">I", 1000))  # claims 1000 bytes
            f.write(b"\x00" * 10)  # only 10

        with pytest.raises(ValueError, match="auth params data"):
            vol.read_volume_auth_params(path)


# ── Corrupt volume open tests ────────────────────────────────────────────────

class TestCorruptVolumeOpen:
    """Tests for VolumeContainer.open() with corrupt data."""

    def test_wrong_key_gives_helpful_error(self, tmp_dir):
        """Opening a volume with wrong key gives a clear error message."""
        path = os.path.join(tmp_dir, "wrongkey.qcv")
        password = "correct"
        meta = vol.create_volume_single(path, password)
        wrong_key = os.urandom(64)  # random key, not derived from password
        vc = vol.VolumeContainer(path, wrong_key)
        with pytest.raises(ValueError, match="password or key may be incorrect"):
            vc.open()

    def test_truncated_baseline_raises(self, tmp_dir):
        """Truncation inside the baseline section raises at open().

        Compact first so the file lives in the baseline (not the journal);
        a truncated journal tail is the normal crash-recovery shape and is
        tolerated silently, but baseline truncation has no safe recovery.
        """
        path = os.path.join(tmp_dir, "trunc_data.qcv")
        password = "truncpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/big.txt", b"x" * 10000)
        vc.compact()  # force the blob into the baseline

        file_size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.truncate(file_size - 5000)

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="truncated"):
            vc2.open()

    def test_truncated_journal_tail_tolerated(self, tmp_dir):
        """Partial journal records at EOF are silently dropped (crash-safe).

        A save() that crashes mid-append leaves an incomplete record after
        the last committed one.  The reader must recover to the last
        committed state without raising, same as a database WAL.
        """
        path = os.path.join(tmp_dir, "trunc_journal.qcv")
        password = "journalpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        # First save: commit "/a" into the journal.
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/a.txt", b"alpha" * 200)
        vc.save()
        committed_size = os.path.getsize(path)

        # Second save: append another record, then simulate a crash by
        # chopping 10 bytes off the tail — somewhere inside the body.
        vc.write_file("/b.txt", b"beta" * 200)
        vc.save()
        file_size = os.path.getsize(path)
        assert file_size > committed_size
        with open(path, "r+b") as f:
            f.truncate(file_size - 10)

        # Reopen: /a.txt survives, /b.txt is lost.
        vc2 = vol.VolumeContainer(path, final_key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"alpha" * 200
        assert "/b.txt" not in vc2.dir_index

    def test_save_cleanup_on_error(self, tmp_dir):
        """save() cleans up .tmp file on write error."""
        path = os.path.join(tmp_dir, "cleanup.qcv")
        password = "cleanpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/test.txt", b"data")

        # Verify .tmp doesn't linger after successful save
        vc.save()
        assert not os.path.exists(path + ".tmp")

    def test_open_rejects_missing_hmac(self, tmp_dir):
        """Volume whose metadata HMAC has been stripped fails to open.

        Regression guard: VolumeContainer.open() must call _verify_meta_hmac
        after decrypting metadata.  If it skips verification, stripping the
        HMAC field would silently open with undetected tampered auth fields.
        """
        path = os.path.join(tmp_dir, "no_hmac.qcv")
        password = "hmacpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.metadata.pop("hmac", None)
        # compact() forces the mutated metadata to be re-encrypted to disk;
        # save() would append a journal record and leave the on-disk
        # metadata untouched, which is the opposite of what this test wants.
        vc.compact()

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="HMAC"):
            vc2.open()

    def test_open_rejects_tampered_hmac(self, tmp_dir):
        """Flipping the stored HMAC byte-for-byte causes open() to fail."""
        path = os.path.join(tmp_dir, "bad_hmac.qcv")
        password = "hmacpw2"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.metadata["hmac"] = "A" * len(vc.metadata["hmac"])
        vc.compact()  # force metadata rewrite; save() would just append

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="authentication failed"):
            vc2.open()

    def test_open_rejects_non_absolute_dir_entry(self, tmp_dir):
        """Directory index with a non-absolute path is rejected."""
        path = os.path.join(tmp_dir, "nonabs.qcv")
        password = "pathpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.dir_index["relative/path.txt"] = {
            "type": "file",
            "size": 0,
            "mode": 0o100644,
            "mtime": 0,
            "nonce": base64.b64encode(b"\x00" * 12).decode(),
            "chunk_count": 0,
            "data_offset": 0,
            "data_length": 0,
        }
        vc._dirty = True
        # Directory tampering only reaches disk via a full rewrite.  save()
        # would append a no-op journal; compact re-encrypts the directory.
        vc.compact()

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="non-absolute path"):
            vc2.open()

    def test_open_rejects_path_traversal_entry(self, tmp_dir):
        """Directory index containing a '..' segment is rejected."""
        path = os.path.join(tmp_dir, "traversal.qcv")
        password = "pathpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.dir_index["/legit/../escape.txt"] = {
            "type": "file",
            "size": 0,
            "mode": 0o100644,
            "mtime": 0,
            "nonce": base64.b64encode(b"\x00" * 12).decode(),
            "chunk_count": 0,
            "data_offset": 0,
            "data_length": 0,
        }
        vc._dirty = True
        # Directory tampering only reaches disk via a full rewrite.  save()
        # would append a no-op journal; compact re-encrypts the directory.
        vc.compact()

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="path traversal"):
            vc2.open()


class TestReadFileBounds:
    """Defensive bounds checks in VolumeContainer.read_file()."""

    def test_read_rejects_negative_chunk_count(self, tmp_dir):
        path = os.path.join(tmp_dir, "neg.qcv")
        pw = "x"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/f.txt", b"data")
        vc.dir_index["/f.txt"]["chunk_count"] = -1
        with pytest.raises(ValueError, match="Invalid chunk_count"):
            vc.read_file("/f.txt")

    def test_read_rejects_oversized_chunk_count(self, tmp_dir):
        path = os.path.join(tmp_dir, "over.qcv")
        pw = "x"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/f.txt", b"data")  # 1 chunk expected
        vc.dir_index["/f.txt"]["chunk_count"] = 1_000_000
        with pytest.raises(ValueError, match="exceeds what"):
            vc.read_file("/f.txt")

    def test_read_rejects_data_length_mismatch(self, tmp_dir):
        path = os.path.join(tmp_dir, "dlen.qcv")
        pw = "x"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/f.txt", b"data")
        vc.dir_index["/f.txt"]["data_length"] = 999999
        with pytest.raises(ValueError, match="data_length"):
            vc.read_file("/f.txt")


class TestLazyBlobLoad:
    """Exercise the lazy-blob path: files written, saved, then read via
    seek-from-disk rather than _file_data cache."""

    def test_reopen_reads_from_disk(self, tmp_dir):
        path = os.path.join(tmp_dir, "lazy.qcv")
        pw = "lazypw"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)

        # Write two files, save, then close.
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/a.txt", b"alpha" * 100)
        vc.write_file("/b.txt", b"beta" * 100)
        vc.save()

        # Reopen: _file_data should be empty (lazy).
        vc2 = vol.VolumeContainer(path, final_key)
        vc2.open()
        assert vc2._file_data == {}, (
            "open() should not pre-populate _file_data — blobs are lazy-loaded"
        )

        # Reading should seek from disk and return the original plaintext.
        assert vc2.read_file("/a.txt") == b"alpha" * 100
        assert vc2.read_file("/b.txt") == b"beta" * 100

    def test_save_copies_unmodified_blobs_from_disk(self, tmp_dir):
        """After reopen, add one new file and save — unmodified blobs are
        copied straight from the old container without being held in RAM."""
        path = os.path.join(tmp_dir, "mixed.qcv")
        pw = "mixpw"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/old1.txt", b"OLD" * 1000)
        vc.write_file("/old2.txt", b"OLD2" * 1000)
        vc.save()

        # Reopen and add a new file; do NOT touch the existing ones.
        vc2 = vol.VolumeContainer(path, final_key)
        vc2.open()
        vc2.write_file("/new.txt", b"NEW" * 500)
        # Only the newly-written file is in _file_data; save must stream
        # the other two from disk.
        assert set(vc2._file_data.keys()) == {"/new.txt"}
        vc2.save()

        # After save, _file_data is cleared and the volume still reads
        # all three files correctly.
        assert vc2._file_data == {}
        assert vc2.read_file("/old1.txt") == b"OLD" * 1000
        assert vc2.read_file("/old2.txt") == b"OLD2" * 1000
        assert vc2.read_file("/new.txt") == b"NEW" * 500


class TestFormatV2Journal:
    """Coverage for the v2 append-only journal: replay, auto-compact,
    v1→v2 upgrade, and graceful handling of corrupt / partial records."""

    def _open(self, tmp_dir, name="j.qcv", pw="journal-pw"):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        return path, final_key

    def test_replay_write_then_delete(self, tmp_dir):
        """write + save + delete + save — replay yields the deleted state."""
        path, key = self._open(tmp_dir, "write_delete.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"hello")
        vc.save()
        vc.delete("/a.txt")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/a.txt" not in vc2.dir_index

    def test_replay_mkdir_then_rmdir(self, tmp_dir):
        path, key = self._open(tmp_dir, "mkdir_rmdir.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.mkdir("/d")
        vc.save()
        vc.delete("/d/")  # delete() on a dir emits rmdir
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/d/" not in vc2.dir_index

    def test_replay_rename(self, tmp_dir):
        path, key = self._open(tmp_dir, "rename.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"one")
        vc.save()
        vc.rename("/a.txt", "/b.txt")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/a.txt" not in vc2.dir_index
        assert vc2.read_file("/b.txt") == b"one"

    def test_replay_mkdir_persists_directory(self, tmp_dir):
        path, key = self._open(tmp_dir, "mk.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.mkdir("/docs")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/docs/" in vc2.dir_index
        assert vc2.dir_index["/docs/"].get("type") == "dir"

    def test_auto_compact_when_journal_exceeds_ratio(self, tmp_dir):
        """Heuristic: once the journal grows past 30% of the baseline,
        save() performs a full compact instead of appending."""
        path, key = self._open(tmp_dir, "autocompact.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        # 1 MB baseline → 30% threshold ≈ 307 KB.
        vc.write_file("/baseline.bin", b"B" * (1 << 20))
        vc.compact()
        baseline_size = vc._baseline_size
        threshold = int(baseline_size * 0.3)

        # First small write (~100 KB) appends — well under the threshold.
        vc.write_file("/x.bin", b"X" * (100 * 1024))
        vc.save()
        journal_after_append = os.path.getsize(path) - vc._journal_start
        assert 0 < journal_after_append < threshold, (
            f"expected small journal ({journal_after_append} < {threshold})"
        )

        # Next write (~400 KB) would push the journal past 30% of baseline,
        # so save() rolls into a compact instead of appending.
        vc.write_file("/y.bin", b"Y" * (400 * 1024))
        vc.save()

        assert vc._pending_ops == []
        # After compact, the journal is empty again.
        assert os.path.getsize(path) == vc._journal_start
        assert vc._baseline_size > baseline_size  # absorbed /x.bin and /y.bin

    def test_v1_container_upgrades_on_save(self, tmp_dir):
        """Hand-roll a v1 container bytewise, open it, save, and verify the
        on-disk header is bumped to VOLUME_FORMAT_VERSION."""
        path, key = self._open(tmp_dir, "v1.qcv")
        # Patch the header VERSION field from 2 back to 1 on disk to
        # simulate a container created by an older build.
        with open(path, "r+b") as f:
            f.seek(6)  # _OFF_VERSION
            f.write(struct.pack(">I", 1))

        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc.header["version"] == 1
        vc.write_file("/new.txt", b"upgraded")
        vc.save()  # v1 container always compacts

        # Confirm on-disk header is now v2.
        with open(path, "rb") as f:
            f.seek(6)
            version = struct.unpack(">I", f.read(4))[0]
        assert version == vol.VOLUME_FORMAT_VERSION

    def test_v1_container_rejects_trailing_bytes(self, tmp_dir):
        """A v1 container with bytes past the baseline is corrupt."""
        path, key = self._open(tmp_dir, "v1_trail.qcv")
        with open(path, "r+b") as f:
            f.seek(6)
            f.write(struct.pack(">I", 1))
            f.seek(0, 2)
            f.write(b"junk-bytes-pretending-to-be-v2-journal")

        vc = vol.VolumeContainer(path, key)
        with pytest.raises(ValueError, match="Trailing bytes"):
            vc.open()

    def test_save_noop_when_clean(self, tmp_dir):
        """save() on a container with no pending changes is a no-op."""
        path, key = self._open(tmp_dir, "noop.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        size_before = os.path.getsize(path)
        mtime_before = os.path.getmtime(path)
        vc.save()
        assert os.path.getsize(path) == size_before
        # The file must not be rewritten when nothing changed (mtime may
        # be equal even if we touched it, so just check content).
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.dir_index == {}

    def test_corrupt_journal_header_stops_replay(self, tmp_dir):
        """A flipped bit in a journal record's ciphertext header stops
        replay at that record; earlier records still apply."""
        path, key = self._open(tmp_dir, "corrupt_rec.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"alpha")
        vc.save()
        journal_start = vc._journal_start
        vc.write_file("/b.txt", b"beta")
        vc.save()

        # Flip one byte of /b.txt's record header ciphertext.  The second
        # record's nonce lives at journal_start + len(first record).
        # Easy approach: corrupt the first byte after /a.txt's body.
        first_record_end = (
            vc._data_offset + vc.dir_index["/a.txt"]["data_offset"]
            + vc.dir_index["/a.txt"]["data_length"]
        )
        with open(path, "r+b") as f:
            f.seek(first_record_end)
            raw = f.read(1)
            f.seek(first_record_end)
            f.write(bytes([raw[0] ^ 0xFF]))

        # Reopening must preserve /a.txt but drop /b.txt.
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"alpha"
        assert "/b.txt" not in vc2.dir_index

    def test_read_after_journal_append(self, tmp_dir):
        """Files in the journal region are readable via _get_blob seek."""
        path, key = self._open(tmp_dir, "read_journal.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/j.txt", b"journaled" * 500)
        vc.save()
        # Same instance: blob is cleared from _file_data after save, so
        # read must seek into the journal region.
        assert vc._file_data == {}
        assert vc.read_file("/j.txt", verify_hash=False) == b"journaled" * 500

    def test_reopen_after_compact_bounds_check(self, tmp_dir):
        """Open() must bounds-check baseline entries after a compact.

        Covers the baseline loop in open() — prior tests only reopened
        volumes whose baseline dir_index was empty (changes stayed in the
        journal), so the bounds check had nothing to iterate over.
        """
        path, key = self._open(tmp_dir, "baseline_loop.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/base1.txt", b"one" * 100)
        vc.write_file("/base2.txt", b"two" * 100)
        vc.compact()

        # Reopen — baseline dir_index now has two real file entries that
        # the bounds-check loop must walk before declaring the container
        # consistent.
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert set(vc2.dir_index) == {"/base1.txt", "/base2.txt"}
        assert vc2.read_file("/base1.txt") == b"one" * 100

    def test_small_baseline_compact_when_journal_big(self, tmp_dir):
        """Volumes with an empty/tiny baseline still auto-compact once the
        journal exceeds 1 MB — covers the "avoid unbounded-ratio divide"
        branch in save()."""
        path, key = self._open(tmp_dir, "tiny.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc._baseline_size == 0
        # A single 1.5 MB write trips the empty-baseline compact guard.
        vc.write_file("/big.bin", b"Q" * (int(1.5 * (1 << 20))))
        vc.save()
        # After compact, the volume is one big baseline with no journal.
        assert os.path.getsize(path) == vc._journal_start
        assert vc._baseline_size > 1 << 20

    def test_replay_rejects_malformed_vpath(self, tmp_dir):
        """Replay skips records whose vpath is missing/non-absolute instead
        of polluting the dir_index with junk."""
        path, key = self._open(tmp_dir, "badpath.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        # Append a hand-crafted journal record with a bogus vpath.
        with open(path, "r+b") as f:
            f.seek(0, 2)
            vol._write_journal_record(
                f, key,
                {"type": "write", "vpath": "no-leading-slash",
                 "size": 0, "mode": 0, "mtime": 0, "nonce": "",
                 "chunk_count": 0, "content_hash": ""},
                b"",
            )
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "no-leading-slash" not in vc2.dir_index
        assert "/no-leading-slash" not in vc2.dir_index


# ── Graceful shutdown tests ─────────────────────────────────────────────────

import signal
from unittest.mock import MagicMock, patch

from quantacrypt.core.fuse_ops import (
    _emergency_save_all,
    _ensure_shutdown_handlers,
    _signal_handler,
    _shutdown_lock,
)


class TestGracefulShutdown:
    """Tests for atexit / signal-based auto-save on exit."""

    def _make_mounted(self, tmp_dir, dirty=True):
        """Helper: create a volume and register it in _mounted_volumes."""
        path = os.path.join(tmp_dir, "shutdown.qcv")
        password = "shutpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        if dirty:
            vc.write_file("/dirty.txt", b"unsaved data")
        _mounted_volumes["/mnt/test_shutdown"] = {
            "volume": vc,
            "volume_path": path,
            "thread": None,
            "fuse": None,
        }
        return vc, path

    def test_emergency_save_dirty_volume(self, tmp_dir):
        """_emergency_save_all saves dirty volumes."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=True)
        assert vc.is_dirty

        _emergency_save_all()

        # Volume should have been saved — reopen and verify
        vc2 = vol.VolumeContainer(path, vc.final_key)
        vc2.open()
        data = vc2.read_file("/dirty.txt")
        assert data == b"unsaved data"

        _mounted_volumes.clear()

    def test_emergency_save_clean_volume_skipped(self, tmp_dir):
        """_emergency_save_all skips clean (non-dirty) volumes."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=False)
        assert not vc.is_dirty

        # Patch save to verify it's NOT called
        vc.save = MagicMock()
        _emergency_save_all()
        vc.save.assert_not_called()

        _mounted_volumes.clear()

    def test_emergency_save_handles_errors(self, tmp_dir):
        """_emergency_save_all logs but doesn't raise on save failure."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=True)

        # Make save() raise to simulate disk error
        vc.save = MagicMock(side_effect=OSError("disk full"))
        vc._dirty = True  # ensure is_dirty returns True

        # Should not raise
        _emergency_save_all()

        _mounted_volumes.clear()

    def test_emergency_save_multiple_volumes(self, tmp_dir):
        """_emergency_save_all iterates all mounted volumes."""
        _mounted_volumes.clear()
        saved = []

        for i in range(3):
            path = os.path.join(tmp_dir, f"multi_{i}.qcv")
            password = f"pw{i}"
            meta = vol.create_volume_single(path, password)
            final_key = vol.derive_volume_key_single(password, meta)
            vc = vol.VolumeContainer(path, final_key)
            vc.open()
            vc.write_file(f"/file{i}.txt", f"data{i}".encode())

            _mounted_volumes[f"/mnt/vol{i}"] = {
                "volume": vc,
                "volume_path": path,
                "thread": None,
                "fuse": None,
            }

        _emergency_save_all()

        # Verify all three volumes were saved
        for i in range(3):
            path = os.path.join(tmp_dir, f"multi_{i}.qcv")
            info = _mounted_volumes[f"/mnt/vol{i}"]
            vc2 = vol.VolumeContainer(path, info["volume"].final_key)
            vc2.open()
            assert vc2.read_file(f"/file{i}.txt") == f"data{i}".encode()

        _mounted_volumes.clear()

    def test_signal_handler_calls_save(self, tmp_dir):
        """_signal_handler saves volumes before re-raising signal."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=True)

        with patch("quantacrypt.core.fuse_ops.signal.signal"), \
             patch("quantacrypt.core.fuse_ops.os.kill") as mock_kill:
            _signal_handler(signal.SIGTERM, None)

        # Volume should have been saved
        vc2 = vol.VolumeContainer(path, vc.final_key)
        vc2.open()
        assert vc2.read_file("/dirty.txt") == b"unsaved data"

        # os.kill should have been called to re-raise
        mock_kill.assert_called_once_with(os.getpid(), signal.SIGTERM)

        _mounted_volumes.clear()

    def test_ensure_shutdown_registers_once(self):
        """_ensure_shutdown_handlers only registers once."""
        import quantacrypt.core.fuse_ops as fops

        # Reset the flag
        original = fops._shutdown_registered
        fops._shutdown_registered = False

        with patch("quantacrypt.core.fuse_ops.atexit.register") as mock_atexit, \
             patch("quantacrypt.core.fuse_ops.signal.signal"):
            _ensure_shutdown_handlers()
            assert mock_atexit.call_count == 1

            # Second call should be a no-op
            _ensure_shutdown_handlers()
            assert mock_atexit.call_count == 1

        fops._shutdown_registered = original

    def test_ensure_shutdown_handles_non_main_thread(self):
        """_ensure_shutdown_handlers handles signal error on non-main thread."""
        import quantacrypt.core.fuse_ops as fops

        original = fops._shutdown_registered
        fops._shutdown_registered = False

        with patch("quantacrypt.core.fuse_ops.atexit.register") as mock_atexit, \
             patch("quantacrypt.core.fuse_ops.signal.signal",
                   side_effect=ValueError("not main thread")):
            # Should not raise even though signal.signal fails
            _ensure_shutdown_handlers()
            assert mock_atexit.call_count == 1

        fops._shutdown_registered = original
