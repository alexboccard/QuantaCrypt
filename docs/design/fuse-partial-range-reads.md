# Design: Partial-range reads in FUSE layer

## Problem

`QuantaCryptFUSE.open()` materialises the full decrypted plaintext of a file
into `_file_buffers[vpath]` before any `read()` can return data. For a 500 MB
file inside a mounted volume, the first `open()` stalls for 2–3 s — visible
as a beach-ball cursor in Finder, a hang in QuickLook, or "waiting for
metadata" in media players that start by seeking to the end of the file.

## Why it's the way it is

The existing chunked AES-GCM format already supports random access: each
64 KB chunk is an independent AEAD unit with a deterministic nonce
(`base_nonce XOR chunk_index`). So for any byte offset in a file we can
locate the chunk, decrypt just that chunk, and return the slice.

The current code doesn't do this because:
1. The FUSE buffer was designed to double as the write buffer — writes
   modify `_file_buffers[vpath]` in place and `release()` re-encrypts the
   full buffer. Partial reads would complicate this.
2. `VolumeContainer.read_file()` returns the full plaintext (and the
   optional whole-plaintext SHA-256 integrity check), which doesn't fit a
   range-read API.

## Proposed design

### New read path (read-only files)

Add `VolumeContainer.read_file_range(vpath, offset, size) -> bytes`:

1. Locate the dir_index entry, resolve `base_nonce`, `chunk_count`, and
   the absolute on-disk offset of the blob.
2. Compute `first_chunk = offset // chunk_size`, `last_chunk = min(
   chunk_count - 1, (offset + size - 1) // chunk_size)`.
3. Open the container file, seek to the blob's `first_chunk` record
   header, and iterate decrypting chunks into a buffer (with the existing
   seq + AAD checks) until we have enough plaintext to satisfy the range.
4. Slice the buffer to exactly `[offset, offset + size)` and return.

The whole-plaintext SHA-256 check is skipped — FUSE reads already skip it
post-commit-`99a2342`. Users who want an end-to-end integrity scan invoke
`read_file(verify_hash=True)` (from a future "Verify volume integrity"
menu item).

### FUSE ops

`QuantaCryptFUSE.open()`:
- No longer loads the full plaintext.
- Just records the fd → vpath mapping.
- Returns immediately.

`QuantaCryptFUSE.read(path, size, offset, fh)`:
- If `vpath` is dirty (buffered writes pending), fall back to the
  existing full-buffer path.
- Otherwise call `volume.read_file_range(vpath, offset, size)` and return.

`QuantaCryptFUSE.write(path, data, offset, fh)`:
- First write on a previously-unopened file: lazily materialise the full
  plaintext into `_file_buffers[vpath]` (same cost as today's eager
  open, but only paid if the file is actually modified).
- Subsequent writes: operate on the buffer as today.

The LRU cache changes meaning: it now caches *decrypted chunks* rather
than *decrypted files*, keyed by `(vpath, chunk_index)`. This amplifies
the benefit for streaming readers that re-read the same chunks (ffmpeg
keyframe scans, archive tools seeking the central directory, etc.).

### Cost

- Read latency of the first byte drops from O(file size) to O(single
  chunk). For a 500 MB file the first byte is ready in ~1 ms instead of
  ~2 s.
- Per-read overhead goes from O(slice copy) to O(chunk decrypt +
  slice copy). For aligned reads the chunk decrypt is amortised across
  many reads via the LRU cache.
- Writes that modify even one byte still pay the full-plaintext cost on
  first touch — this design doesn't change that. A future design
  (copy-on-write per chunk) could address it.

## Trade-offs

- **Behaviour change on corruption**: today a corrupt 64 KB chunk at
  byte 400 MB of a 500 MB file is caught at `open()`. With range reads
  it's caught only when that byte range is actually read. That matches
  filesystem semantics (you don't want `open()` to read-and-verify a
  10 GB file) but means a corrupt file can partially mount.
- **LRU cache key change** is backward-incompatible for the in-memory
  cache, but since the cache is per-process there's no disk-format
  impact.
- **Dirty-file detection** becomes critical: the range path must never
  be taken while `_dirty_files[vpath]` is set, otherwise a recent write
  would be missed.

## Out of scope

- Copy-on-write per chunk during writes (large win but bigger change;
  separate doc when we pick it up).
- Parallel chunk decryption (modern macOS has AES-NI; single-threaded
  decrypt is already ~1 GB/s).

## Status

Not implemented. This is the biggest remaining FUSE-latency item; it
requires a new public method on `VolumeContainer` and a non-trivial
rework of `QuantaCryptFUSE.open()` / `read()` / `write()` behaviour. We
keep the existing eager-open path for now — RAM is bounded at one file
at a time and the full-buffer approach is measurably correct across all
current tests.
