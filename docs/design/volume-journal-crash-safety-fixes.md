# Volume Journal Crash-Safety Fixes (post-review blockers)

**Date:** 2026-09-01
**Source:** `.review/FINAL.md` findings F-001, F-004, F-005, F-006, F-008 (data-loss cluster)
and F-002, F-003, F-007 (FUSE wiring/bundling). Round files in `.review/`.

## Problem

The v1.3.0 volumes feature had five independent data-loss/corruption bugs in the
journal/compact/FUSE lifecycle, plus FUSE wiring that never worked through a real
mount. All were found by a 3-round independent review (zero refutations).

## Decisions

### F-004 — valid-journal-end bookkeeping
`_read_journal_records` now returns `(records, valid_end, suspicious)`. The container
tracks `_journal_end` (absolute offset just past the last valid record).
`_append_journal` seeks to `_journal_end` and **truncates** before appending, so a
crash-garbage tail can never orphan subsequent saves. Options considered: (a) remember
end + truncate on append (chosen — no format change, reclaims dead bytes); (b) resync
scan past garbage (rejected: garbage length unknowable, records are offset-bound via AAD).

### F-008 — rollback detection (partial)
Replay now distinguishes the crash shape (record runs out of bytes at EOF → benign)
from a *complete* record failing authentication (→ `journal_suspicious = True` +
`logging` warning). Crash truncation can only produce out-of-bytes tails because
records are written sequentially and fsync'd; a fully-present record that fails auth
means corruption or deliberate rollback/tampering. **Not done here:** an authenticated
journal generation/length trailer (would need a format rev); a tamperer who truncates
at an exact record boundary is still undetected. Follow-up captured in TASKS.md.

### F-005 — transactional compact()
`compact()` no longer mutates `dir_index`/`metadata`/header state before the atomic
`os.replace()`. New offsets, re-keyed entries, bumped `format_version`, and new nonces
are computed into fresh objects; the in-memory state is committed only after the
replace succeeds. A failed compact (disk full) leaves both disk and memory exactly as
before, so a retry is safe. This also fixes F-012 (persisted metadata kept claiming
format v1 after upgrade) for free, since the version bump now happens in the copy that
gets encrypted.

### F-006 — coalescing tombstones
`_coalesce_pending_ops` treated any pending `write X` as proof `X` was created
in-session, dropping delete/rename records. Wrong when `X` already persisted (baseline
or earlier save): replay resurrected deleted files. The container now tracks
`_persisted_paths` (snapshot of `dir_index` keys at open, refreshed after every
successful save/compact). Coalescing keeps a `delete` tombstone — and converts a
`rename` of a persisted-source path into a tombstone — whenever the path persists on
disk. Alternative (always emit every record, ~300 B each) rejected only because the
tombstone rule is nearly as simple and keeps journals smaller.

### F-001 — durability at flush time
FUSE `flush()`/`release()`/`unlink()`/`rmdir()`/`mkdir()`/`rename()` now call
`volume.save()` when the volume is dirty (journal append is O(delta) by design), and a
`fsync()` FUSE op is implemented. Writes therefore hit the disk journal at the same
moment the kernel is told they're flushed — SIGKILL/power loss loses at most the
current unflushed buffer, not the whole session. Since `_append_journal` clears
`_file_data`, this also bounds the previous unbounded RAM growth. Trade-off: one
fsync per kernel flush (chatty writers pay; F-039 re-encrypt cost unchanged, still open).

### F-007 — fuse.Operations subclass
`QuantaCryptFUSE` now subclasses `fuse.Operations` (fusepy's dispatch calls the
operations object; a plain class made every op fail EINVAL after a "successful" mount).
Import is guarded: without fusepy a no-op stand-in base keeps the module importable
(direct-call tests, `check_fuse_available` flow). `chmod`/`utimens` are implemented as
in-memory attribute updates (not journaled — cosmetic), `fsync` persists.

### F-002 — bundling
`fusepy` added to the `dev` extra (CI installs `.[dev]`) and to PyInstaller `HIDDEN`
so shipped .apps can mount. The in-app "Install fusepy" pip button is suppressed when
frozen (`sys.executable` is the GUI in a bundle — it respawned the app instead of pip).

### F-003 — self-executing .qcx
`_find_dec()` no longer returns `sys.executable` when frozen: the build is onedir, so
the embedded Mach-O could never bootstrap standalone, and appending payload bytes
invalidates the arm64 signature ("killed: 9"). The embed checkbox simply doesn't appear
in frozen builds until a dedicated onefile decryptor artifact exists (follow-up).

## Promoted mid-fix: F-015 + F-021 (live-mount evidence)

The first real macFUSE end-to-end test (which no review round could run) failed and
exposed why these two "latent behind F-007" findings are actually load-bearing:

- macOS stores xattrs in AppleDouble `._` sidecars (our getxattr/setxattr are
  ENOTSUP) and renames a fresh sidecar **over the existing one** — hitting the
  rename-refuses-to-replace bug (F-015) on the very first kernel rename.
- The resulting errno-less `FileExistsError` hit fusepy's wrapper, whose
  `e.errno > 0` check raises TypeError on `None` and falls into a broken
  critical-exception path → `fuse: bad error value` returned to the kernel,
  with unpredictable downstream behavior (F-021).

Fixes: POSIX replace semantics in `VolumeContainer.rename()` (regular-file
destinations replaced with a tombstone pending op; directory destinations still
refuse with EISDIR), errno on every container refusal, and a coalescing correction —
a re-keyed write is emitted at the *rename's* position, not the original write's,
so the replaced destination's tombstone doesn't replay after the fresh content.

Live-mount validation (macFUSE, real kernel dispatch): mount → write → read →
readdir → rename → delete → **fresh container reads flushed data mid-mount
(crash-durability)** → unmount → reopen. All passed.

## Regression tests

- truncated tail → reopen → write → save → reopen → data survives (F-004)
- complete-record corruption sets `journal_suspicious`; crash truncation does not (F-008)
- failed compact (fsync raises) → reads still work → retry compact → all content intact (F-005)
- edit+delete and edit+rename of persisted paths stay deleted/moved across reopen (F-006)
- FUSE flush/fsync persist to disk immediately, readable by a fresh container (F-001)
- `issubclass(QuantaCryptFUSE, fuse.Operations)` + chmod/utimens smoke (F-007)
