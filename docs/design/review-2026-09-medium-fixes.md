# Review Run 2 — Medium+ Fix Batch

**Date:** 2026-09-01
**Source:** `.review/FINAL.md` (validation re-run, 47 findings). Scope: all Medium+
findings F-001..F-010, plus F-017 (coupled to F-008) and F-043 (co-located with F-002).

## F-002 — coalescing must simulate on-replay existence (High)

`_coalesce_pending_ops` decided tombstones by consulting `_persisted_paths`, a
snapshot from the *last save*. A rename of a baseline path emitted earlier in the
same batch materializes its destination on replay, which the snapshot can't see —
two reproduced resurrection scenarios. Fix: track `on_disk` (initialized from
`_persisted_paths`, updated as the scan walks the ops: as-is rename moves a name,
delete removes one) and use it for both tombstone decisions. Writes are deliberately
NOT added to `on_disk`: a write's only interaction with a later delete/rename on the
same path goes through `current_owner`, and when the delete drops the write, the
write never materializes anything on replay — adding it would emit spurious
tombstones. Alternative rejected: emitting every op uncoalesced (correct but
journals grow ~300 B/op and the estimate heuristic breaks).

## F-043 — journal-size estimate from the coalesced list (Low, co-located)

`save()` now coalesces once, estimates from the coalesced ops, and hands the same
list to `_append_journal(ops)` — no double coalesce, and superseded writes no longer
inflate the compact heuristic.

## F-001 — directory rename (High)

Two halves. `VolumeContainer.rename()` detects a directory source (slash-suffixed
key), refuses destinations that exist (EEXIST; dir-over-dir merge is out of scope)
and renames into the source's own subtree (EINVAL), then re-keys the dir entry and
**every key under the `old + "/"` prefix**, emitting one rename pending-op per key —
replay already handles per-key renames, so no format change. `QuantaCryptFUSE.rename`
re-keys child state (`_file_buffers`, `_dirty_files`, cache) by prefix for dir
sources. Alternative rejected: a `rename_tree` journal record (new record type =
format rev for a case per-key records already express).

## F-005 — rename onto a pending-unlink destination (Medium)

Destination-side sibling of the existing source guard: `new_vp in _pending_unlink`
raises EBUSY, matching `create()`'s reasoning — buffers are vpath-keyed, so letting
the rename land corrupts the unlinked-but-open fd's view and the deferred delete
would destroy the renamed file. The real fix remains the per-fd/inode buffer
refactor (F-013, queued).

## F-008 + F-017 — shutdown handlers dead in the GUI; emergency-save deadlock

`signal.signal` only works on the main thread; every GUI mount runs on a worker, so
the `except ValueError: pass` swallowed the install and `_shutdown_registered = True`
latched — SIGTERM never triggered `_emergency_save_all`. Fix: separate
`_atexit_registered` / `_signals_registered` flags; the signal half only latches on
success, so a later main-thread call (added to `__main__.main()`) installs it.
Coupled F-017: handlers now actually run in the GUI, so `QuantaCryptFUSE._lock`
becomes an `RLock` — a signal arriving while the main thread holds the lock (e.g.
inside `unmount_volume → save_all_dirty`) would otherwise self-deadlock in
`_emergency_save_all`.

## F-007 — unmount result checked; fusermount3 (Medium)

`unmount_volume` ran the OS unmount fire-and-forget *after* dropping tracking: a
failed unmount (file open in another app) left a live, serving, untracked mount —
invisible to emergency save and re-mountable into a two-writer journal. New order:
save (still tracked) → run subprocess → check `returncode` → pop tracking only on
success; failure raises RuntimeError carrying stderr so the UI can show "in use".
Linux prefers `fusermount3` when present (check_fuse_components already accepts
fusermount3-only systems).

## F-004 — Tk reads on the mount worker (Medium)

`_do_mount` now captures password/shares text on the main thread and passes plain
strings to the worker — same pattern the encryptor/decryptor already use.

## F-003 — CI on push/PR (Medium)

New `.github/workflows/ci.yml`: push + PR, ubuntu, `pip install -e ".[dev]"`,
`python -m pytest --tb=short -q --cov-fail-under=95` (explicit flag removes the
does-pytest-cov-honor-pyproject ambiguity). Ruff gate deferred: the repo has no ruff
config yet; adding a lint gate and a config in one batch with 12 behavior fixes
muddies bisection. Queued in TASKS.md.

## F-006 — requirements.txt drift (Medium)

Reduced to `-e .[dev]` + comment naming pyproject.toml as the single source of
truth (per CLAUDE.md). Deleting it outright was the alternative; kept as a pointer
because README and some tooling reference `pip install -r requirements.txt`.

## F-010 — plaintext temp zip in $TMPDIR (Medium)

The folder-encryption staging zip now goes in the **output file's directory**
(the volume the user chose for the ciphertext) as `.<outname>.qc-staging-<rand>.zip`
via `mkstemp` (0600), not the system temp dir — a crash no longer strands plaintext
on an unrelated, possibly unencrypted volume, and the leftover is visible next to
the expected output instead of hidden in $TMPDIR. Deliberately NOT added: zero-
overwrite "shredding" before delete — on APFS (CoW) overwriting doesn't destroy the
old extents, and pretending otherwise is worse than documenting the behavior
(README note added). Long-term: stream the zip straight into the encryptor (queued).

## Run 3 addendum (2026-09-01, same day)

The validation re-run (run 3, `.review/FINAL.md`) confirmed the batch above
held up but surfaced 1 High + 6 Medium, three of them in code the batch
touched. Fixes, in its order:

- **R3 F-001 (High, fix-batch regression)** — the staging-zip relocation let
  the zip include *itself* when the user saves the output inside the source
  folder (deflate output is incompressible → the writer never catches the
  reader → disk fills; reproduced). Three-part fix: `_zip_folder` skips
  `dst_path` during the walk, `_validate()` refuses an output inside the
  source folder, and `_zip_folder` takes `cancel_check` so Cancel works
  during compression.
- **R3 F-002** — `VolumeContainer.rename(x, x)` on a file hit the
  destination-exists branch, deleting the entry + journaling a tombstone,
  then KeyError-ing. Guard added: self-rename is a POSIX no-op success
  (`_rename_dir` already had one).
- **R3 F-003** — FUSE `rename` re-keyed buffers/dirty/cache but not
  `_open_files`, so rename-then-unlink of an open file bypassed the entire
  deferred-unlink machinery (eager delete, ENOENT on the live fd;
  reproduced). Both rename branches now re-key fd→vpath values.
- **R3 F-004** — `journal_suspicious` was computed and swallowed; worse,
  the first post-mount save truncates the suspicious tail (evidence gone).
  The Volume Manager now shows a warning dialog at mount completion,
  before the user writes.
- **R3 F-005** — unauthenticated 4-byte `ct_len` was read and allocated
  unbounded in `stream_decrypt_payload` and the decryptor's `_verify_run`
  (crafted `.qcx` → 4 GB allocation). Bounded to `CHUNK_SIZE + 16`,
  mirroring the journal's `_JOURNAL_MAX_HEADER_CT` guard.
- **R3 F-006** — the double-mount duplicate check ran before the lock and
  the FUSE worker started before the re-check, so a race loser left a
  live untracked mount corrupting the shared journal. The check, worker
  start, wait, and registration now form one atomic step under
  `_mount_lock` (teardown-on-duplicate rejected: never spawning the loser
  is simpler than unwinding it).
- **R3 F-007** — fusepy raises `EnvironmentError` (an OSError), not
  ImportError, when the package imports but no libfuse loads; all three
  guards caught only ImportError, so the guided FUSE-setup screen crashed
  on exactly the machines it was built for. Guards now catch both, and
  `_prepare_fuse_environment()` sets `FUSE_LIBRARY_PATH` to a detected
  `libfuse-t.dylib` when macFUSE is absent — fusepy's Darwin loader never
  looks for FUSE-T on its own.
- Also: `.review*/` gitignored (finding lists must never reach the public
  repo) and pyproject version aligned to the existing v1.3.0 tag (the CI
  bump-back job is still blocked on PAT_TOKEN; from-source runs showed a
  phantom "update available" banner).

## Run 4 addendum (2026-09-01, same day)

Run 4 (`.review/FINAL.md`, verdict **Healthy**) re-traced the run-3 fixes —
all held — and left 8 Mediums, all pre-existing gaps except one fix-adjacent
(R4 F-001). Fixes:

- **R4 F-001** — FUSE-layer `rename(a, a)` popped the destination buffer
  (which IS the source's) before the container-level self-rename guard could
  help, destroying unflushed writes (reproduced). Mirror guard added in the
  FUSE file branch.
- **R4 F-002** — batch encryption mapped colliding stems (`report.txt` +
  `report.md`) onto one `report.qcx`, silently destroying the first output.
  `_batch_output_paths()` uniquifies with the decryptor-style `_2` suffix;
  the overwrite pre-check uses the same list.
- **R4 F-003** — volume creation `open(path, "wb")`-truncated an existing —
  even currently mounted — `.qcv` with no guard on typed paths. `_do_create`
  now refuses mounted volumes and prompts before overwriting existing files.
- **R4 F-004** — `_shares_pending` was one global bool: saving ONE batch
  file's Shamir shares (or a partial, error-interrupted save) disarmed the
  unsaved-shares leave-guard for every other file. Now a set of per-file
  tokens; partial saves keep the file pending (the leave-guard's "Leave
  anyway?" remains the escape hatch).
- **R4 F-005** — `unmount_volume` ran `save_all_dirty()` which applied and
  CLEARED `_pending_unlink` before the OS unmount; a failed unmount left the
  mount serving with the limbo set gone, so a later flush resurrected
  unlinked-while-open files. `save_all_dirty(apply_pending_unlink=False)`
  for the pre-unmount save; a new `apply_pending_unlinks()` runs only once
  shutdown is certain (post-unmount-success, exit/signal paths).
- **R4 F-006** — the double-mount guard was per-process. Mounts now hold an
  advisory `flock(LOCK_EX | LOCK_NB)` on a `<volume>.lock` sidecar for the
  mount's lifetime. Sidecar, not the .qcv itself: `compact()` replaces the
  volume's inode via `os.replace()`, which would silently release an flock
  on the old inode. The 0-byte sidecar is never deleted (unlinking would
  race a concurrent locker onto a fresh unlocked inode).
- **R4 F-007** — `rename(file, dir)` with the slash-less destination FUSE
  actually passes missed the slash-suffixed dir key and installed durable
  `/d` + `/d/` twin keys (reproduced). The file branch now checks
  `new_path + "/"` and raises EISDIR.

### R4 F-008 — deferred by design: whole-file re-encrypt on flush/fsync

Every FUSE flush/fsync re-encrypts the full buffer and journals a complete
blob — O(n²) for fsync-heavy writers. **Deliberately NOT fixed here**:

- Skipping the journal append on fsync would violate fsync's durability
  contract (the run-2 F-001 fix exists precisely to honor it).
- Re-encrypting only changed chunks under the file's existing base_nonce
  would reuse an AES-GCM nonce with different plaintext — catastrophic
  (key-stream recovery). Any partial re-encryption therefore needs
  per-chunk nonce state in the directory entry, i.e. **format v3** with a
  chunk-patch journal record, migration, and its own design doc.
- Repeated fsyncs with no intervening writes already no-op via
  `_dirty_files`.

This is an accepted limitation of format v2, matching the documented
journal-boundary-rollback acceptance; queued in TASKS.md as the format v3
design task. Reviewers: treat as documented-accepted, not a finding.

## Run 5 addendum (2026-09-01, same day)

Run 5 (`.review/FINAL.md`, verdict "Concerns") found 7 Mediums: one genuine
regression from run 4, two residual gaps in the run-4 flock area, and four
pre-existing. Fixes:

- **R5 F-001 (run-4 regression)** — `_save_individual_shares` reassigns
  `qcx_path` (for the fingerprint) before the pending-token discard ran, so
  the single-file guard token `"__single__"` was never discarded and the
  guard stayed armed forever. Token captured at function top. Lesson: the
  getsource mirror-test replaced in run 4 couldn't catch this; the new
  behavior test simulates the actual call.
- **R5 F-002** — `_start` destroyed the results area (with any unsaved
  share cards) without the `_check_shares_saved()` guard `_reset`/`_close`
  already had. Guard added; consenting clears the pending set.
- **R5 F-003** — quitting the launcher with volumes mounted did a bare
  `destroy()`: in-flight kernel writes lost, mountpoint left dangling.
  `_quit_app()` prompts, unmounts everything, and refuses to quit while an
  unmount fails (files in use).
- **R5 F-004** — the flock sidecar was keyed on the caller-spelled path;
  a symlink alias contended on a different lock file. Now keyed on
  `os.path.realpath()`.
- **R5 F-005** — `mount_volume` opened the container (reading
  `_journal_end`) BEFORE acquiring the flock; racing another process's
  unmount could win the lock holding stale bookkeeping and truncate
  committed records. The flock is now acquired before `VolumeContainer`
  opens, held via a `lock_owned` try/finally through both foreground and
  background paths.
- **R5 F-006** — volume creation's mounted-check was in-process only; it
  now also probes the sidecar flock (acquire + immediately release) when
  the target exists, refusing if another process holds it.
- **R5 F-007** — an external eject (Finder) ended the FUSE worker without
  cleanup: permanent zombie tracking + held flock made the volume
  un-remountable until app restart. `_reap_dead_mounts_locked()` (called
  from mount, unmount, and `get_mounted_volumes`) detects dead worker
  threads, best-effort saves, and releases tracking + lock. The R2
  refinement — `apply_pending_unlinks()` failing after a successful OS
  unmount stranded tracking — is fixed with a try/finally.

## Run 6 addendum (2026-09-01, same day)

Run 6 (verdict **Healthy**) verified all run-5 fixes clean and left exactly
one Medium: Shamir k/n were re-read from the still-live spinboxes when
generating mnemonics and share files after encryption, so post-start drift
produced recovery material the decryptor rejects (reproduced in rounds 2
and 3). Fix: `_result_k`/`_result_n` frozen in `_start`/`_start_batch` at
the same moment the worker params are captured; every share-artifact path
(`_done`, `_done_batch`, `_save_individual_shares`, combined save) reads
the snapshot.

## Run 7 addendum (2026-09-01, same day)

Run 7 (verdict **Healthy**) verified the run-6 fix and — notably — fuzzed
the journal engine empirically (400-seed randomized differential test
against a shadow model + 800-point truncation sweep) with zero
divergences. Sole Medium: `friendly_error` matched "invalidtag" against
`str(exc)`, but cryptography's `InvalidTag` stringifies to `""`, so the
mainline wrong-password mount failure showed "InvalidTag (no additional
detail)". Fix: match against `msg or type(exc).__name__`.

## Run 8 addendum (2026-09-01, same day)

Run 8 (verdict **Healthy**) verified the run-7 fix; sole Medium: `statfs`
reported `max(container, 1 GB) − plaintext` as free space, which collapses
to ~zero once a volume holds ≈1 GB — Finder's free-space pre-flight then
refuses every copy into the mount (verified empirically three times, incl.
a live-mount statvfs check). Fix: free space is now the HOST filesystem's
(`os.statvfs` on the container's directory; total = used + host free), the
gocryptfs/Cryptomator approach. Live mount confirms the kernel now sees the
real host free space.

## F-009 — partial-range reads + chunk-granular dirty tracking (Medium)

Implemented per the existing design doc `docs/design/fuse-partial-range-reads.md`
(see it for the format-level rationale; deviations, if any, recorded there).
Summary: `VolumeContainer.read_file_range(vpath, offset, length)` decrypts only the
64 KB chunks covering the range; FUSE `read()` uses it instead of materializing the
whole file, and `open()` no longer eagerly decrypts. Writes still materialize the
full buffer (write path unchanged — chunk-granular *write-back* needs a journal
record that can patch ranges, i.e. a format rev; explicitly out of scope here).
