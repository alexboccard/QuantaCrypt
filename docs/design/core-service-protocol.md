# Core service protocol (`qc-core`)

Date: 2026-09-02. Status: implemented (v1). Parent decision: `native-macos-ui.md`.

## Problem

The native macOS shell (SwiftUI) needs to drive the Python core — encrypt,
decrypt, verify, inspect, volumes — without importing Python. The Tk UI also
re-implements pieces of the core (key derivation, first-chunk verification,
output naming, folder zipping) that belong below the UI. Both need one
process-level API that streams progress and supports cancellation.

## Options considered

1. **HTTP daemon on localhost** (the trading client's pattern). Familiar, but
   secrets would travel over a socket any local process can connect to, and a
   port must be chosen and guarded. Rejected for a crypto tool.
2. **Embed CPython in the Swift app** (PythonKit + Python.xcframework). One
   binary, but every call crosses a GIL/threading boundary from Swift and FUSE
   mounts then live inside the GUI process. Kept as a later option.
3. **Helper process speaking JSON lines over stdin/stdout.** Only the parent
   can talk to it; no ports; the process owns the FUSE mounts and dies with
   the app (shutdown handlers unmount). Trivial to drive from `Process` in
   Swift and from tests in Python. **Chosen.**

## Design

Executable: `qc-core` (entry point `quantacrypt.cli:main`), also
`python -m quantacrypt.cli`. One request per line on stdin, one JSON object
per line on stdout, nothing else on stdout (logs go to stderr).

### Request

```json
{"id": "r1", "op": "encrypt", "params": {...}}
```

`id` is any string chosen by the client; every event for the request carries
it back. Requests run concurrently on worker threads; control ops (`cancel`,
`shutdown`, `version`, `ping`) are answered inline.

### Events

```json
{"id": "r1", "event": "progress", "stage": "kdf", "label": "Securing password", "pct": 0.0, "message": "<raw core message>"}
{"id": "r1", "event": "done", "result": {...}}
{"id": "r1", "event": "error", "code": "wrong_credentials", "message": "<friendly text>", "detail": "<raw exception>"}
```

Error codes: `wrong_credentials`, `cancelled`, `io`, `permission_denied`,
`format`, `not_found`, `busy`, `unsupported`, `invalid_request`, `internal`. `message` is the same
`friendly_error` text the Tk UI shows; `detail` is for logs and disclosure
triangles.

Stages: `compress`, `kdf`, `kem`, `lock`, `payload`, `write`, `split`,
`read`, `mount`, `verify`. `pct` is within the stage (0–1) when the core
reports one, else `null`.

### Ops

| op | params | result |
|---|---|---|
| `version` | — | `{version, format_version, platform, python}` |
| `ping` | — | `{}` |
| `fuse_check` | — | `{fuse_backend: {ok, detail}, fusepy: {ok, detail}, ok}` |
| `inspect` | `path` (.qcx) | `{path, size, version, mode, threshold, total, embedded, argon2}` |
| `volume_inspect` | `path` (.qcv) | `{path, size, format_version, mode, threshold, total}` |
| `encrypt` | `source` (file or folder), `output`, `mode` (`password`\|`shamir`), `password`, `k`, `n`, `embed_binary` (optional path prepended for self-executing files) | `{output, size, filename, mode, threshold, total, shares: [{index, code, mnemonic}]}` |
| `decrypt` | `path`, `output_dir`, `password` or `shares` (codes or 50-word mnemonics), `verify_only` | `{verified}` or `{output, filename, size, original_size, timestamp, renamed}` |
| `volume_create` | `path`, `mode`, `password` or `k`,`n` | `{path, mode, shares}` |
| `volume_mount` | `path`, `mount_point`, `password` or `shares` | `{mount_point, volume_path, journal_suspicious}` |
| `volume_unmount` | `mount_point` | `{mount_point}` |
| `volume_list` | — | `{volumes: [{mount_point, volume_path, stats: {file_count, dir_count, total_plaintext_size, container_size, ...} \| null}]}` |
| `cancel` | `target` (request id) | `{cancelled: bool}` |
| `shutdown` | — | `{}` then the process unmounts everything and exits |

**Vocabulary.** Requests accept `mode` = `password` (alias `single`) or
`shamir`; results always report the on-disk format's `mode` = `single` or
`shamir`, because that is what `inspect` reads back from a file.

**Cancellation coverage.** `encrypt`, `decrypt` and `volume_create` poll
the token between stages and per chunk; `volume_mount` checks it before
the FUSE call only; `fuse_check`, `volume_unmount`, `volume_list` and the
inspect ops are short and never cancel. A client should fail such
requests locally after a grace period rather than wait for a
`cancelled` event.

Passwords and shares travel in the request JSON. That is acceptable because
stdin is a private pipe from the parent process; the same secrets already
live in the parent's memory. The service never logs params.

### Lifecycle

- EOF on stdin → no more requests: in-flight work finishes (a one-shot
  client can write one request and close the pipe), then every volume is
  saved and unmounted and the process exits 0.
- `shutdown` or SIGTERM → the abrupt form: cancel in-flight requests
  first, then unmount and exit.
- One writer lock serialises stdout; events from different requests
  interleave line-by-line.
- Output files are written to `<output>.tmp` and `os.replace`d; decrypt
  writes to a `mkstemp` file in the output directory and renames to the
  original filename (with `_2` suffixing on collision, reported as `renamed`).
- Folder sources are zipped to a `0600` staging file in the output directory
  (same reasoning as the Tk encryptor: never `$TMPDIR`), encrypted as
  `<folder>.zip`, and the staging file is always removed.

## What moved into `core/`

- `core/package.py`: `load_pkg`, `derive_final_key`, `verify_first_chunk`,
  `encrypt_to_qcx`, `decrypt_qcx`, `safe_output_name`, `unique_path`,
  `folder_stats`, `zip_folder`, `batch_output_paths`, `normalize_shares`.
- `core/errors.py`: `friendly_error`, `classify_error`.
- `core/service.py`: the dispatcher; `cli.py`: the executable.

The Tk UI keeps its names (`decryptor.load_pkg`, `encryptor._zip_folder`,
`shared.friendly_error`) as re-exports so nothing user-facing changes in this
step. Follow-up: route the Tk wizards through `package.py` too and delete the
duplicated key-derivation code in `decryptor.py`.

## Trade-offs

- A helper process means one more binary to sign and bundle. Accepted; it is
  the same helper the Tk app would need for a `--classic` mode later.
- JSON lines cannot carry binary; every payload is a path. Fine: the core is
  file-to-file by design.
- Progress is stage + optional percent, not bytes. The client keeps its own
  ETA logic (as the Tk `StagedProgressBar` does).
