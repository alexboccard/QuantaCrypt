# Releasing QuantaCrypt

## Version management

The version is defined in one place: the `version` field in `pyproject.toml`.

It propagates automatically to:
- `__version__` at runtime (via `importlib.metadata`)
- `CFBundleShortVersionString` / `CFBundleVersion` in the .app bundle (via `build.py`)

In CI, every build job stamps the git tag version before building, with
`scripts/stamp_version.py`:

```bash
python3 scripts/stamp_version.py 1.4.0          # rewrite
python3 scripts/stamp_version.py 1.4.0 --check  # verify only
```

It rewrites `pyproject.toml`, `src/quantacrypt/__init__.py` and
`macos/project.yml`'s `CFBundleShortVersionString`, and **exits non-zero if any
of the three no longer matches** — the `sed` substitutions it replaced exited 0
on a no-match and would have shipped a release labelled with the previous
version. Since the in-app update checker compares the running version against
GitHub Releases, that left every user on an "update available" banner that
installing could not clear. `bump-version` runs the same script, so `master`
carries the version that was actually released.

## How to release

1. **Tag and push** — the version comes from the tag name (no manual bump needed):

   ```bash
   git tag v1.1.0
   git push origin master --tags
   ```

2. **GitHub Actions takes over** — the `release.yml` workflow will:
   - Run the full test suite on Apple Silicon
   - Stamp the tag version into `pyproject.toml`, `__init__.py` and `macos/project.yml`
   - Build the Tkinter `.dmg` installers for **arm64** (Apple Silicon) and **x86_64** (Intel)
   - Build the native SwiftUI app and its `.dmg` (arm64, on a `macos-26` runner)
   - Write `SHA256SUMS` for the three DMGs and sign a build-provenance
     attestation for them (`gh attestation verify <dmg> --owner alexboccard`)
   - Create a GitHub Release with the DMGs and `SHA256SUMS` attached
   - Auto-generate release notes from commits since the last tag
   - Commit the version bump back to `master`, together with a regenerated
     `uv.lock` / `requirements-lock.txt`, so the repo stays in sync

3. **The release appears** at:
   ```
   https://github.com/alexboccard/QuantaCrypt/releases/tag/v1.1.0
   ```
   with three downloads: `quantacrypt-arm64.dmg` and `quantacrypt-x86_64.dmg`
   (Tkinter app), and `QuantaCrypt-native-arm64.dmg` (native SwiftUI app),
   plus `SHA256SUMS`.

## Local build (without CI)

```bash
pip install --require-hashes -r requirements-lock.txt && pip install --no-deps -e .

# Build for current machine's architecture
python scripts/build.py

# Build for a specific architecture
python scripts/build.py --arch arm64
python scripts/build.py --arch x86_64

# Skip tests (if already run separately)
python scripts/build.py --arch arm64 --skip-tests
```

Output lands in `dist/quantacrypt.app` and `dist/quantacrypt-{arch}.dmg`.

### Native app in one command

```bash
python scripts/build.py --native --skip-tests      # → dist/QuantaCrypt.app + dist/QuantaCrypt-native-<arch>.dmg
python scripts/build.py --native --skip-tests --no-dmg
```

`--native` builds the `qc-core` helper bundle, renders the app and document
icons from `src/quantacrypt/assets/` into `macos/QuantaCrypt/Resources/`,
runs `xcodegen generate` and a Release `xcodebuild`, verifies that the helper
is inside the bundle and that the signature checks, copies the app to
`dist/`, and wraps it in the same drag-to-Applications DMG as the Tk app.
Set `CODESIGN_IDENTITY` for a Developer ID build (ad-hoc otherwise). The
result is a single `.app`: the SwiftUI interface plus the Python core at
`Contents/Helpers/qc-core.app`.

### Core helper for the native shell

The SwiftUI app in `macos/` does not embed Python; it launches `qc-core`, a
PyInstaller build of the JSON-lines core service packaged as a headless
`.app` (codesign only accepts nested code that is itself a signed bundle)
(`docs/design/core-service-protocol.md`):

```bash
python scripts/build.py --helper --skip-tests            # → dist/qc-core.app (headless bundle; --arch arm64|x86_64 to cross-build)
```

The build runs a smoke request against the binary and fails if it does not
answer. `--native` runs this for you. The Xcode project copies `dist/qc-core.app` into
`QuantaCrypt.app/Contents/Helpers/` (see `macos/project.yml`); build the
helper first, then the app:

```bash
python scripts/build.py --icons --skip-tests   # .icns are gitignored artifacts; xcodebuild needs them
cd macos && xcodegen generate && xcodebuild -scheme QuantaCrypt -configuration Release build
```

## Version scheme

Follow [Semantic Versioning](https://semver.org):

- **Major** (2.0.0) — breaking changes to the `.qcx` file format
- **Minor** (1.1.0) — new features, backward-compatible
- **Patch** (1.0.1) — bug fixes only

The `.qcx` file format has its own `FORMAT_VERSION` (currently 2) in `crypto.py`, and `.qcv` volumes their own `VOLUME_FORMAT_VERSION` (currently 3) in `volume.py`. Both are independent of the app version and only change when the binary format itself changes. Readers keep every earlier version openable: `tests/fixtures/v1/` holds real format-1 `.qcx` and format-2 `.qcv` containers written with the shipped Argon2id parameters, and `tests/test_audit_2026_09.py` opens them on every run.

## Dependency lock

`uv.lock` is the source of truth; `requirements-lock.txt` is its hash-pinned
export with every extra, used by CI, the release workflow and local builds
(`pip install --require-hashes`). After changing `pyproject.toml`:

```bash
uv lock
uv export --frozen --no-emit-project --all-extras --format requirements.txt -o requirements-lock.txt
```

CI enforces this rather than trusting the step to be remembered: the `test`
job runs `uv lock --check` and re-exports `requirements-lock.txt`, failing on
any diff. It also runs `pip-audit` against the lock. `bump-version`
regenerates both files after stamping the released version, because `uv.lock`
records the project's own version and would otherwise lag by one release
forever.

### Every build input is pinned

- **Actions** by full commit SHA with a `# vX.Y.Z` comment; Dependabot keeps
  the pins current. `tests/test_release_scripts.py` fails on a tag pin.
- **Python packages** by hash, and the *build backend* too: pip's build
  isolation would otherwise fetch an unpinned setuptools to build fusepy's
  sdist and this project, so every job installs `setuptools` from the lock
  first (`scripts/lock_subset.py setuptools`) and then runs pip with
  `--no-build-isolation`.
- **The interpreter**: one `PYTHON_VERSION` in `release.yml` for all three
  artefacts. The x86_64 job installs it from the python.org universal2 pkg,
  verified against `PYTHON_PKG_SHA256`; the other jobs ask setup-python for
  the same version. Bump all three together (record the new SHA-256 with
  `shasum -a 256` on the downloaded pkg).
- **XcodeGen** by release and SHA-256 in `scripts/install_xcodegen.sh` —
  it writes the build phases the signed xcodebuild executes, so it must not
  come from whatever homebrew-core serves that day. Bump the version and the
  digest together (the script's header says how).

## Code signing

`build.py` ad-hoc signs every Mach-O inside the bundle, then the main
executable, then the outer `.app`, and finally runs
`codesign --verify --deep --strict` over the result. **Any of those failing
aborts the build**; the release jobs repeat the verification on the artefact
they are about to upload. An `.app` with absent or inconsistent signatures
opens as "damaged and can't be opened" instead of the expected
unidentified-developer prompt, so a silently-unsigned build is worse than no
build. Set `CODESIGN_IDENTITY` to sign with a Developer ID instead: the
executable and the outer bundle are then signed with `--options runtime
--timestamp` and `scripts/hardened-runtime.entitlements` (library validation
off, so libfuse from another Team ID loads; unsigned executable memory, for
cffi), which is what notarization will need.

The native app is built with `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` and
checked afterwards: a plain `xcodebuild build` otherwise injects
`com.apple.security.get-task-allow`, the entitlement that lets any same-user
process attach a debugger to the running app and read the memory holding
passwords and shares. `build.py` and the release job both fail on it.

## Future improvements

- **Code signing**: add a Developer ID certificate to the GitHub Actions runner to eliminate the Gatekeeper "unidentified developer" warning
- **Notarization**: submit the `.dmg` to Apple via `xcrun notarytool` for full Gatekeeper approval
