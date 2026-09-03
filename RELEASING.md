# Releasing QuantaCrypt

## Version management

The version is defined in one place: the `version` field in `pyproject.toml`.

It propagates automatically to:
- `__version__` at runtime (via `importlib.metadata`)
- `CFBundleShortVersionString` / `CFBundleVersion` in the .app bundle (via `build.py`)

In CI, the workflow also stamps the git tag version into both `pyproject.toml` and
`src/quantacrypt/__init__.py` before building, so the frozen app always shows the
correct release version. The in-app update checker queries the GitHub Releases API
and shows a banner when a newer version is available.

## How to release

1. **Tag and push** — the version comes from the tag name (no manual bump needed):

   ```bash
   git tag v1.1.0
   git push origin master --tags
   ```

2. **GitHub Actions takes over** — the `release.yml` workflow will:
   - Run the full test suite on Apple Silicon
   - Stamp the tag version into `pyproject.toml` and `__init__.py` before building
   - Build separate `.dmg` installers for **arm64** (Apple Silicon) and **x86_64** (Intel)
   - Create a GitHub Release with both DMGs attached
   - Auto-generate release notes from commits since the last tag
   - Commit the version bump back to `master` so the repo stays in sync

3. **The release appears** at:
   ```
   https://github.com/alexboccard/QuantaCrypt/releases/tag/v1.1.0
   ```
   with two downloads: `quantacrypt-arm64.dmg` and `quantacrypt-x86_64.dmg`.

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

The `.qcx` file format has its own `FORMAT_VERSION` (currently 1) in `crypto.py`, which is independent of the app version and only changes when the binary format itself changes.

## Dependency lock

`uv.lock` is the source of truth; `requirements-lock.txt` is its hash-pinned
export with every extra, used by CI, the release workflow and local builds
(`pip install --require-hashes`). After changing `pyproject.toml`:

```bash
uv lock
uv export --frozen --no-emit-project --all-extras --format requirements.txt -o requirements-lock.txt
```

CI also runs `pip-audit` against the lock. The python.org installer used for
the x86_64 release build is verified against `PYTHON_PKG_SHA256` in
`release.yml`; update both together.

## Future improvements

- **Code signing**: add a Developer ID certificate to the GitHub Actions runner to eliminate the Gatekeeper "unidentified developer" warning
- **Notarization**: submit the `.dmg` to Apple via `xcrun notarytool` for full Gatekeeper approval
