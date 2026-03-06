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
pip install ".[dev]"

# Build for current machine's architecture
python scripts/build.py

# Build for a specific architecture
python scripts/build.py --arch arm64
python scripts/build.py --arch x86_64

# Skip tests (if already run separately)
python scripts/build.py --arch arm64 --skip-tests
```

Output lands in `dist/quantacrypt.app` and `dist/quantacrypt-{arch}.dmg`.

## Version scheme

Follow [Semantic Versioning](https://semver.org):

- **Major** (2.0.0) — breaking changes to the `.qcx` file format
- **Minor** (1.1.0) — new features, backward-compatible
- **Patch** (1.0.1) — bug fixes only

The `.qcx` file format has its own `FORMAT_VERSION` (currently 1) in `crypto.py`, which is independent of the app version and only changes when the binary format itself changes.

## Future improvements

- **Code signing**: add a Developer ID certificate to the GitHub Actions runner to eliminate the Gatekeeper "unidentified developer" warning
- **Notarization**: submit the `.dmg` to Apple via `xcrun notarytool` for full Gatekeeper approval
