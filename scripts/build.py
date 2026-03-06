#!/usr/bin/env python3
"""
Build script — produces a self-contained macOS app bundle.

  macOS:   dist/quantacrypt.app   (double-clickable .app bundle)

The app handles all three launch modes:
  - Run directly              → Launcher (choose Encrypt or Decrypt)
  - quantacrypt myfile.qcx   → Decryptor (opens that file)
  - ./myfile.qcx             → Decryptor (self-executing .qcx)

When encrypting with "Embed decryptor" ticked, the binary embeds itself
into the .qcx file. No companion files needed — just the one binary.

Usage:
  python3 scripts/build.py          (from repo root)
"""

import io
import os
import plistlib
import shutil
import struct
import subprocess
import sys

# ROOT = repo root (one level up from scripts/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, "src")
PKG  = os.path.join(SRC, "quantacrypt")
DIST = os.path.join(ROOT, "dist")
WORK = os.path.join(ROOT, "build")
NAME = "quantacrypt"
BUNDLE_ID = "com.alexboccard.quantacrypt"
QCX_UTI   = "com.alexboccard.quantacrypt.qcx"

SUF = ".app"

HIDDEN = [
    "quantacrypt", "quantacrypt.core", "quantacrypt.core.crypto",
    "quantacrypt.ui", "quantacrypt.ui.shared", "quantacrypt.ui.launcher",
    "quantacrypt.ui.encryptor", "quantacrypt.ui.decryptor",
    "cryptography", "cryptography.hazmat.primitives.ciphers.aead",
    "argon2", "argon2.low_level",
    "kyber_py", "kyber_py.kyber",
    "shamirs", "shamirs.shamirs",
    "mnemonic",
    "tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox",
    # tkinterdnd2 must be in hidden imports so PyInstaller collects the
    # package. The native tkdnd/ directory is also bundled via --add-data below
    # because TkinterDnD._require() locates it via os.path.dirname(__file__).
    "tkinterdnd2", "tkinterdnd2.TkinterDnD",
    # zxcvbn must be bundled so the password strength bar works correctly
    # and the weak-password dialog fires. Without it the binary silently uses a
    # simpler fallback estimator and skips the weak-password warning entirely.
    "zxcvbn",
]


def _make_icns(png_path, out_path):
    """Generate a minimal .icns from a PNG using Pillow.

    Writes PNG-encoded icon slices for every standard macOS size so the dock
    icon looks sharp on both standard and Retina displays.
    """
    from PIL import Image
    src = Image.open(png_path).convert("RGBA")

    # (type_code, pixel_size)
    SIZES = [
        (b"icp4",   16), (b"icp5",   32), (b"icp6",   64),
        (b"ic07",  128), (b"ic08",  256), (b"ic09",  512),
        (b"ic10", 1024),
    ]

    chunks = b""
    for code, px in SIZES:
        resized = src.resize((px, px), Image.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format="PNG")
        data = buf.getvalue()
        chunk_len = 8 + len(data)          # 4-byte type + 4-byte length + data
        chunks += code + struct.pack(">I", chunk_len) + data

    header = b"icns" + struct.pack(">I", 8 + len(chunks))
    with open(out_path, "wb") as f:
        f.write(header + chunks)



def _build_icon():
    """Return (icon_flag_args, icon_path_for_cleanup) for PyInstaller --icon."""
    png = os.path.join(PKG, "assets", "icon.png")
    if not os.path.isfile(png):
        print("[!] icon.png not found — building without custom icon")
        return [], None

    out = os.path.join(ROOT, "icon.icns")
    try:
        _make_icns(png, out)
        print(f"[+] Generated {out}")
        return ["--icon", out], out
    except Exception as e:
        print(f"[!] Could not generate .icns ({e}) — skipping icon")
        return [], None


def _build_doc_icon():
    """Generate a .icns for the .qcx document type icon.

    Returns the path to the generated file, or None if doc_icon.png is missing.
    The .icns is copied into the .app bundle's Resources/ directory after build.
    """
    png = os.path.join(PKG, "assets", "doc_icon.png")
    if not os.path.isfile(png):
        print("[!] doc_icon.png not found — .qcx files will use a generic icon")
        return None

    out = os.path.join(ROOT, "doc_icon.icns")
    try:
        _make_icns(png, out)
        print(f"[+] Generated {out}")
        return out
    except Exception as e:
        print(f"[!] Could not generate doc .icns ({e}) — skipping document icon")
        return None


def _find_tkinterdnd2():
    """Return the tkinterdnd2 package directory, or None if not installed.
    Needed to add the native tkdnd shared-library tree via --add-data so that
    TkinterDnD._require() can resolve tkdnd/<platform>/ via __file__ at runtime.
    A hidden-import entry alone is not sufficient -- the package must be present
    on disk inside _MEIPASS, not just importable."""
    try:
        import tkinterdnd2 as _t
        return os.path.dirname(_t.__file__)
    except ImportError:
        return None


def _read_version():
    """Read the project version from pyproject.toml (single source of truth)."""
    toml_path = os.path.join(ROOT, "pyproject.toml")
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        import tomli as tomllib  # Python 3.10 fallback
    with open(toml_path, "rb") as f:
        cfg = tomllib.load(f)
    return cfg["project"]["version"]


def _patch_plist(app_path, icon_name):
    """Patch the Info.plist inside a built .app bundle.

    Sets the version strings, adds CFBundleDocumentTypes, and exports
    UTExportedTypeDeclarations so macOS recognises .qcx files and routes
    double-clicks to QuantaCrypt.
    """
    plist_path = os.path.join(app_path, "Contents", "Info.plist")
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)

    version = _read_version()
    plist["CFBundleIdentifier"] = BUNDLE_ID
    plist["CFBundleShortVersionString"] = version   # user-facing "1.0.0"
    plist["CFBundleVersion"] = version               # build number

    # Declare that we handle .qcx documents
    plist["CFBundleDocumentTypes"] = [
        {
            "CFBundleTypeName": "QuantaCrypt Encrypted File",
            "CFBundleTypeRole": "Editor",
            "LSHandlerRank": "Owner",
            "LSItemContentTypes": [QCX_UTI],
            "CFBundleTypeExtensions": ["qcx"],
            **({"CFBundleTypeIconFile": icon_name} if icon_name else {}),
        },
    ]

    # Export the UTI so macOS knows what .qcx means even before
    # the user has ever opened one
    plist["UTExportedTypeDeclarations"] = [
        {
            "UTTypeIdentifier": QCX_UTI,
            "UTTypeDescription": "QuantaCrypt Encrypted File",
            "UTTypeConformsTo": ["public.data"],
            "UTTypeTagSpecification": {
                "public.filename-extension": ["qcx"],
                "public.mime-type": "application/x-quantacrypt",
            },
            **({"UTTypeIconFile": icon_name} if icon_name else {}),
        },
    ]

    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f)

    print(f"[+] Patched {plist_path}")
    print(f"    Version:       {version}")
    print(f"    Bundle ID:     {BUNDLE_ID}")
    print(f"    Document type: .qcx → {QCX_UTI}")


def _create_dmg(app_path, arch_label=""):
    """Create a .dmg installer with a drag-to-Applications layout.

    The DMG contains:
      - The .app bundle
      - A symlink to /Applications

    Uses Finder's native icon view with snap-to-grid so the layout
    stays clean regardless of how the user resizes the window.

    Requires macOS (hdiutil + osascript).  Skipped gracefully on other platforms.
    """
    if sys.platform != "darwin":
        print("[!] DMG creation requires macOS — skipping")
        return None

    suffix = f"-{arch_label}" if arch_label else ""
    dmg_path = os.path.join(DIST, f"{NAME}{suffix}.dmg")
    volume_name = "QuantaCrypt"
    window_w, window_h = 480, 300
    icon_size = 128

    # Remove old DMG if present
    if os.path.isfile(dmg_path):
        os.remove(dmg_path)

    # Create a temporary writable DMG
    tmp_dmg = os.path.join(DIST, f"{NAME}_tmp.dmg")
    if os.path.isfile(tmp_dmg):
        os.remove(tmp_dmg)

    # Calculate size: app size + 20 MB headroom
    app_size = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, files in os.walk(app_path)
        for f in files
    )
    dmg_size_mb = max(app_size // 1_000_000 + 20, 50)

    print(f"\n[+] Creating DMG ({dmg_size_mb} MB)...")

    # Create a temporary read-write DMG
    subprocess.run([
        "hdiutil", "create",
        "-size", f"{dmg_size_mb}m",
        "-fs", "HFS+",
        "-volname", volume_name,
        tmp_dmg,
    ], check=True, capture_output=True)

    # Mount it
    result = subprocess.run(
        ["hdiutil", "attach", tmp_dmg, "-readwrite", "-noverify", "-noautoopen"],
        check=True, capture_output=True, text=True,
    )
    # Parse mount point from hdiutil output
    mount_point = None
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            mount_point = parts[-1].strip()
    if not mount_point:
        mount_point = f"/Volumes/{volume_name}"

    try:
        # Copy the .app into the DMG
        dest_app = os.path.join(mount_point, os.path.basename(app_path))
        subprocess.run(["cp", "-R", app_path, dest_app], check=True)

        # Create Applications symlink
        os.symlink("/Applications", os.path.join(mount_point, "Applications"))

        # Use AppleScript to configure the Finder window appearance.
        # "snap to grid" arrangement keeps icons centred even if the
        # user resizes the window — no fixed-position background needed.
        applescript = f'''
            tell application "Finder"
                tell disk "{volume_name}"
                    open
                    set current view of container window to icon view
                    set toolbar visible of container window to false
                    set statusbar visible of container window to false
                    set the bounds of container window to {{200, 200, {200 + window_w}, {200 + window_h}}}
                    set viewOptions to the icon view options of container window
                    set arrangement of viewOptions to snap to grid
                    set icon size of viewOptions to {icon_size}
                    close
                    open
                    update without registering applications
                    delay 2
                    close
                end tell
            end tell
        '''
        subprocess.run(["osascript", "-e", applescript],
                       capture_output=True, timeout=60)

    finally:
        # Unmount
        subprocess.run(["hdiutil", "detach", mount_point, "-quiet"],
                       capture_output=True)

    # Convert to a compressed, read-only DMG
    subprocess.run([
        "hdiutil", "convert", tmp_dmg,
        "-format", "UDZO",
        "-imagekey", "zlib-level=9",
        "-o", dmg_path,
    ], check=True, capture_output=True)

    # Clean up the temporary writable DMG
    os.remove(tmp_dmg)

    sz = os.path.getsize(dmg_path) / 1_000_000
    print(f"[+] Created {dmg_path}  ({sz:.1f} MB)")
    return dmg_path


def _run_tests():
    """Run the test suite with coverage and abort the build on failure.

    Reads the minimum coverage threshold from pyproject.toml
    ([tool.coverage.report] fail_under).  Defaults to 0 (no minimum)
    if the key is absent, so coverage data is still collected and printed.
    """
    print(f"\n{'='*60}\n  Running tests + coverage\n{'='*60}\n")

    # Read fail_under from pyproject.toml so there's a single source of truth
    fail_under = 0
    toml_path = os.path.join(ROOT, "pyproject.toml")
    if os.path.isfile(toml_path):
        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:
            try:
                import tomli as tomllib  # Python 3.10 fallback
            except ModuleNotFoundError:
                tomllib = None
        if tomllib:
            with open(toml_path, "rb") as f:
                cfg = tomllib.load(f)
            fail_under = (
                cfg.get("tool", {})
                   .get("coverage", {})
                   .get("report", {})
                   .get("fail_under", 0)
            )

    cmd = [
        sys.executable, "-m", "pytest",
        "--tb=short", "-q",
        f"--cov-fail-under={fail_under}",
    ]

    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"\n[!] Tests failed or coverage below {fail_under}% — aborting build.")
        sys.exit(1)

    print(f"\n[+] All tests passed (coverage >= {fail_under}%)\n")


def _parse_args():
    """Parse build CLI arguments."""
    import argparse
    p = argparse.ArgumentParser(description="Build QuantaCrypt macOS app bundle")
    p.add_argument("--arch", choices=["arm64", "x86_64", "universal2"],
                   default=None,
                   help="Target architecture. Default: current machine's arch. "
                        "Use 'universal2' for a fat binary that runs on both "
                        "Intel and Apple Silicon.")
    p.add_argument("--skip-tests", action="store_true",
                   help="Skip the test suite (useful for CI split builds)")
    return p.parse_args()


def main():
    args = _parse_args()
    os.makedirs(DIST, exist_ok=True)

    # ── Gate: tests + coverage must pass before we build ──
    if not args.skip_tests:
        _run_tests()

    icon_args, icon_tmp = _build_icon()
    doc_icon_tmp = _build_doc_icon()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name",      NAME,
        "--distpath",  DIST,
        "--workpath",  WORK,
        "--specpath",  WORK,
        "--noconsole",
        "--clean",
        "--noconfirm",
        "--osx-bundle-identifier", BUNDLE_ID,
    ] + icon_args

    # Universal binary / arch targeting (macOS only)
    target_arch = args.arch
    if target_arch:
        cmd += ["--target-arch", target_arch]
        arch_label = target_arch
    else:
        import platform
        arch_label = platform.machine()  # arm64 or x86_64

    # --onedir produces a proper .app bundle (double-clickable, Dock-friendly).
    for h in HIDDEN:
        cmd += ["--hidden-import", h]

    sep = ":"

    # Bundle the entire src/quantacrypt package so all modules are available
    cmd += ["--add-data", f"{PKG}{sep}quantacrypt"]

    # Bundle icon.png so the runtime iconphoto call can find it inside the app
    png = os.path.join(PKG, "assets", "icon.png")
    if os.path.isfile(png):
        cmd += ["--add-data", f"{png}{sep}."]

    # Bundle the entire tkinterdnd2 package tree so the native
    # tkdnd/<platform>/ directory is available at _MEIPASS/tkinterdnd2/ at runtime.
    tkdnd2_dir = _find_tkinterdnd2()
    if tkdnd2_dir:
        cmd += ["--add-data", f"{tkdnd2_dir}{sep}tkinterdnd2"]
    else:
        print("[!] WARNING: tkinterdnd2 not installed -- drag-and-drop will be disabled.")
        print("    Install with: pip install tkinterdnd2")

    # Add src/ to paths so quantacrypt package is importable
    cmd += ["--paths", SRC]
    cmd.append(os.path.join(PKG, "__main__.py"))

    print(f"\n{'='*60}\n  Building: {NAME}{SUF}  ({arch_label})\n{'='*60}")
    # When cross-building x86_64 on Apple Silicon, wrap the PyInstaller
    # subprocess with `arch -x86_64` so it and all its children run under
    # Rosetta.  Without this, sys.executable spawns an arm64 process even
    # if the outer script was invoked with `arch -x86_64`.
    import platform
    if target_arch == "x86_64" and platform.machine() == "arm64":
        cmd = ["arch", "-x86_64"] + cmd
    result = subprocess.run(cmd, cwd=ROOT)

    # Clean up the generated platform icon (icns/ico) — only needed during build
    if icon_tmp and os.path.isfile(icon_tmp):
        os.remove(icon_tmp)

    if result.returncode != 0:
        print("[!] Build failed"); sys.exit(1)

    out = os.path.join(DIST, NAME + SUF)

    # Copy the document icon into the .app bundle's Resources directory
    # so macOS can find it for .qcx file thumbnails in Finder
    doc_icon_name = None
    if doc_icon_tmp and os.path.isfile(doc_icon_tmp):
        resources_dir = os.path.join(out, "Contents", "Resources")
        os.makedirs(resources_dir, exist_ok=True)
        dest = os.path.join(resources_dir, "doc_icon.icns")
        shutil.copy2(doc_icon_tmp, dest)
        os.remove(doc_icon_tmp)
        doc_icon_name = "doc_icon.icns"
        print(f"[+] Installed {dest}")

    # Patch Info.plist with .qcx file-association metadata
    _patch_plist(out, doc_icon_name)

    # Ad-hoc code sign the .app bundle so macOS Gatekeeper shows the
    # standard "unidentified developer" dialog instead of "damaged".
    # A paid Apple Developer ID would eliminate the warning entirely,
    # but ad-hoc signing is sufficient for open-source distribution.
    print("[*] Ad-hoc code signing the .app bundle …")
    sign_cmd = [
        "codesign", "--force", "--deep", "--sign", "-",
        "--options", "runtime",
        out,
    ]
    sign_result = subprocess.run(sign_cmd, capture_output=True, text=True)
    if sign_result.returncode == 0:
        print("[+] Code signing succeeded")
    else:
        print(f"[!] Code signing failed (non-fatal): {sign_result.stderr.strip()}")

    # .app is a directory — report total size by walking it
    total = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, files in os.walk(out)
        for f in files
    )
    sz = total / 1_000_000

    # Create distributable DMG with drag-to-Applications layout
    dmg_path = _create_dmg(out, arch_label)

    print(f"\n{'='*60}")
    print(f"  BUILD COMPLETE  ({arch_label})")
    print(f"{'='*60}")
    print(f"  App:  {out}  ({sz:.1f} MB)")
    if dmg_path:
        dmg_sz = os.path.getsize(dmg_path) / 1_000_000
        print(f"  DMG:  {dmg_path}  ({dmg_sz:.1f} MB)")
    print()
    if dmg_path:
        print(f"  Share the .dmg — recipients open it and drag to Applications.")
    else:
        print(f"  Double-click the .app to launch, or drag it to /Applications.")
    print(f"  First launch: right-click → Open → Open to bypass Gatekeeper.")
    print(f"  If macOS says 'damaged': xattr -cr /Applications/{NAME}.app")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
