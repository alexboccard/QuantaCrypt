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

import os, sys, subprocess, struct, io

# ROOT = repo root (one level up from scripts/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, "src")
PKG  = os.path.join(SRC, "quantacrypt")
DIST = os.path.join(ROOT, "dist")
WORK = os.path.join(ROOT, "build")
NAME = "quantacrypt"

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
    # BUG-2: tkinterdnd2 must be in hidden imports so PyInstaller collects the
    # package. The native tkdnd/ directory is also bundled via --add-data below
    # because TkinterDnD._require() locates it via os.path.dirname(__file__).
    "tkinterdnd2", "tkinterdnd2.TkinterDnD",
    # BUG-3: zxcvbn must be bundled so the password strength bar works correctly
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


def main():
    os.makedirs(DIST, exist_ok=True)

    icon_args, icon_tmp = _build_icon()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name",      NAME,
        "--distpath",  DIST,
        "--workpath",  WORK,
        "--specpath",  WORK,
        "--noconsole",
        "--clean",
        "--noconfirm",
    ] + icon_args

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

    # BUG-2 (continued): bundle the entire tkinterdnd2 package tree so the native
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

    print(f"\n{'='*60}\n  Building: {NAME}{SUF}\n{'='*60}")
    result = subprocess.run(cmd, cwd=ROOT)

    # Clean up the generated platform icon (icns/ico) — only needed during build
    if icon_tmp and os.path.isfile(icon_tmp):
        os.remove(icon_tmp)

    if result.returncode != 0:
        print("[!] Build failed"); sys.exit(1)

    out = os.path.join(DIST, NAME + SUF)

    # .app is a directory — report total size by walking it
    total = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, files in os.walk(out)
        for f in files
    )
    sz = total / 1_000_000
    print(f"\n{'='*60}")
    print(f"  BUILD COMPLETE")
    print(f"{'='*60}")
    print(f"  {out}  ({sz:.1f} MB)")
    print()
    print(f"  Double-click the .app to launch, or drag it to /Applications.")
    print(f"  First launch: right-click → Open to bypass Gatekeeper.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
