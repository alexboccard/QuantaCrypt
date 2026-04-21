#!/usr/bin/env python3
"""QuantaCrypt -- single binary entry point.

Launch behaviour:
  1. If this binary IS a .qcx file (self-executing payload appended) -> Decryptor
  2. If a .qcx path is passed as argv[1]                            -> Decryptor
  3. Otherwise                                                       -> Launcher
"""

import os
import sys

# When running as a frozen PyInstaller bundle, _MEIPASS is the temp dir
# containing unpacked resources.  Add it to sys.path so that bundled
# packages (quantacrypt, tkinterdnd2, etc.) are importable.
if getattr(sys, "frozen", False):
    _base = sys._MEIPASS          # type: ignore[attr-defined]
    sys.path.insert(0, _base)
else:
    _base = os.path.dirname(os.path.abspath(__file__))

from quantacrypt.ui.decryptor import load_pkg, DecryptorApp


def _register_open_document(root):
    """Register a macOS Apple Event handler for opening .qcx/.qcv files.

    When a user double-clicks a .qcx or .qcv file while the app is already
    running, macOS sends an ``kAEOpenDocuments`` event.  Tk on macOS exposes
    this via the ``::tk::mac::OpenDocument`` Tcl command.  We register a
    callback so those files are routed to the appropriate screen automatically.
    """
    def _open_document(*paths):
        for path in paths:
            if not os.path.isfile(path):
                continue
            # .qcv → Volume Manager (mount mode)
            if path.lower().endswith(".qcv"):
                from quantacrypt.ui.volume_manager import VolumeManagerApp
                VolumeManagerApp(root, volume_path=path)
                continue
            # .qcx → Decryptor
            try:
                pkg = load_pkg(path)
            except (ValueError, OSError):
                continue
            # Provide on_close so closing this window doesn't leave
            # the app running with no visible windows
            DecryptorApp(root, payload=pkg, qcx_path=path,
                         on_close=lambda: None)

    try:
        root.createcommand("::tk::mac::OpenDocument", _open_document)
    except Exception:
        # Not on macOS or Tcl/Tk doesn't support it — no-op
        pass


def _make_root():
    """Create a single persistent hidden Tk root shared by all screens.

    Using one root avoids the Python 3.13 macOS bug where destroying a Tk
    instance and then creating a new one corrupts the Tcl interpreter
    (TclError: invalid command name).  All app windows are Toplevels on
    this root; the root itself is never shown directly.
    """
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except ImportError:
        import tkinter as tk
        root = tk.Tk()
    root.withdraw()

    # Set the app icon (replaces the default Python rocket in the dock)
    try:
        import tkinter as tk
        _assets = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "assets",
        )
        if getattr(sys, "frozen", False):
            icon_path = os.path.join(_base, "icon.png")
        else:
            icon_path = os.path.join(_assets, "icon.png")
        if os.path.isfile(icon_path):
            img = tk.PhotoImage(file=icon_path)
            root.iconphoto(True, img)
            root._icon_img = img  # prevent GC from collecting it
    except (tk.TclError, OSError):
        pass

    return root


def main():
    """Determine launch mode and start the appropriate screen."""
    root = _make_root()
    _register_open_document(root)

    # Case 1: self-executing .qcx (binary with payload appended)
    exe = sys.executable if getattr(sys, "frozen", False) else __file__
    try:
        self_payload = load_pkg(exe)
    except (ValueError, OSError):
        self_payload = None
    if self_payload:
        DecryptorApp(root, payload=self_payload, qcx_path=exe)
        root.mainloop()
        return

    # Case 2: .qcx path passed as argument
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isfile(arg):
            # Case 2a: .qcv volume → open Volume Manager in mount mode
            if arg.lower().endswith(".qcv"):
                from quantacrypt.ui.launcher import LauncherApp
                launcher = LauncherApp(root)
                # Defer volume open until after mainloop starts
                root.after(100, lambda: launcher._open_volumes(volume_path=arg))
                root.mainloop()
                return

            # Case 2b: .qcx encrypted file → Decryptor
            try:
                pkg = load_pkg(arg)
            except (ValueError, OSError) as e:
                from tkinter import messagebox
                messagebox.showerror(
                    "Cannot open file",
                    f"{os.path.basename(arg)} is not a valid"
                    f" QuantaCrypt file.\n\n{e}",
                    parent=root,
                )
                root.destroy()
                return
            DecryptorApp(root, payload=pkg, qcx_path=arg)
            root.mainloop()
            return

    # Case 3: Launcher
    from quantacrypt.ui.launcher import LauncherApp
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
