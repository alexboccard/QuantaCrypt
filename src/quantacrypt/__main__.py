#!/usr/bin/env python3
"""
QuantaCrypt -- single binary entry point.

Launch behaviour:
  1. If this binary IS a .qcx file (self-executing payload appended) -> Decryptor
  2. If a .qcx path is passed as argv[1]                            -> Decryptor
  3. Otherwise                                                       -> Launcher
"""
import os, sys

if getattr(sys, "frozen", False):
    _base = sys._MEIPASS
    sys.path.insert(0, _base)
else:
    _base = os.path.dirname(os.path.abspath(__file__))

# load_pkg: tail-only reads (O(1 MB) RAM), validates MIN/MAX version,
# gives clear error messages.  No separate _has_payload helper needed.
from quantacrypt.ui.decryptor import load_pkg, DecryptorApp


def _make_root():
    """Create a single persistent hidden Tk root shared by all screens.

    Using one root avoids the Python 3.13 macOS bug where destroying a Tk
    instance and then creating a new one corrupts the Tcl interpreter
    (TclError: invalid command name).  All app windows are Toplevels on this
    root; the root itself is never shown directly.
    """
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except Exception:
        import tkinter as tk
        root = tk.Tk()
    root.withdraw()

    # Set the app icon (replaces the default Python rocket in the dock)
    try:
        import tkinter as tk
        _assets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
        icon_path = os.path.join(_assets, "icon.png") if not getattr(sys, "frozen", False) else os.path.join(_base, "icon.png")
        if os.path.isfile(icon_path):
            img = tk.PhotoImage(file=icon_path)
            root.iconphoto(True, img)
            root._icon_img = img   # keep a reference so GC doesn't collect it
    except Exception:
        pass

    return root


def main():
    root = _make_root()

    # Case 1: self-executing .qcx (binary with payload appended)
    exe = sys.executable if getattr(sys, "frozen", False) else __file__
    try:
        self_payload = load_pkg(exe)
    except Exception:
        self_payload = None
    if self_payload:
        DecryptorApp(root, payload=self_payload, qcx_path=exe)
        root.mainloop()
        return

    # Case 2: .qcx path passed as argument
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isfile(arg):
            try:
                pkg = load_pkg(arg)
            except Exception as e:
                # Show a clear error instead of silently falling through to Launcher
                from tkinter import messagebox
                messagebox.showerror(
                    "Cannot open file",
                    os.path.basename(arg) + " is not a valid QuantaCrypt file.\n\n" + str(e),
                    parent=root)
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
