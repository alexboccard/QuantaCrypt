#!/usr/bin/env python3
"""QuantaCrypt Launcher — home screen for the combined binary."""
import os
import sys
import tkinter as tk

from quantacrypt import __version__
from quantacrypt.ui.shared import (
    C, F, UI,
    fmt_size, rule, friendly_error,
    FlatButton, RecentFiles,
)

try:
    from tkinterdnd2 import DND_FILES as _DND_FILES, TkinterDnD as _TkDnD
except ImportError:
    _DND_FILES = None
    _TkDnD = None  # type: ignore[assignment,misc]

# Type alias: the launcher's master may be a plain Tk or a TkinterDnD.Tk,
# and the launcher itself gains dnd methods at runtime when tkinterdnd2 is
# available.  We use TYPE_CHECKING to keep the static analyser happy.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class LauncherApp(tk.Toplevel):
    # DnD methods are injected at runtime by tkinterdnd2; declare for type-checkers
    drop_target_register: "Any"
    dnd_bind: "Any"

    def __init__(self, master: "tk.Misc"):
        super().__init__(master)
        self.title("QuantaCrypt")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self._build()
        self._center()
        # Check for updates in the background (non-blocking)
        from quantacrypt.ui.updater import check_for_update
        check_for_update(self, __version__)
        # Keyboard shortcuts.  Bind both the Ctrl+ variant (Linux/Win
        # convention) and the Cmd+ variant (macOS convention); Tk on
        # macOS maps Cmd to Meta/Command, so binding both gives users
        # either a platform-native or familiar shortcut.
        _shortcuts = {
            "e": self._open_encryptor,
            "E": self._open_encryptor,
            "d": self._open_decryptor,
            "D": self._open_decryptor,
            "i": self._inspect_file,
            "I": self._inspect_file,
            "v": self._open_volumes,
            "V": self._open_volumes,
        }
        for key, handler in _shortcuts.items():
            self.bind(f"<Control-{key}>", lambda e, h=handler: h())
            if sys.platform == "darwin":
                self.bind(f"<Command-{key}>", lambda e, h=handler: h())
        # Escape quits the app; Cmd+W closes the window (macOS convention)
        self.bind("<Escape>", lambda e: self.master.destroy())
        if sys.platform == "darwin":
            self.bind("<Command-w>", lambda e: self.master.destroy())
            self.bind("<Command-W>", lambda e: self.master.destroy())
            self.bind("<Command-q>", lambda e: self.master.destroy())
            self.bind("<Command-Q>", lambda e: self.master.destroy())
        self.protocol("WM_DELETE_WINDOW", self.master.destroy)
        # Drag-and-drop: drop a .qcx → open decryptor
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

    def _on_drop(self, event):
        try:
            paths = self.tk.splitlist(event.data)
        except Exception:
            # Fallback for non-standard Tcl encoding
            raw = event.data.strip()
            if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
            paths = [raw.split("} {")[0]]
        # Accept any combination of .qcx / .qcv files dropped together.
        # Previously we only honoured paths[0] and silently lost the rest;
        # for multi-file drops this looked like an app bug.  We only open
        # one wizard window at a time (the remaining paths queue behind
        # the first on the Tk event loop via after()).
        accepted = [
            p for p in paths
            if os.path.isfile(p)
            and os.path.splitext(p)[1].lower() in (".qcx", ".qcv")
        ]
        if not accepted:
            return

        def _dispatch(path: str):
            ext = os.path.splitext(path)[1].lower()
            if ext == ".qcv":
                self._open_volumes(volume_path=path)
            else:
                self._open_qcx(path)

        # First file opens immediately; any additional files open after
        # the current wizard closes (they queue as after() callbacks).
        _dispatch(accepted[0])
        for extra in accepted[1:]:
            self.after(1, lambda p=extra: _dispatch(p))

    def _center(self):
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h   = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self):
        P = 32

        # ── Logo / title ──────────────────────────────────────────────────────
        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="x", padx=P, pady=(36, 0))

        tk.Label(top, text="QuantaCrypt", font=(UI, 22, "bold"),
                 bg=C["bg"], fg=C["text"]).pack()
        tk.Label(top, text="Post-quantum file encryption",
                 font=F["body"], bg=C["bg"], fg=C["text3"]).pack(pady=(4, 0))

        rule(self, pady=28, padx=P)

        # ── Two mode cards ────────────────────────────────────────────────────
        cards = tk.Frame(self, bg=C["bg"])
        cards.pack(padx=P, pady=(0, 8))

        self._enc_card = self._make_card(
            cards,
            icon="🔒",
            title="Encrypt",
            body="Protect a file with a password\nor split it across multiple people.",
            btn_text="Encrypt a file →",
            command=self._open_encryptor,
            accent=True,
        )
        self._enc_card.grid(row=0, column=0, padx=(0, 10), sticky="nsew")

        self._dec_card = self._make_card(
            cards,
            icon="🔓",
            title="Decrypt",
            body="Open an encrypted .qcx file\nusing your password or shares.",
            btn_text="Decrypt a file →",
            command=self._open_decryptor,
            accent=False,
        )
        self._dec_card.grid(row=0, column=1, sticky="nsew")

        cards.columnconfigure(0, weight=1, minsize=220)
        cards.columnconfigure(1, weight=1, minsize=220)

        # ── Volumes card ───────────────────────────────────────────────────────
        vol_row = tk.Frame(self, bg=C["bg"])
        vol_row.pack(padx=P, pady=(10, 0))
        self._vol_card = self._make_card(
            vol_row,
            icon="💾",
            title="Volumes",
            body="Create or mount encrypted\nvirtual drives (.qcv files).",
            btn_text="Manage volumes →",
            command=self._open_volumes,
            accent=False,
        )
        self._vol_card.pack(fill="x")

        # ── Drop hint ─────────────────────────────────────────────────────────
        rule(self, pady=20, padx=P)

        drop_hint = (
            "You can also drag a .qcx or .qcv file onto this window."
            if _DND_FILES else
            "You can also open a .qcx file via the Decrypt button above, "
            "or manage .qcv volumes via the Volumes card."
        )
        tk.Label(self, text=drop_hint,
                 font=F["caption"], bg=C["bg"], fg=C["text3"],
                 wraplength=420).pack(pady=(0, 12))

        # Inspect button — previously only discoverable via Ctrl+I
        inspect_row = tk.Frame(self, bg=C["bg"])
        inspect_row.pack(pady=(0, 8))
        FlatButton(inspect_row, "🔍 Inspect a .qcx file", self._inspect_file,
                   primary=False, small=True).pack()
        tk.Label(inspect_row, text="View encryption details without the password",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(2, 0))
        tk.Label(self,
                 text="Your files are protected with quantum-resistant encryption.\n"
                      "Encrypted files use the .qcx format and can only be opened with your password.",
                 font=F["small"], bg=C["bg"], fg=C["text3"],
                 wraplength=420, justify="center").pack(pady=(0, 8))

        tk.Label(self, text=f"v{__version__}",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(0, 4))

        # Discoverable keyboard shortcut hint
        tk.Label(self, text="Keyboard: Ctrl+E  Encrypt  ·  Ctrl+D  Decrypt  ·  Ctrl+V  Volumes  ·  Ctrl+I  Inspect",
                 font=F["small"], bg=C["bg"], fg=C["text3"],
                 wraplength=420).pack(pady=(0, 6))

        # ── Recent files ───────────────────────────────────────────────────────
        self._recent_frame = tk.Frame(self, bg=C["bg"])
        self._recent_frame.pack(fill="x", padx=P, pady=(0, 18))
        self._build_recent()

    def _build_recent(self):
        """Render or refresh the recent .qcx files list."""
        for w in self._recent_frame.winfo_children():
            w.destroy()
        entries = RecentFiles.load()
        if not entries:
            return
        hdr = tk.Frame(self._recent_frame, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 6))
        tk.Label(hdr, text="RECENTLY USED", font=F["small"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left")
        def _do_clear():
            RecentFiles.clear()
            self._build_recent()
        FlatButton(hdr, "Clear", _do_clear, primary=False, small=True).pack(side="right")
        MAX_VISIBLE = 5
        for path, entry in entries[:MAX_VISIBLE]:
            self._build_recent_row(path, entry)
        # Show overflow count so the launcher doesn't overflow the screen
        if len(entries) > MAX_VISIBLE:
            extra = len(entries) - MAX_VISIBLE
            tk.Label(self._recent_frame,
                     text=f"… and {extra} more",
                     font=F["small"], bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(2, 0))

    def _build_recent_row(self, path, entry):
        """Render a single recent-file row inside ``_recent_frame``."""
        import time as _t

        mode = entry.get("mode", "single")
        k, n = entry.get("threshold", 0), entry.get("total", 0)
        mode_tag = (f"Split key ({k} of {n})" if mode == "shamir" and k and n
                    else "Password")
        ts = entry.get("ts", 0)
        try:
            date_str = _t.strftime("%b %d", _t.localtime(ts)) if ts else ""
        except Exception:
            date_str = ""

        row = tk.Frame(self._recent_frame, bg=C["surface"],
                       highlightbackground=C["border"], highlightthickness=1,
                       cursor="hand2")
        row.pack(fill="x", pady=(0, 4))
        top_inner = tk.Frame(row, bg=C["surface"])
        top_inner.pack(fill="x", padx=12, pady=(8, 2))
        name_lbl = tk.Label(top_inner, text=os.path.basename(path),
                            font=F["caption"], bg=C["surface"], fg=C["text"])
        name_lbl.pack(side="left")
        combined_meta = "  ·  ".join(x for x in [mode_tag, date_str] if x)
        meta_lbl = tk.Label(top_inner, text=combined_meta,
                            font=F["small"], bg=C["surface"], fg=C["text3"])
        meta_lbl.pack(side="right")
        dir_lbl = tk.Label(row, text=os.path.dirname(path),
                           font=F["small"], bg=C["surface"], fg=C["text3"],
                           anchor="w", cursor="hand2")
        dir_lbl.pack(fill="x", padx=12, pady=(0, 6))

        widgets = (row, top_inner, name_lbl, meta_lbl, dir_lbl)

        def _hl(on, _widgets=widgets):
            col = C["surface2"] if on else C["surface"]
            for w in _widgets:
                try:
                    w.config(bg=col)
                except Exception:
                    pass

        for w in widgets:
            w.bind("<Button-1>", lambda e, p=path: self._open_qcx(p))
            w.bind("<Enter>", lambda e: _hl(True))
            w.bind("<Leave>", lambda e: _hl(False))


    def _make_card(self, parent, icon, title, body, btn_text, command, accent):
        card = tk.Frame(parent, bg=C["surface"],
                        highlightbackground=C["border"],  # Equal visual weight
                        highlightthickness=1)

        inner = tk.Frame(card, bg=C["surface"])
        inner.pack(fill="both", expand=True, padx=20, pady=20)

        lbl_icon  = tk.Label(inner, text=icon, font=(UI, 28),
                             bg=C["surface"], fg=C["text"])
        lbl_icon.pack(anchor="w")

        lbl_title = tk.Label(inner, text=title, font=F["heading"],
                             bg=C["surface"], fg=C["text"])
        lbl_title.pack(anchor="w", pady=(8, 0))

        lbl_body  = tk.Label(inner, text=body, font=F["caption"],
                             bg=C["surface"], fg=C["text3"],
                             justify="left", wraplength=175)
        lbl_body.pack(anchor="w", pady=(6, 16))

        btn = FlatButton(inner, btn_text, command, primary=accent)
        btn.pack(anchor="w", fill="x")

        # Collect every bg-carrying widget so the hover effect is visible
        # across the full card area, not just the outer frame.
        _bg_widgets = [card, inner, lbl_icon, lbl_title, lbl_body]

        def _enter(_e):
            if card.cget("highlightbackground") == C["accent"]: return  # focused — don't override
            for w in _bg_widgets:
                try: w.config(bg=C["surface2"])
                except Exception: pass

        def _leave(_e):
            for w in _bg_widgets:
                try: w.config(bg=C["surface"])
                except Exception: pass

        # Keyboard: make the whole card focusable with Tab, activate with Enter/Space
        card.config(takefocus=True, cursor="hand2")
        card.bind("<Return>", lambda e: command())
        card.bind("<space>",  lambda e: command())
        card.bind("<FocusIn>",  lambda e: card.config(highlightbackground=C["accent"], highlightthickness=2))
        card.bind("<FocusOut>", lambda e: (card.config(highlightbackground=C["border"], highlightthickness=1), _leave(e)))
        # Bind hover to card only — tkinter fires Enter/Leave per-widget, so binding
        # to the card frame alone avoids rapid flicker as the pointer crosses children.
        card.bind("<Enter>", _enter)
        card.bind("<Leave>", _leave)

        return card

    # ── Navigation ────────────────────────────────────────────────────────────

    def _safe_open_wizard(self, build_wizard):
        """Withdraw the launcher, construct a wizard, recover on failure.

        Previously the launcher called self.withdraw() *before* the wizard's
        import/constructor ran.  If construction raised (missing optional
        dependency, disk error, etc.), the launcher stayed hidden and the
        user saw a running process with no visible window.  This wrapper
        re-shows the launcher and surfaces the error in a dialog so the
        user can recover without force-quitting.
        """
        from tkinter import messagebox
        self.withdraw()
        try:
            build_wizard()
        except Exception as exc:
            self.deiconify()
            messagebox.showerror(
                "Cannot open window",
                f"Something went wrong opening that screen.\n\n{friendly_error(exc)}",
                parent=self,
            )

    def _open_volumes(self, volume_path: str | None = None):
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            from quantacrypt.ui.volume_manager import VolumeManagerApp
            VolumeManagerApp(
                self.master, on_close=self.deiconify, center_at=(cx, cy),
                volume_path=volume_path,
            )
        self._safe_open_wizard(_build)

    def _open_encryptor(self):
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            from quantacrypt.ui.encryptor import EncryptorApp
            EncryptorApp(self.master, on_close=self.deiconify, center_at=(cx, cy))
        self._safe_open_wizard(_build)

    def _open_decryptor(self):
        """Trigger a file picker immediately so the Decrypt card does what it says.
        Only navigate to the decryptor if the user actually picks a file; if they
        cancel the dialog we stay on the launcher."""
        from tkinter import filedialog
        from quantacrypt.ui.decryptor import load_pkg
        path = filedialog.askopenfilename(
            title="Open encrypted file",
            filetypes=[("QuantaCrypt", "*.qcx"), ("All files", "*")])
        if not path:
            return  # user cancelled — stay on launcher
        try:
            pkg = load_pkg(path)
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror(
                "Cannot open file",
                f"{os.path.basename(path)}\n\n{friendly_error(e)}",
                parent=self)
            return
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            from quantacrypt.ui.decryptor import DecryptorApp
            DecryptorApp(self.master, payload=pkg, qcx_path=path, on_close=self.deiconify, center_at=(cx, cy))
        self._safe_open_wizard(_build)

    def _open_qcx(self, path):
        """Open a specific .qcx file directly in the decryptor."""
        from quantacrypt.ui.decryptor import DecryptorApp, load_pkg  # noqa: E401
        try:
            pkg = load_pkg(path)
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror(
                "Cannot open file",
                f"{os.path.basename(path)}\n\n{friendly_error(e)}",
                parent=self)
            return
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            DecryptorApp(self.master, payload=pkg, qcx_path=path, on_close=self.deiconify, center_at=(cx, cy))
        self._safe_open_wizard(_build)


    def _inspect_file(self):
        """Open a .qcx file and show its metadata without entering credentials."""
        from tkinter import filedialog, messagebox
        from quantacrypt.ui.decryptor import load_pkg
        path = filedialog.askopenfilename(
            title="Inspect encrypted file",
            filetypes=[("QuantaCrypt", "*.qcx"), ("All files", "*")])
        if not path: return
        try:
            pkg = load_pkg(path)
        except Exception as e:
            messagebox.showerror(
                "Cannot read file",
                f"{os.path.basename(path)}\n\n{friendly_error(e)}",
                parent=self)
            return
        meta = pkg["meta"]
        # Build a summary dialog
        win = tk.Toplevel(self)
        win.title(f"File info — {os.path.basename(path)}")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()
        P = 24
        tk.Label(win, text="File Information", font=F["heading"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", padx=P, pady=(20,12))
        card = tk.Frame(win, bg=C["surface"],
                        highlightbackground=C["border"], highlightthickness=1)
        card.pack(fill="x", padx=P, pady=(0,8))
        rows = [
            ("File",       os.path.basename(path)),
            ("Size",       fmt_size(os.path.getsize(path))),
            ("Format",     f"v{meta.get('version', '?')}"),
            ("Mode",       "Password-protected" if meta.get("mode") == "single"
                           else f"Split key — needs {meta.get('threshold')} of {meta.get('total')} people"),
            ("Encryption", "Quantum-resistant (AES-256-GCM + ML-KEM)"),
        ]
        if meta.get("mode") == "single" and "argon_salt" in meta:
            rows.append(("Password", "Hardened with slow hash (Argon2id)"))
        if meta.get("payload_offset"):
            rows.append(("Embedded", "Decryptor binary included"))
        for lbl, val in rows:
            row = tk.Frame(card, bg=C["surface"]); row.pack(fill="x", padx=14, pady=4)
            tk.Label(row, text=lbl, font=F["caption"], bg=C["surface"], fg=C["text3"],
                     width=10, anchor="w").pack(side="left")
            tk.Label(row, text=val, font=F["caption"], bg=C["surface"], fg=C["text2"],
                     anchor="w", wraplength=320, justify="left").pack(side="left", fill="x")
        tk.Frame(card, bg=C["border"], height=1).pack(fill="x", pady=(6,0))
        # Path
        tk.Label(win, text=path, font=F["small"], bg=C["bg"], fg=C["text3"],
                 wraplength=380, justify="left").pack(anchor="w", padx=P, pady=(0,4))
        note = tk.Label(win,
                        text="Note: filename, original size, and encryption date are hidden\n"
                             "inside the encrypted payload and can only be seen after decryption.",
                        font=F["small"], bg=C["bg"], fg=C["text3"],
                        wraplength=380, justify="left")
        note.pack(anchor="w", padx=P, pady=(0,12))
        btn_row = tk.Frame(win, bg=C["bg"]); btn_row.pack(fill="x", padx=P, pady=(0,20))
        FlatButton(btn_row, "Decrypt this file →",
                   lambda: (win.destroy(), self._open_qcx(path)),
                   primary=True, small=True).pack(side="left")
        FlatButton(btn_row, "Close", win.destroy,
                   primary=False, small=True).pack(side="left", padx=(8,0))
        # Centre over launcher
        win.update_idletasks()
        lx, ly = self.winfo_x(), self.winfo_y()
        lw, lh = self.winfo_width(), self.winfo_height()
        ww, wh = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{lx+(lw-ww)//2}+{ly+(lh-wh)//2}")


if __name__ == "__main__":
    # Standalone launch — create a hidden root (same pattern as quantacrypt.py)
    root = tk.Tk()
    root.withdraw()
    LauncherApp(root)
    root.mainloop()
