#!/usr/bin/env python3
"""QuantaCrypt Launcher — home screen for the combined binary."""
import os, sys
import tkinter as tk
from tkinter import filedialog

if getattr(sys, "frozen", False):
    _base = sys._MEIPASS
    sys.path.insert(0, _base)
else:
    _base = os.path.dirname(os.path.abspath(__file__))

from quantacrypt.ui.shared import *

try:
    from tkinterdnd2 import DND_FILES as _DND_FILES
except ImportError:
    _DND_FILES = None


class LauncherApp(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("QuantaCrypt")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self._build()
        self._center()
        # Keyboard shortcuts: Ctrl+E → Encrypt, Ctrl+D → Decrypt, Ctrl+I → Inspect
        self.bind("<Control-e>", lambda e: self._open_encryptor())
        self.bind("<Control-E>", lambda e: self._open_encryptor())
        self.bind("<Control-d>", lambda e: self._open_decryptor())
        self.bind("<Control-D>", lambda e: self._open_decryptor())
        self.bind("<Control-i>", lambda e: self._inspect_file())
        self.bind("<Control-I>", lambda e: self._inspect_file())
        # Escape quits the app
        self.bind("<Escape>", lambda e: self.master.destroy())
        self.protocol("WM_DELETE_WINDOW", self.master.destroy)
        # Drag-and-drop: drop a .qcx → open decryptor
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

    def _on_drop(self, event):
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
        path = raw.split("} {")[0]
        if os.path.isfile(path):
            self._open_qcx(path)

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
            body="Open a .qcx file using your\npassword or Shamir shares.",
            btn_text="Decrypt a file →",
            command=self._open_decryptor,
            accent=False,
        )
        self._dec_card.grid(row=0, column=1, sticky="nsew")

        cards.columnconfigure(0, weight=1, minsize=200)
        cards.columnconfigure(1, weight=1, minsize=200)

        # ── Drop hint ─────────────────────────────────────────────────────────
        rule(self, pady=20, padx=P)

        drop_hint = (
            "You can also drag a .qcx file onto this window to decrypt it directly."
            if _DND_FILES else
            "You can also open a .qcx file via the Decrypt button above."
        )
        tk.Label(self, text=drop_hint,
                 font=F["caption"], bg=C["bg"], fg=C["text3"],
                 wraplength=420).pack(pady=(0, 12))

        # UX-L2: Inspect button — previously only discoverable via Ctrl+I
        inspect_row = tk.Frame(self, bg=C["bg"])
        inspect_row.pack(pady=(0, 8))
        FlatButton(inspect_row, "Inspect a .qcx file", self._inspect_file,
                   primary=False, small=True).pack()
        tk.Label(self,
                 text="QuantaCrypt uses ML-KEM (Kyber-768) post-quantum encryption + AES-256-GCM.\n"
                      "Files use the .qcx format. Shamir mode splits the key across multiple people.",
                 font=F["small"], bg=C["bg"], fg=C["text3"],
                 wraplength=420, justify="center").pack(pady=(0, 8))

        tk.Label(self, text="v4.0",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(0, 4))

        # Fix 17: discoverable keyboard shortcut hint
        tk.Label(self, text="Keyboard: Ctrl+E  Encrypt  ·  Ctrl+D  Decrypt  ·  Ctrl+I  Inspect",
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
        import time as _t
        MAX_VISIBLE = 5
        for path, entry in entries[:MAX_VISIBLE]:
            mode = entry.get("mode", "single")
            k, n = entry.get("threshold", 0), entry.get("total", 0)
            mode_tag = (f"Shamir {k}-of-{n}" if mode == "shamir" and k and n
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
            # UX-L1: show both date and mode, not one or the other
            combined_meta = "  ·  ".join(x for x in [mode_tag, date_str] if x)
            meta_lbl = tk.Label(top_inner, text=combined_meta,
                                font=F["small"], bg=C["surface"], fg=C["text3"])
            meta_lbl.pack(side="right")
            dir_lbl = tk.Label(row, text=os.path.dirname(path),
                               font=F["small"], bg=C["surface"], fg=C["text3"],
                               anchor="w", cursor="hand2")
            dir_lbl.pack(fill="x", padx=12, pady=(0, 6))

            _all = [row, top_inner, name_lbl, meta_lbl, dir_lbl]

            def _hl(on, widgets=_all):
                col = C["surface2"] if on else C["surface"]
                for w in widgets:
                    try: w.config(bg=col)
                    except Exception: pass

            def _open(p=path):
                self._open_qcx(p)

            for w in _all:
                w.bind("<Button-1>", lambda e, p=path: _open(p))
                w.bind("<Enter>", lambda e: _hl(True))
                w.bind("<Leave>", lambda e: _hl(False))
        # UX-L3: show overflow count so the launcher doesn't overflow the screen
        if len(entries) > MAX_VISIBLE:
            extra = len(entries) - MAX_VISIBLE
            tk.Label(self._recent_frame,
                     text=f"… and {extra} more",
                     font=F["small"], bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(2, 0))


    def _make_card(self, parent, icon, title, body, btn_text, command, accent):
        card = tk.Frame(parent, bg=C["surface"],
                        highlightbackground=C["border"],  # UX-11: equal visual weight
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

        # G-Q: collect every bg-carrying widget so the hover effect is visible
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

    def _open_encryptor(self):
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        self.withdraw()
        from quantacrypt.ui.encryptor import EncryptorApp
        EncryptorApp(self.master, on_close=self.deiconify, center_at=(cx, cy))

    def _open_decryptor(self):
        """G-A: trigger a file picker immediately so the Decrypt card does what it says.
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
                f"{os.path.basename(path)} is not a valid QuantaCrypt file.\n\n{e}",
                parent=self)
            return
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        self.withdraw()
        from quantacrypt.ui.decryptor import DecryptorApp
        DecryptorApp(self.master, payload=pkg, qcx_path=path, on_close=self.deiconify, center_at=(cx, cy))

    def _open_qcx(self, path):
        """Open a specific .qcx file directly in the decryptor."""
        from quantacrypt.ui.decryptor import DecryptorApp, load_pkg  # noqa: E401
        try:
            pkg = load_pkg(path)
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror(
                "Cannot open file",
                f"{os.path.basename(path)} is not a valid QuantaCrypt file.\n\n{e}",
                parent=self)
            return
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        self.withdraw()
        DecryptorApp(self.master, payload=pkg, qcx_path=path, on_close=self.deiconify, center_at=(cx, cy))


    def _inspect_file(self):
        """Open a .qcx file and show its metadata without entering credentials."""
        from tkinter import filedialog, messagebox
        from quantacrypt.ui.decryptor import load_pkg
        import time as _t
        path = filedialog.askopenfilename(
            title="Inspect encrypted file",
            filetypes=[("QuantaCrypt", "*.qcx"), ("All files", "*")])
        if not path: return
        try:
            pkg = load_pkg(path)
        except Exception as e:
            messagebox.showerror("Cannot read file",
                f"{os.path.basename(path)} is not a valid QuantaCrypt file.\n\n{e}",
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
            ("Mode",       "Single Password" if meta.get("mode") == "single"
                           else f"Shamir  {meta.get('threshold')}-of-{meta.get('total')}"),
            ("Cipher",     "AES-256-GCM"),
            ("KEM",        "ML-KEM / Kyber-768"
                           + (f"  ·  {meta['key_bits']}-bit key" if "key_bits" in meta else "")),
        ]
        if meta.get("mode") == "single" and "argon_salt" in meta:
            rows.append(("KDF", "Argon2id"))
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
