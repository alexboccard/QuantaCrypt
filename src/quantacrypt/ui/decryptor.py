#!/usr/bin/env python3
"""QuantaCrypt Decryptor — decryption GUI with password and Shamir modes."""
import base64 as _b64
import json
import os
import struct
import subprocess
import sys
import threading
import time as _time
import uuid

import tkinter as tk
from tkinter import filedialog, messagebox

from quantacrypt.core import crypto as cc
from quantacrypt.core.crypto import (
    MAGIC, FORMAT_VERSION, MIN_FORMAT_VERSION, MAX_FORMAT_VERSION,
)
from quantacrypt.ui.shared import (
    C, F, UI,
    styled_entry, bind_context_menu, fmt_size, rule, section_label,
    FlatButton, SegmentedControl, StagedProgressBar,
    FileCard, WizardSteps, RecentFiles, notify,
)

P = 24  # consistent padding throughout

STAGES = [
    ("Verifying password",  0.55, "Argon2id"),
    ("Loading key",         0.05, "Parsing"),
    ("Recovering key",      0.10, "Reconstructing"),
    ("Unlocking",           0.15, "Decapsulat"),
    ("Decrypting file",     0.15, "Decrypting payload"),
]

_WL = None
def get_wl():
    global _WL
    if _WL is None:
        from mnemonic import Mnemonic
        _WL = Mnemonic("english").wordlist
    return _WL

_MAX_TAIL = 1 << 20  # 1 MB tail search window

def load_pkg(path):
    """Parse a .qcx file without loading the whole thing into RAM."""
    file_size = os.path.getsize(path)
    tail_size = min(file_size, _MAX_TAIL)
    with open(path, "rb") as f:
        f.seek(file_size - tail_size)
        tail = f.read(tail_size)
    i = tail.rfind(MAGIC)
    if i < 0:
        raise ValueError("Not a QuantaCrypt file")
    o = i + len(MAGIC)
    if o + 4 > len(tail):
        raise ValueError("File appears truncated or corrupt")
    n = struct.unpack(">I", tail[o:o+4])[0]
    if o + 4 + n > len(tail):
        raise ValueError("File appears truncated or corrupt")
    pkg = json.loads(tail[o+4:o+4+n])
    if not isinstance(pkg, dict):
        raise ValueError("File metadata envelope is not a valid dictionary — file may be corrupt")
    meta = pkg.get("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("File metadata is not a valid dictionary — file may be corrupt")
    ver = meta.get("version", 1)
    # Reject files from future versions (need a newer app)
    if ver > MAX_FORMAT_VERSION:
        raise ValueError(
            f"This file was created with a newer version of QuantaCrypt (format v{ver}). "
            f"Please upgrade the app."
        )
    # Reject files from older versions (v1 is the minimum supported format)
    if ver < MIN_FORMAT_VERSION:
        raise ValueError(
            f"This file uses an older format (v{ver}) that is no longer supported. "
            f"Use an older version of QuantaCrypt to decrypt it, "
            f"then re-encrypt with this version."
        )
    # Validate required fields so downstream code never hits bare KeyError
    if "mode" not in meta:
        raise ValueError("File metadata is missing required field 'mode' — file may be corrupt")
    if meta["mode"] not in ("single", "shamir"):
        raise ValueError(f"Unknown encryption mode {meta['mode']!r} — file may be corrupt or from an unsupported version")
    if meta["mode"] == "shamir":
        for field in ("threshold", "total"):
            if field not in meta:
                raise ValueError(f"Shamir file metadata is missing required field '{field}' — file may be corrupt")
        if not (2 <= meta["threshold"] <= meta["total"] <= 255):
            raise ValueError(f"Invalid Shamir parameters: threshold={meta.get('threshold')}, total={meta.get('total')}")
    return pkg

def _find_stage(msg):
    for i,(name,_,kw) in enumerate(STAGES):
        if kw.lower() in msg.lower(): return i, msg
    return None, None

def _reveal(path):
    """Open the containing folder in the system file manager."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", path], check=False)
        elif sys.platform == "win32":
            subprocess.run(["explorer", "/select,", path], check=False)
        else:
            subprocess.run(["xdg-open", os.path.dirname(os.path.abspath(path))], check=False)
    except Exception:
        pass


def _open_file(path):
    """Open the decrypted file directly with the system default application."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        elif sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        pass


# ── WordEntry ─────────────────────────────────────────────────────────────────

class WordEntry(tk.Frame):
    MAX_DROP = 8

    def __init__(self, parent, number, wl, on_confirm=None, **kw):
        super().__init__(parent, bg=C["surface2"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        self._wl=wl; self._cb=on_confirm; self._nxt=None
        self._dd=None; self._lb=None; self._open=False
        tk.Label(self, text=f"{number:02d}", font=(UI,7),
                 bg=C["surface2"], fg=C["text3"], width=2).pack(side="left", padx=(4,1))
        self._v = tk.StringVar()
        self._v.trace_add("write", self._typed)
        self._e = tk.Entry(self, textvariable=self._v, font=F["mono_s"],
                           bg=C["surface2"], fg=C["text"],
                           insertbackground=C["accent"],
                           relief="flat", bd=0, highlightthickness=0, width=9)
        bind_context_menu(self._e)
        self._e.pack(side="left", fill="x", expand=True, ipady=4, padx=(0,4))
        for ev,fn in [("<Down>",self._dn),("<Up>",self._up),("<Return>",self._ret),
                      ("<Tab>",self._tab),("<space>",self._spc),
                      ("<FocusOut>",self._fout),("<FocusIn>",self._fin),
                      ("<Escape>",lambda e:self._close())]:
            self._e.bind(ev, fn)

    def get(self): return self._v.get().strip().lower()
    def set(self, w): self._v.set(w); self._border()
    def focus(self): self._e.focus_set()
    def focus_force(self): self.winfo_toplevel().lift(); self._e.focus_force()
    def valid(self): return self.get() in self._wl

    def _typed(self,*_):
        t = self._v.get().strip().lower()
        if not t: self._close(); self._set_b(C["border"]); return
        m = [w for w in self._wl if w.startswith(t)]
        if not m: self._set_b(C["error"]); self._close(); return
        self._set_b(C["success"] if t in self._wl else C["accent"])
        if not (len(m)==1 and m[0]==t): self._show(m)
        else: self._close()

    def _fin(self,e):
        t = self._v.get().strip().lower()
        if t and t not in self._wl:
            m = [w for w in self._wl if w.startswith(t)]
            if m: self._show(m)

    def _fout(self,e): self.after(150, self._hfo)
    def _hfo(self):
        try:
            if not self.winfo_exists(): return   # widget destroyed during the 150ms delay
        except Exception: return
        self._border()
        try:
            f = self.winfo_toplevel().focus_get()
            if f is not self._lb: self._close()
        except Exception: self._close()

    def _border(self):
        if self.valid(): self._set_b(C["success"])
        elif self.get(): self._set_b(C["error"])
        else: self._set_b(C["border"])

    def _dn(self,e):
        if not self._open:
            t = self._v.get().strip().lower()
            if t: self._show([w for w in self._wl if w.startswith(t)])
        if self._lb:
            self._lb.focus_set()
            if not self._lb.curselection(): self._lb.selection_set(0)
            self._lb.event_generate("<Down>")
        return "break"

    def _up(self,e):
        if self._lb and self._open: self._lb.focus_set(); self._lb.event_generate("<Up>")
        return "break"

    def _ret(self,e):
        if self._open and self._lb:
            s = self._lb.curselection()
            if s: self._sel(self._lb.get(s[0])); return "break"
        if self.valid(): self._next()
        return "break"

    def _tab(self,e):
        if self._open and self._lb:
            s = self._lb.curselection()
            if s: self._sel(self._lb.get(s[0])); return "break"
            if self._lb.size(): self._sel(self._lb.get(0)); return "break"
        self._close()
        if self.valid(): self._next()
        return "break"

    def _spc(self,e):
        if self._open and self._lb:
            s = self._lb.curselection()
            if s: self._sel(self._lb.get(s[0])); return "break"
            if self._lb.size(): self._sel(self._lb.get(0)); return "break"
        if self.valid(): self._next(); return "break"

    def _show(self, matches):
        if not matches: self._close(); return
        if self._dd is None:
            self._dd = tk.Toplevel(self)
            self._dd.transient(self.winfo_toplevel())
            self._dd.wm_overrideredirect(True)
            self._dd.wm_attributes("-topmost", True)
            self._dd.configure(bg=C["border"])
            fr = tk.Frame(self._dd, bg=C["surface"],
                          highlightbackground=C["accent"], highlightthickness=1)
            fr.pack(fill="both", expand=True, padx=1, pady=1)
            sb2 = tk.Scrollbar(fr, orient="vertical", bg=C["surface2"])
            self._lb = tk.Listbox(fr, yscrollcommand=sb2.set, font=F["mono_s"],
                                   bg=C["surface"], fg=C["text"],
                                   selectbackground=C["accent"],
                                   selectforeground=C["text"],
                                   activestyle="none", relief="flat", bd=0,
                                   highlightthickness=0, width=12)
            sb2.config(command=self._lb.yview)
            self._lb.pack(side="left", fill="both", expand=True)
            sb2.pack(side="right", fill="y")
            self._lb.bind("<Return>",          self._lbpick)
            self._lb.bind("<Double-1>",        self._lbpick)
            self._lb.bind("<ButtonRelease-1>", self._lbpick)
            self._lb.bind("<Tab>",             self._lbtab)
            self._lb.bind("<Escape>",          lambda e: self._close())
            self._lb.bind("<FocusOut>",        lambda e: self.after(120,self._mc))
        self._lb.delete(0,"end")
        show = matches[:30]
        for w in show: self._lb.insert("end",w)
        row_h = min(len(show), self.MAX_DROP)
        self._lb.config(height=row_h)
        self.update_idletasks()
        x   = self._e.winfo_rootx()
        ey  = self._e.winfo_rooty()
        eh  = self._e.winfo_height()
        # Estimate dropdown pixel height to check screen bounds
        # Listbox row height ≈ font size + 2px padding; approximate as 16px per row
        dd_h = row_h * 16 + 4
        screen_h = self.winfo_toplevel().winfo_screenheight()
        if ey + eh + dd_h > screen_h:
            # Flip above the entry widget
            y = ey - dd_h
        else:
            y = ey + eh
        self._dd.wm_geometry(f"+{x}+{y}")
        self._dd.deiconify(); self._open = True

    def _close(self, dest=True):
        self._open = False
        if self._dd: self._dd.withdraw()
        if dest and self._dd:
            try: self._dd.destroy()
            except Exception: pass
            self._dd = None; self._lb = None

    def _mc(self):
        try:
            f = self.winfo_toplevel().focus_get()
            if f not in (self._e, self._lb): self._close()
        except Exception: self._close()

    def _lbpick(self,e):
        s = self._lb.curselection()
        if s: self._sel(self._lb.get(s[0]))

    def _lbtab(self,e):
        s = self._lb.curselection()
        if s: self._sel(self._lb.get(s[0]))
        return "break"

    def _sel(self, word):
        self._v.set(word); self._set_b(C["success"])
        self._close()
        self.winfo_toplevel().lift()
        self._e.focus_force()
        if self._cb: self._cb(word)
        self.after(50, self._next)

    def _next(self):
        if self._nxt: self._nxt.focus_force()

    def _set_b(self,c): self.config(highlightbackground=c, highlightthickness=1)


# ── MnemonicShareInput ────────────────────────────────────────────────────────

class MnemonicShareInput(tk.Frame):
    """Collapsible mnemonic share panel.  Share 1 starts expanded; others
    start collapsed so only the header/progress bar is visible.  Clicking the
    header row (or the chevron) toggles the 50-word grid open/closed."""

    def __init__(self, parent, num, wl, start_expanded=True, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        self._wl=wl; self._cells=[]; self._expanded = start_expanded

        hdr = tk.Frame(self, bg=C["surface"],
                       highlightbackground=C["border"], highlightthickness=1,
                       cursor="hand2")
        hdr.pack(fill="x", pady=(0,6))

        # Chevron label — changes between ▸ (collapsed) and ▾ (expanded)
        self._chevron = tk.Label(hdr, text="▾" if start_expanded else "▸",
                                  font=F["body_b"], bg=C["surface"], fg=C["text3"],
                                  cursor="hand2")
        self._chevron.pack(side="left", padx=(10,0), pady=10)

        left = tk.Frame(hdr, bg=C["surface"])
        left.pack(side="left", padx=(6,14), pady=10)
        tk.Label(left, text=f"Share {num}", font=F["body_b"],
                 bg=C["surface"], fg=C["text"]).pack(anchor="w")
        self._count = tk.Label(left, text="0 / 50 words", font=F["caption"],
                                bg=C["surface"], fg=C["text3"])
        self._count.pack(anchor="w")

        self._btn_right = tk.Frame(hdr, bg=C["surface"])
        self._btn_right.pack(side="right", padx=14, pady=10)
        self._paste_btn = FlatButton(self._btn_right, "Paste", self._paste, primary=False, small=True)
        self._paste_btn.pack(side="right", padx=(8,0))
        self._clear_btn = FlatButton(self._btn_right, "Clear", self.clear,  primary=False, small=True)
        self._clear_btn.pack(side="right")

        self._pbar = tk.Canvas(hdr, height=2, bg=C["surface2"], highlightthickness=0)
        self._pbar.pack(fill="x", side="bottom")

        # Bind click on header elements to toggle
        for w in (hdr, self._chevron, left):
            w.bind("<Button-1>", lambda e: self.toggle())

        self._grid_frame = tk.Frame(self, bg=C["bg"])
        for c in range(10): self._grid_frame.columnconfigure(c, weight=1)

        for i in range(50):
            cell = WordEntry(self._grid_frame, i+1, wl, on_confirm=self._confirmed)
            cell.grid(row=i//10, column=i%10, padx=2, pady=2, sticky="ew")
            self._cells.append(cell)
        for i in range(49):
            self._cells[i]._nxt = self._cells[i+1]

        if start_expanded:
            self._grid_frame.pack(fill="x")
        # (collapsed: grid_frame stays unpacked until toggle)

        self._tick()

    def toggle(self):
        """Expand or collapse the word-entry grid."""
        self._expanded = not self._expanded
        if self._expanded:
            self._grid_frame.pack(fill="x")
            self._chevron.config(text="▾")
        else:
            self._grid_frame.pack_forget()
            self._chevron.config(text="▸")

    def expand(self):
        if not self._expanded: self.toggle()

    def collapse(self):
        if self._expanded: self.toggle()

    def get_mnemonic(self): return " ".join(c.get() for c in self._cells)
    def is_complete(self): return all(c.valid() for c in self._cells)
    def valid_count(self): return sum(1 for c in self._cells if c.valid())
    def focus(self):
        """Expand first so cells are visible before giving focus."""
        self.expand()
        if self._cells: self._cells[0].focus()
    def clear(self):
        for c in self._cells: c.set("")
        self._upd()
        self.after(0, self._tick)   # restart tick loop (it stops when is_complete() was True)
    def _confirmed(self,_): self._upd()

    def _tick(self):
        try:
            if not self.winfo_exists(): return
        except Exception: return
        self._upd()
        if not self.is_complete(): self.after(300, self._tick)

    def _upd(self):
        n = self.valid_count()
        col = C["success"] if n==50 else (C["warning"] if n>=25 else C["accent"])
        self._count.config(
            text=f"{n} / 50 words",
            fg=C["success"] if n==50 else (C["warning"] if n>0 else C["text3"]))
        self.update_idletasks()
        w = self._pbar.winfo_width()
        if w > 1:
            self._pbar.delete("all")
            f = int(w*n/50)
            if f: self._pbar.create_rectangle(0,0,f,2, fill=col, outline="")

    def _paste(self):
        try: text = self.clipboard_get()
        except Exception: messagebox.showwarning("Paste","Clipboard empty."); return
        if text.strip().startswith("QCSHARE-"):
            messagebox.showinfo("Wrong format",
                "That looks like a code share (starts with QCSHARE-).\n\n"
                "Switch the share to \"code\" format using the toggle button,\n"
                "then paste it there instead."); return
        words = text.strip().split()
        if len(words) != 50:
            messagebox.showwarning("Wrong length",f"Expected 50 words, got {len(words)}."); return
        bad = [w for w in words if w.lower() not in self._wl]
        if bad and not messagebox.askyesno("Unknown words",
            f"{len(bad)} unknown word(s): {', '.join(bad[:3])}.\nFill anyway?"): return
        for cell,word in zip(self._cells, words): cell.set(word.lower())
        self._upd()


# ── FileInfoCard ──────────────────────────────────────────────────────────────

class FileInfoCard(tk.Frame):
    """Shows file metadata including encrypted-at date and original size."""
    def __init__(self, parent, meta, orig, sz=0, ts=0, **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        # Filename is always inside the encrypted payload (revealed after decryption).
        if orig:
            file_label = orig
        else:
            file_label = "Hidden — shown after decryption"
        mode = meta.get("mode", "?")
        if mode == "single":
            mode_label = "Password-protected"
        elif mode == "shamir":
            mode_label = f"Split key — needs {meta.get('threshold','?')} of {meta.get('total','?')} people"
        else:
            mode_label = mode
        rows = [
            ("File",       file_label),
            ("Mode",       mode_label),
            ("Encryption", "Quantum-resistant (AES-256-GCM + ML-KEM)"),
        ]
        # Show original size and encryption date if available
        if sz: rows.append(("Orig size", fmt_size(sz)))
        if ts:
            try:
                rows.append(("Encrypted", _time.strftime("%Y-%m-%d %H:%M", _time.localtime(ts))))
            except Exception: pass
        for lbl,val in rows:
            row = tk.Frame(self, bg=C["surface"])
            row.pack(fill="x", padx=14, pady=3)
            tk.Label(row, text=lbl, font=F["caption"],
                     bg=C["surface"], fg=C["text3"], width=9, anchor="w").pack(side="left")
            tk.Label(row, text=val, font=F["caption"],
                     bg=C["surface"], fg=C["text2"],
                     wraplength=340, justify="left", anchor="w").pack(side="left", fill="x")
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x", pady=(6,0))


# ── Main App ──────────────────────────────────────────────────────────────────

# DnD support — works when the root Tk was created as TkinterDnD.Tk
try:
    from tkinterdnd2 import DND_FILES as _DND_FILES
except ImportError:
    _DND_FILES = None


class _Tooltip:
    """Minimal hover tooltip for Tkinter widgets.
    Usage: _Tooltip(widget, "text")
    """
    def __init__(self, widget, text):
        self._widget = widget; self._text = text; self._tip = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, event=None):
        if self._tip: return
        try:
            x = self._widget.winfo_rootx() + self._widget.winfo_width() // 2
            y = self._widget.winfo_rooty() - 28
            self._tip = tip = tk.Toplevel(self._widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{x}+{y}")
            tip.configure(bg=C["surface2"])
            tk.Label(tip, text=self._text, font=F["small"],
                     bg=C["surface2"], fg=C["text2"],
                     padx=8, pady=4).pack()
        except Exception: self._tip = None

    def _hide(self, event=None):
        try:
            if self._tip: self._tip.destroy()
        except Exception: pass
        self._tip = None


class DecryptorApp(tk.Toplevel):
    STEPS = ["File", "Secret", "Decrypt"]

    def __init__(self, master=None, payload=None, qcx_path=None, on_close=None, center_at=None):
        super().__init__(master)
        self.title("QuantaCrypt · Decrypt")
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.geometry("620x780")
        self.minsize(560, 560)

        self._payload  = payload
        self._qcx_path = qcx_path
        self._meta     = payload["meta"] if payload else None
        self._orig     = None
        self._sz       = 0   # Original size (known after decryption)
        self._ts       = 0   # Encryption timestamp (known after decryption)
        self._mode_val = self._meta["mode"] if self._meta else None
        self._busy     = False
        self._cancel   = False   # signals worker thread to abort
        self._tmp_path = None    # tracks temp file for cleanup on close
        self._imode    = tk.StringVar(value="mnemonic")
        self._inputs   = []
        self._entries  = []
        self._on_close = on_close
        self._imode_trace_id = None  # set in _load_payload when shamir mode is active
        # Always wire WM_DELETE_WINDOW so closing while busy is handled safely
        self.protocol("WM_DELETE_WINDOW", self._close)

        self._build()
        self._center(center_at=center_at)
        self.update()  # macOS: force canvas embedded-window Configure event so form renders
        if self._payload and qcx_path:
            self._file_card.load(qcx_path)
            self._load_payload()
        elif self._payload:
            self._load_payload()

        # Register drag-and-drop (only works when base class is TkinterDnD.Tk)
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass
        # Ctrl+O to open file (guarded: no-op while busy)
        def _ctrl_o(e):
            if self._busy:
                self._err.config(text="Busy — please wait for decryption to finish")
                self.after(2000, lambda: self._err.config(text="") if self._err.cget("text").startswith("Busy") else None)
            else:
                self._file_card._pick()
        self.bind("<Control-o>", _ctrl_o)
        self.bind("<Control-O>", _ctrl_o)
        # Ctrl+Return to start decryption (shows busy message if already running)
        def _ctrl_ret(e):
            if self._busy:
                self._err.config(text="Busy — please wait for decryption to finish")
                self.after(2000, lambda: self._err.config(text="")
                           if self._err.cget("text").startswith("Busy") else None)
            else:
                self._start()
        self.bind("<Control-Return>", _ctrl_ret)
        # Escape closes the window — safe even without a launcher (on_close may be None)
        self.bind("<Escape>", lambda e: self._close())

    def _close(self):
        if self._busy:
            # Signal worker to stop, clean up temp file, then close
            self._cancel = True
            self._err.config(text="Cancelling — please wait…")
            # Poll until worker finishes (or force close after 5s)
            self._poll_close(0)
            return
        # Clean up any leftover temp file
        if self._tmp_path:
            try: os.remove(self._tmp_path)
            except OSError: pass
            self._tmp_path = None
        self.destroy()
        if self._on_close:
            self._on_close()
        else:
            self.master.destroy()  # no launcher — quit app

    def _poll_close(self, attempts):
        """Poll until the worker thread finishes, then close."""
        if self._busy and attempts < 50:  # up to ~5 seconds
            self.after(100, self._poll_close, attempts + 1)
        else:
            self._busy = False
            self._close()

    def _center(self, center_at=None):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        if center_at:
            cx, cy = center_at
        else:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            cx, cy = sw // 2, sh // 2
        x = max(0, cx - w // 2)
        y = max(0, cy - h // 2)
        self.geometry(f"+{x}+{y}")

    def _on_drop(self, event):
        """Handle drag-and-drop .qcx file."""
        if self._busy: return          # ignore drops during active decryption
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
        path = raw.split("} {")[0]
        if os.path.isfile(path):
            self._file_card.load(path)
            self._on_file(path)

    def _build(self):
        hdr = tk.Frame(self, bg=C["bg"])
        hdr.pack(fill="x", padx=P, pady=(18,0))
        tk.Label(hdr, text="QuantaCrypt", font=F["display"],
                 bg=C["bg"], fg=C["text"]).pack(side="left")
        tk.Label(hdr, text="Decrypt", font=F["heading"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(10,0), pady=3)
        if self._on_close:
            FlatButton(hdr, "← Home", self._close, primary=False, small=True).pack(side="right")
        self._wiz = WizardSteps(self, self.STEPS)
        self._wiz.pack(fill="x", padx=P, pady=(12,0))
        rule(self, pady=0)

        outer = tk.Frame(self, bg=C["bg"]); outer.pack(fill="both", expand=True)
        cv = tk.Canvas(outer, bg=C["bg"], bd=0, highlightthickness=0)
        vsb = tk.Scrollbar(outer, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); cv.pack(side="left", fill="both", expand=True)
        self._body = b = tk.Frame(cv, bg=C["bg"])
        self._cv = cv  # store for scroll-to-top on reset
        wid = cv.create_window((0,0), window=b, anchor="nw")
        b.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(wid, width=e.width))
        # Focus-aware scroll: only scroll this canvas when focus is not in a Toplevel dropdown
        def _scroll(delta):
            fw = self.focus_get()
            if fw and fw.winfo_toplevel() is not self: return
            cv.yview_scroll(delta, "units")
        cv.bind_all("<MouseWheel>", lambda e: _scroll(int(-e.delta)))

        # 1. File — uses shared FileCard from shared_ui
        section_label(b, "1  FILE", padx=P)
        self._file_card = FileCard(b, self._on_file,
                                   prompt="Select an encrypted .qcx file",
                                   sub="Click anywhere · .qcx is QuantaCrypt's encrypted format · or drag & drop",
                                   filetypes=[("QuantaCrypt","*.qcx"),("All files","*")])
        self._file_card.pack(fill="x", padx=P)
        self._info_wrap = tk.Frame(b, bg=C["bg"])
        self._info_wrap.pack(fill="x", padx=P, pady=(8,0))
        # Inspect button — shown after file load, reveals public metadata
        self._inspect_row = tk.Frame(b, bg=C["bg"])
        self._inspect_row.pack(fill="x", padx=P, pady=(4,0))

        # 2. Password / Shares
        section_label(b, "2  PASSWORD / SHARES", padx=P)
        self._sec_wrap = tk.Frame(b, bg=C["bg"])
        self._sec_wrap.pack(fill="x", padx=P)
        tk.Label(self._sec_wrap, text="Open a file to see decryption options.",
                 font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")

        # 3. Output
        section_label(b, "3  OUTPUT FOLDER", padx=P)
        out_row = tk.Frame(b, bg=C["bg"]); out_row.pack(fill="x", padx=P)
        self._out = styled_entry(out_row)
        self._out.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)
        self._browse_btn = FlatButton(out_row, "…", self._browse_out, primary=False, small=True)
        self._browse_btn.pack(side="left", padx=(6,0))
        self._out_hint = tk.Label(b, text="Open a file first to set output folder.",
                                   font=F["caption"], bg=C["bg"], fg=C["text3"], anchor="w")
        self._out_hint.pack(fill="x", padx=P, pady=(4,0))

        rule(b, pady=18, padx=P)
        act = tk.Frame(b, bg=C["bg"]); act.pack(fill="x", padx=P, pady=(0,4))
        self._btn = FlatButton(act, "Decrypt File →", self._start)
        self._btn.pack(side="left")
        self._btn.enable(False)   # enabled once a file is loaded
        # Verify: check key is correct without writing any output to disk
        self._verify_btn = FlatButton(act, "Verify key only", self._start_verify,
                                       primary=False, small=True)
        self._verify_btn.pack(side="left", padx=(10,0))
        self._verify_btn.enable(False)   # enabled once a file is loaded
        # Tooltip so first-time users understand what "Verify key only" does
        _Tooltip(self._verify_btn,
                 "Checks your password/shares are correct without writing any output")
        self._err = tk.Label(b, text="", font=F["caption"], bg=C["bg"], fg=C["error"],
                             anchor="w", justify="left", wraplength=490)
        self._err.pack(fill="x", padx=P, pady=(0,8))

        self._prog = StagedProgressBar(b, [(n,w) for n,w,_ in STAGES])
        # Cancel button row shown alongside the progress bar while busy.
        self._cancel_row = tk.Frame(b, bg=C["bg"])
        self._cancel_btn = FlatButton(
            self._cancel_row, "Cancel", self._request_cancel,
            primary=False, small=True,
        )
        self._cancel_btn.pack(side="right")
        self._results = tk.Frame(b, bg=C["bg"]); self._results.pack(fill="x", padx=P)
        # keyboard shortcut hint
        tk.Label(b, text="Ctrl+O  Open file  ·  Ctrl+↵  Decrypt",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(8,0))
        tk.Frame(b, bg=C["bg"], height=16).pack()

    # ── File loading ──────────────────────────────────────────────────────────

    def _on_file(self, path):
        """Sanitize exception — show our ValueError messages, mask OS errors."""
        self._err.config(text="")  # Clear any previous file-load error
        try:
            pkg = load_pkg(path)
            self._payload  = pkg
            self._meta     = pkg["meta"]
            self._orig     = None
            self._mode_val = self._meta["mode"]
            self._qcx_path = path  # Keep in sync so _run decrypts the right file
            self._load_payload(path)
            self.title(f"{os.path.basename(path)} — QuantaCrypt · Decrypt")
        except ValueError as e:
            # Our own descriptive messages are safe to show
            self._err.config(text=f"File error: {e}")
        except Exception:
            # OS/IO errors — don't expose paths or internals
            self._err.config(text="Could not open file — check it is a valid .qcx file")

    def _load_payload(self, path=None):
        for w in self._info_wrap.winfo_children(): w.destroy()
        # Show metadata — sz/ts not yet known (revealed after decryption)
        FileInfoCard(self._info_wrap, self._meta, self._orig,
                     sz=self._sz, ts=self._ts).pack(fill="x")

        if path or self._qcx_path:
            qcx = path or self._qcx_path
            # Suggest the same folder the .qcx lives in; the original filename
            # is sealed inside the payload and restored automatically after decryption.
            suggested_dir = os.path.dirname(os.path.abspath(qcx))
            if path or not self._out.get().strip():
                self._out.delete(0,"end"); self._out.insert(0, suggested_dir)
            self._out_hint.config(text="Output folder — the original filename will be restored.")

        # Refresh inspect button row — make it discoverable
        for w in self._inspect_row.winfo_children(): w.destroy()
        FlatButton(self._inspect_row, "🔍 View file details", self._show_inspect,
                   primary=False, small=True).pack(side="left")
        tk.Label(self._inspect_row, text="(no password needed)",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(6, 0))

        # Enable action buttons now that a valid file is loaded
        self._btn.enable(True)
        self._btn.config(text="Decrypt File →")  # Restore action label
        self._verify_btn.enable(True)

        for w in self._sec_wrap.winfo_children(): w.destroy()
        self._inputs=[]; self._entries=[]
        self._wiz.set_step(1)

        if self._mode_val == "single":
            tk.Label(self._sec_wrap, text="Password", font=F["caption"],
                     bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(0,3))
            # Password row with per-field show/hide toggle
            pw_row = tk.Frame(self._sec_wrap, bg=C["bg"])
            pw_row.pack(fill="x")
            self._pw = styled_entry(pw_row, show="•")
            self._pw.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)
            self._eye_btn = FlatButton(pw_row, "Show", self._toggle_pw, primary=False, small=True)
            self._eye_btn.pack(side="left", padx=(4,0))
            self._pw.bind("<Return>", lambda e: self._start())
            self._pw.focus()
        else:
            k=self._meta.get("threshold", 2); n=self._meta.get("total", k)
            tk.Label(self._sec_wrap,
                     text=f"Enter any {k} of the {n} shares to unlock this file.",
                     font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(0,6))
            # Remove stale trace from previous file load before _imode.set
            # (which fires all live traces against the destroyed _inputs_frame)
            if self._imode_trace_id:
                try: self._imode.trace_remove("write", self._imode_trace_id)
                except Exception: pass
                self._imode_trace_id = None
            self._imode.set("mnemonic")
            SegmentedControl(self._sec_wrap,
                [("mnemonic","50-word phrases"), ("raw","QCSHARE- codes")],
                self._imode).pack(fill="x", pady=(0,10))
            self._imode_trace_id = self._imode.trace_add("write", lambda *_: self._rebuild_inputs())
            self._inputs_frame = tk.Frame(self._sec_wrap, bg=C["bg"])
            self._inputs_frame.pack(fill="x")
            self._build_share_inputs(k)

    def _show_inspect(self):
        """Show a popup with public metadata from the .qcx file (no key required)."""
        if not self._meta or not self._qcx_path:
            return
        meta = self._meta
        import hashlib

        # Compute file fingerprint
        fp = ""
        try:
            with open(self._qcx_path, "rb") as fh:
                fp = hashlib.sha256(fh.read(65536)).hexdigest()[:16]
        except Exception:
            pass
        try:
            file_size = fmt_size(os.path.getsize(self._qcx_path))
        except OSError:
            file_size = "unknown"

        mode = meta.get("mode", "?")
        if mode == "shamir":
            k, n = meta.get("threshold", "?"), meta.get("total", "?")
            mode_str = f"Split key — needs {k} of {n} people"
        else:
            mode_str = "Password-protected"

        version = meta.get("version", "?")
        key_bits = meta.get("key_bits", 512)

        # Build popup
        win = tk.Toplevel(self)
        win.title("File Info")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        P2 = 20
        tk.Label(win, text="File Info", font=F["heading"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", padx=P2, pady=(18,4))
        tk.Label(win, text=os.path.basename(self._qcx_path), font=F["mono"],
                 bg=C["bg"], fg=C["text2"]).pack(anchor="w", padx=P2, pady=(0,10))

        card = tk.Frame(win, bg=C["surface"],
                        highlightbackground=C["border"], highlightthickness=1)
        card.pack(fill="x", padx=P2, pady=(0,4))

        def row(label, value, hl=False):
            r = tk.Frame(card, bg=C["surface"]); r.pack(fill="x", padx=14, pady=4)
            tk.Label(r, text=label, font=F["caption"], bg=C["surface"],
                     fg=C["text3"], width=14, anchor="w").pack(side="left")
            tk.Label(r, text=value, font=F["caption"], bg=C["surface"],
                     fg=C["success"] if hl else C["text2"],
                     anchor="w", justify="left", wraplength=320).pack(side="left", fill="x")

        row("File size",   file_size)
        row("Mode",        mode_str)
        row("Encryption",  "Quantum-resistant (AES-256-GCM + ML-KEM)")
        row("Password",    "Hardened with slow hash (Argon2id)")
        row("Format",      f"QuantaCrypt v{version}")
        if fp:
            row("Fingerprint", fp + "…  (first 64KB SHA-256)")
        tk.Label(win,
                 text="The original filename and file size are encrypted\n"
                      "and only revealed after successful decryption.",
                 font=F["small"], bg=C["bg"], fg=C["text3"],
                 justify="left").pack(anchor="w", padx=P2, pady=(8,0))

        FlatButton(win, "Close", win.destroy, primary=False, small=True).pack(
            anchor="e", padx=P2, pady=(12,18))

        # Centre over parent
        win.update_idletasks()
        pw, ph = self.winfo_x(), self.winfo_y()
        ww, wh = self.winfo_width(), self.winfo_height()
        dw, dh = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{pw+(ww-dw)//2}+{ph+(wh-dh)//2}")

    def _toggle_pw(self):
        """Toggle password field visibility with text button."""
        if not hasattr(self, "_pw"): return
        vis = self._pw.cget("show") == "•"
        self._pw.config(show="" if vis else "•")
        if hasattr(self, "_eye_btn"):
            self._eye_btn.config(text="Hide" if vis else "Show")

    def _build_share_inputs(self, k):
        for w in self._inputs_frame.winfo_children(): w.destroy()
        self._inputs=[]; self._entries=[]
        if self._imode.get() == "mnemonic":
            wl = get_wl()
            for i in range(k):
                # First share expanded, rest collapsed to reduce initial height
                inp = MnemonicShareInput(self._inputs_frame, i+1, wl, start_expanded=(i==0))
                inp.pack(fill="x", pady=(0,12))
                self._inputs.append(inp)
            if self._inputs: self._inputs[0].focus()
        else:
            # Raw share mode — header row with fill counter + Paste all button
            hdr_row = tk.Frame(self._inputs_frame, bg=C["bg"])
            hdr_row.pack(fill="x", pady=(0,6))
            self._share_counter = tk.Label(hdr_row,
                text=f"0 of {k} shares entered",
                font=F["caption"], bg=C["bg"], fg=C["text3"])
            self._share_counter.pack(side="left")
            # Paste all — finds QCSHARE- lines in clipboard and fills entries in order
            FlatButton(hdr_row, "Paste all", self._paste_all_shares,
                       primary=False, small=True).pack(side="right")
            for i in range(k):
                row = tk.Frame(self._inputs_frame, bg=C["bg"])
                row.pack(fill="x", pady=(0,8))
                tk.Label(row, text=f"Share {i+1}", font=F["caption"],
                         bg=C["bg"], fg=C["text3"], width=9, anchor="w").pack(side="left")
                e = styled_entry(row)
                e.pack(side="left", fill="x", expand=True, ipady=7, ipadx=10)
                def _on_share_key(ev, entry=e):
                    self._update_share_counter()
                    val = entry.get().strip()
                    if not val:
                        entry.config(highlightbackground=C["border"])
                    elif val.startswith("QCSHARE-"):
                        entry.config(highlightbackground=C["success"])
                    else:
                        entry.config(highlightbackground=C["error"])
                e.bind("<KeyRelease>", _on_share_key)
                # <<Paste>> fires before text lands; schedule validation 10ms later
                e.bind("<<Paste>>", lambda ev: self.after(10, _on_share_key, None))
                # Individual paste button for each share
                def _paste_one(entry=e):
                    self._paste_single_share(entry)
                FlatButton(row, "Paste", _paste_one,
                           primary=False, small=True).pack(side="left", padx=(6,0))
                self._entries.append(e)
            if self._entries: self._entries[0].focus()

    def _update_share_counter(self):
        """Update fill count label for raw QCSHARE- mode."""
        if not hasattr(self, "_share_counter"): return
        filled = sum(1 for e in self._entries if e.get().strip())
        total  = len(self._entries)
        col    = C["success"] if filled == total else (C["warning"] if filled > 0 else C["text3"])
        self._share_counter.config(
            text=f"{filled} of {total} share{'s' if total!=1 else ''} entered",
            fg=col)

    def _paste_single_share(self, entry):
        """Paste a single QCSHARE- code from the clipboard into one entry."""
        try:
            text = self.clipboard_get().strip()
        except Exception:
            messagebox.showwarning("Paste", "Clipboard is empty or unreadable.")
            return
        # If clipboard has multiple lines, grab the first QCSHARE- line
        code = text
        for ln in text.splitlines():
            ln = ln.strip()
            if ln.startswith("QCSHARE-"):
                code = ln
                break
        entry.delete(0, "end")
        entry.insert(0, code)
        if code.startswith("QCSHARE-"):
            entry.config(highlightbackground=C["success"])
        else:
            entry.config(highlightbackground=C["error"])
        self._update_share_counter()

    def _paste_all_shares(self):
        """Find all QCSHARE- lines in clipboard and fill entries in order."""
        try:
            text = self.clipboard_get()
        except Exception:
            messagebox.showwarning("Paste all", "Clipboard is empty or unreadable."); return
        lines = [ln.strip() for ln in text.splitlines()]
        found = [ln for ln in lines if ln.startswith("QCSHARE-")]
        if not found:
            messagebox.showwarning(
                "Paste all",
                "No QCSHARE- codes found in clipboard.\n\n"
                "Copy your shares file and try again."); return
        k = len(self._entries)
        if len(found) < k:
            if not messagebox.askyesno(
                    "Not enough shares",
                    f"Found {len(found)} QCSHARE- code(s) but need {k}.\n\n"
                    f"Fill the first {len(found)} anyway?",
                    icon="warning"): return
        for i, entry in enumerate(self._entries):
            entry.delete(0, "end")
            if i < len(found):
                entry.insert(0, found[i])
                entry.config(highlightbackground=C["success"])
            else:
                entry.config(highlightbackground=C["border"])
        self._update_share_counter()

    def _rebuild_inputs(self):
        if self._meta and self._mode_val == "shamir":
            has_data = (
                any(inp.valid_count() > 0 for inp in self._inputs)
                or any(e.get().strip() for e in self._entries)
            )
            if has_data:
                if not messagebox.askyesno("Switch mode?",
                        "Switching input mode will clear any shares you have entered.",
                        icon="warning"):
                    if getattr(self, "_rebuilding", False): return
                    # Use try/finally so flag always gets reset, even on exception
                    try:
                        self._rebuilding = True
                        prev = "raw" if self._imode.get() == "mnemonic" else "mnemonic"
                        self._imode.set(prev)
                    finally:
                        self._rebuilding = False
                    return
            if getattr(self, "_rebuilding", False): return
            self._build_share_inputs(self._meta["threshold"])

    def _browse_out(self):
        cur = self._out.get().strip()
        if cur and os.path.isdir(cur):
            init_dir = cur
        elif cur:
            init_dir = os.path.dirname(os.path.abspath(cur))
        else:
            init_dir = os.path.expanduser("~")
        p = filedialog.askdirectory(initialdir=init_dir)
        if p:
            self._out.delete(0,"end"); self._out.insert(0, p)

    # ── Decrypt flow ──────────────────────────────────────────────────────────

    def _validate(self):
        if not self._payload: return "Open a .qcx file first"
        out_dir = self._out.get().strip()
        if not out_dir: return "Specify an output folder"
        if not os.path.isdir(out_dir): return "Output folder does not exist"
        if self._mode_val == "single":
            if not hasattr(self, "_pw") or not self._pw.get(): return "Enter your password"
        else:
            # Validate enough shares are provided for the threshold
            threshold = self._meta.get("threshold", 2) if self._meta else 2
            if self._imode.get() == "mnemonic":
                if len(self._inputs) < threshold:
                    return f"Need at least {threshold} shares, but only {len(self._inputs)} provided"
                bad = [(i+1, inp.valid_count()) for i,inp in enumerate(self._inputs)
                       if not inp.is_complete()]
                if bad:
                    return "Incomplete: " + ", ".join(f"Share {i}: {n}/50" for i,n in bad)
            else:
                if len(self._entries) < threshold:
                    return f"Need at least {threshold} shares, but only {len(self._entries)} provided"
                empty = [i+1 for i,e in enumerate(self._entries) if not e.get().strip()]
                if empty: return f"Share(s) {empty} are empty"
                # Check QCSHARE- prefix so bad pastes give a clear error
                bad_fmt = [i+1 for i,e in enumerate(self._entries)
                           if e.get().strip() and not e.get().strip().startswith("QCSHARE-")]
                if bad_fmt:
                    verb = "don't" if len(bad_fmt) > 1 else "doesn't"
                    pl = "s" if len(bad_fmt) > 1 else ""
                    return (f"Share{pl} {bad_fmt} {verb} look right — "
                            f"code shares start with QCSHARE-")
        return None

    def _start(self):
        if self._busy: return
        err = self._validate()
        if err:
            self._err.config(text=err)
            self.after(50, lambda: self._cv.yview_moveto(1.0))  # Scroll after layout reflow
            return
        out = self._out.get().strip()
        self._err.config(text=""); self._busy=True
        self._cancel = False
        self._prog.pack(fill="x", padx=P, pady=(0,4), before=self._results)
        self._cancel_row.pack(fill="x", padx=P, pady=(0, 6), before=self._results)
        self._cancel_btn.enable(True)
        self._prog.start(); self._freeze(); self._wiz.set_step(2)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        for w in self._results.winfo_children(): w.destroy()
        # Capture ALL Tk widget state on the main thread — widget reads are not thread-safe
        pw_captured = self._pw.get() if self._mode_val == "single" and hasattr(self, "_pw") else None
        # For Shamir mode, collect shares now (StringVar/Entry reads must be on main thread)
        shares_captured = None
        if self._mode_val != "single":
            try:
                shares_captured = self._collect_shares()
            except Exception as ex:
                self._busy = False
                self._prog.pack_forget()
                self._thaw()
                self._err.config(text=str(ex))
                return
        threading.Thread(target=self._run, args=(out, pw_captured, shares_captured), daemon=True).start()

    def _freeze(self):
        """Disable all interactive controls while decryption runs."""
        self._btn.enable(False)
        try: self._browse_btn.enable(False)  # Prevent browse during decrypt
        except Exception: pass
        try: self._out.config(state="disabled")
        except Exception: pass
        try:
            self._file_card.config(cursor="")
            for w in [self._file_card, self._file_card._icon,
                      self._file_card._line1, self._file_card._line2]:
                w.unbind("<Button-1>")
            # Suppress hover highlight during decryption
            self._file_card.unbind("<Enter>")
            self._file_card.unbind("<Leave>")
        except Exception: pass
        # Freeze password or share inputs
        try:
            if self._mode_val == "single" and hasattr(self, "_pw"):
                self._pw.config(state="disabled")
                self._eye_btn.enable(False)
        except Exception: pass

    def _thaw(self):
        """Re-enable all interactive controls after decryption completes or fails."""
        self._btn.enable(True)
        try: self._browse_btn.enable(True)  # Restore browse button
        except Exception: pass
        try: self._out.config(state="normal")
        except Exception: pass
        try:
            self._file_card.config(cursor="hand2")
            for w in [self._file_card, self._file_card._icon,
                      self._file_card._line1, self._file_card._line2]:
                w.bind("<Button-1>", lambda e: self._file_card._pick())
            # Restore hover bindings after decryption
            self._file_card.bind("<Enter>", lambda e: self._file_card._hl(True))
            self._file_card.bind("<Leave>", lambda e: self._file_card._hl(False))
        except Exception: pass
        try:
            if self._mode_val == "single" and hasattr(self, "_pw"):
                self._pw.config(state="normal")
                if hasattr(self, "_eye_btn"): self._eye_btn.enable(True)
        except Exception: pass

    def _prog_cb(self, msg):
        idx,_ = _find_stage(msg)
        if idx is not None: self.after(0, self._prog.advance, idx, msg)

    def _run(self, out_dir, pw_captured, shares_captured=None):
        """Worker thread — streaming decryption."""
        tmp = os.path.join(out_dir, f".qcx_decrypt_{uuid.uuid4().hex[:8]}.tmp")
        self._tmp_path = tmp
        try:
            if self._cancel:
                return
            meta = self._meta

            # Derive final_key from whichever credential mode was used
            if self._mode_val == "single":
                self.after(0, self._prog.advance, 0, "Verifying your password...")
                # Encode to bytes and drop the str reference right away.
                # Python can't actively zero strings, but releasing the only
                # reference lets the GC reclaim the memory; the bytes object
                # is harder to spot in a heap dump.
                pw_bytes = pw_captured.encode()
                pw_captured = None  # noqa: F841 — release str reference
                argon_key = cc.argon2id_derive(pw_bytes, _b64.b64decode(meta["argon_salt"]))
                del pw_bytes
                self.after(0, self._prog.advance, 1, "Loading encryption key...")
                sk = cc.aes_gcm_decrypt(argon_key,
                                        _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                        _b64.b64decode(meta["kyber_sk_enc"]))
                self.after(0, self._prog.advance, 2, "Unlocking file protection...")
                kem_ss    = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
                final_key = cc.xor_bytes(argon_key, kem_ss)
                hmac_key  = final_key
                # Mark stage 3 done so no dot is skipped in the visual sequence
                self.after(0, self._prog.advance, 3, "Key ready")
            else:
                self.after(0, self._prog.advance, 0, f"Reading {len(shares_captured)} shares...")
                share_dicts = [cc.decode_share(s) for s in shares_captured]
                self.after(0, self._prog.advance, 1, "Combining shares to recover the key...")
                master_key = cc.shamir_recover(share_dicts[:meta["threshold"]])
                self.after(0, self._prog.advance, 2, "Loading encryption key...")
                sk = cc.aes_gcm_decrypt(master_key,
                                        _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                        _b64.b64decode(meta["kyber_sk_enc"]))
                self.after(0, self._prog.advance, 3, "Unlocking file protection...")
                kem_ss    = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
                final_key = cc.xor_bytes(master_key, kem_ss)
                hmac_key  = master_key

            # Verify metadata HMAC before touching the payload
            cc._verify_meta_hmac(hmac_key, meta)

            self.after(0, self._prog.advance, 4, "Decrypting your file...")
            with open(tmp, "wb") as f:
                fname, sz, ts = cc.decrypt_streaming(
                    self._qcx_path, f, meta, final_key,
                    progress_cb=self._prog_cb,
                    cancel_check=lambda: self._cancel)
            out_size = os.path.getsize(tmp)

            # Build the final output path from the original filename stored in
            # the payload.  basename() already blocks path traversal; also
            # strip null bytes and control characters that would land in the
            # filesystem as invisible / unusable filenames, and fall back to
            # a generic name if nothing usable remains.
            orig_basename = os.path.basename(fname) if fname else ""
            orig_basename = "".join(
                ch for ch in orig_basename
                if ch.isprintable() and ch not in ("/", "\0")
            ).strip().strip(".")
            if not orig_basename:
                orig_basename = "decrypted"
            out = os.path.join(out_dir, orig_basename)
            root, ext = os.path.splitext(orig_basename)
            n = 2
            while os.path.exists(out):
                out = os.path.join(out_dir, f"{root}_{n}{ext}")
                n += 1
            os.replace(tmp, out)

            if self._mode_val == "single":
                self.after(0, self._clear_pw)
            self.after(0, self._done, out, out_size, fname, sz, ts)
        except cc.CancelledOperation:
            try: os.remove(tmp)
            except OSError: pass
            self.after(0, self._cancelled)
        except Exception as ex:
            try: os.remove(tmp)
            except OSError: pass
            # Some cryptography exceptions (e.g. InvalidTag) produce an empty str().
            # Fall back to the class name so _fail can still pattern-match on it.
            self.after(0, self._fail, str(ex) or type(ex).__name__)

    def _clear_pw(self):
        """Clear password entry on the main thread after successful decryption."""
        if hasattr(self, "_pw"):
            try: self._pw.delete(0, "end")
            except Exception: pass

    def _collect_shares(self):
        if self._imode.get() == "mnemonic":
            share_dicts = [cc.mnemonic_to_share(inp.get_mnemonic()) for inp in self._inputs]
            meta_k = self._meta.get("threshold", 0)
            for i, sd in enumerate(share_dicts, 1):
                mn_k = sd.get("threshold", 0)
                if mn_k and mn_k != meta_k:
                    raise ValueError(
                        f"Share {i} doesn't match this file — it was created for a "
                        f"different encryption that needs {mn_k} people, but this file "
                        f"needs {meta_k}. Check you have the right shares."
                    )
            return [cc.encode_share(sd) for sd in share_dicts]
        return [e.get().strip() for e in self._entries]

    def _start_verify(self):
        """Validate the password/shares decrypt the file without writing any output.
        Derives keys, verifies the metadata HMAC, and decrypts the first chunk only.
        Gives confidence the credentials are correct before doing a full decrypt."""
        if self._busy: return
        err = self._validate()
        if err:
            self._err.config(text=err)
            self.after(50, lambda: self._cv.yview_moveto(1.0))
            return
        self._err.config(text=""); self._busy = True
        self._prog.pack(fill="x", padx=P, pady=(0,4), before=self._results)
        self._prog.start(); self._freeze(); self._wiz.set_step(2)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        for w in self._results.winfo_children(): w.destroy()
        pw_captured = self._pw.get() if self._mode_val == "single" and hasattr(self, "_pw") else None
        shares_captured = None
        if self._mode_val != "single":
            try:
                shares_captured = self._collect_shares()
            except Exception as ex:
                self._busy = False
                self._prog.pack_forget()
                self._thaw()
                self._err.config(text=str(ex))
                return
        threading.Thread(
            target=self._verify_run,
            args=(pw_captured, shares_captured),
            daemon=True
        ).start()

    def _verify_run(self, pw_captured, shares_captured=None):
        """Worker thread: derive keys, verify HMAC, decrypt first chunk. No output written."""
        try:
            meta = self._meta
            if self._mode_val == "single":
                self.after(0, self._prog.advance, 0, "Verifying your password...")
                pw_bytes = pw_captured.encode()
                pw_captured = None  # noqa: F841 — release str reference
                argon_key = cc.argon2id_derive(pw_bytes, _b64.b64decode(meta["argon_salt"]))
                del pw_bytes
                self.after(0, self._prog.advance, 1, "Loading encryption key...")
                sk = cc.aes_gcm_decrypt(argon_key,
                                        _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                        _b64.b64decode(meta["kyber_sk_enc"]))
                self.after(0, self._prog.advance, 2, "Unlocking file protection...")
                kem_ss    = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
                final_key = cc.xor_bytes(argon_key, kem_ss)
                hmac_key  = final_key
                self.after(0, self._prog.advance, 3, "Key ready")
            else:
                self.after(0, self._prog.advance, 0, f"Reading {len(shares_captured)} shares...")
                share_dicts = [cc.decode_share(s) for s in shares_captured]
                self.after(0, self._prog.advance, 1, "Combining shares to recover the key...")
                master_key = cc.shamir_recover(share_dicts[:meta["threshold"]])
                self.after(0, self._prog.advance, 2, "Loading encryption key...")
                sk = cc.aes_gcm_decrypt(master_key,
                                        _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                                        _b64.b64decode(meta["kyber_sk_enc"]))
                self.after(0, self._prog.advance, 3, "Unlocking file protection...")
                kem_ss    = cc.kyber_decaps(sk, _b64.b64decode(meta["kyber_kem_ct"]))
                final_key = cc.xor_bytes(master_key, kem_ss)
                hmac_key  = master_key

            # Step 1: verify metadata HMAC
            self.after(0, self._prog.advance, 4, "Checking file integrity...")
            cc._verify_meta_hmac(hmac_key, meta)

            # Step 2: decrypt first chunk only — proves AES key is correct without full decrypt
            import struct as _struct
            payload_offset = meta.get("payload_offset", 0)
            base_nonce = _b64.b64decode(meta["payload_nonce"])
            aes_key = cc.derive_aes_key(final_key)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            cipher = AESGCM(aes_key)
            with open(self._qcx_path, "rb") as f:
                f.seek(payload_offset)
                seq_raw = f.read(4)
                if len(seq_raw) < 4:
                    raise ValueError("File appears truncated")
                seq = _struct.unpack(">I", seq_raw)[0]
                if seq != 0:
                    raise ValueError(f"First chunk has unexpected sequence number {seq} — file may be corrupt")
                ct_len = _struct.unpack(">I", f.read(4))[0]
                ct = f.read(ct_len)
            nonce = cc._chunk_nonce(base_nonce, 0)
            chunk_count = meta["payload_chunk_count"]
            aad = cc._chunk_aad(0, chunk_count == 1)
            cipher.decrypt(nonce, ct, aad)  # raises if wrong key
            self.after(0, self._verify_done)
        except Exception as ex:
            self.after(0, self._fail, str(ex) or type(ex).__name__)

    def _verify_done(self):
        """Show verification success without writing any output."""
        self._busy = False; self._prog.complete(); self._thaw()
        self._wiz.set_step(len(self.STEPS))
        ok = tk.Frame(self._results, bg=C["surface"],
                      highlightbackground=C["success"], highlightthickness=1)
        ok.pack(fill="x", pady=(14,0))
        ok_in = tk.Frame(ok, bg=C["surface"]); ok_in.pack(fill="x", padx=14, pady=12)
        tk.Label(ok_in, text="✓  Key verified — credentials are correct",
                 font=F["body_b"], bg=C["surface"], fg=C["success"]).pack(side="left")
        tk.Label(ok, text="Your password / shares successfully decrypted the first block. "
                          "No output file was written.",
                 font=F["caption"], bg=C["surface"], fg=C["text3"],
                 anchor="w", justify="left", wraplength=490).pack(anchor="w", padx=14, pady=(0,8))
        btn_row = tk.Frame(ok, bg=C["surface"]); btn_row.pack(fill="x", padx=14, pady=(0,12))
        FlatButton(btn_row, "Decrypt now →", self._reset_and_decrypt,
                   primary=True, small=True).pack(side="left")
        FlatButton(btn_row, "Decrypt another →", self._reset,
                   primary=False, small=True).pack(side="left", padx=(8,0))
        self.after(50, lambda: self._cv.yview_moveto(1.0))

    def _reset_and_decrypt(self):
        """After a successful verify, keep the same file loaded and go straight to decrypt."""
        # Save state we want to preserve
        saved_payload  = self._payload
        saved_meta     = self._meta
        saved_qcx      = self._qcx_path
        saved_mode     = self._mode_val
        self._reset()
        # Reload the same file so the form is populated
        if saved_qcx and os.path.isfile(saved_qcx):
            self._file_card.load(saved_qcx)
            self._payload  = saved_payload
            self._meta     = saved_meta
            self._qcx_path = saved_qcx
            self._mode_val = saved_mode
            self._load_payload()

    def _done(self, path, size, fname="", sz=0, ts=0):
        self._busy=False; self._prog.complete(); self._cancel_row.pack_forget(); self._thaw()
        # Immediately disable the Decrypt button — _thaw() re-enables it,
        # but on success it must stay disabled until "Decrypt another" is clicked.
        # Doing this before building the card avoids a visible flash of the enabled state.
        self._btn.enable(False)
        # set_step past the last step → all circles show ✓ (complete)
        self._wiz.set_step(len(self.STEPS))
        display = os.path.basename(fname) if fname else os.path.basename(path)
        notify("Decryption complete", display)
        # Store sz/ts and recovered filename so FileInfoCard shows them
        self._sz = sz; self._ts = ts
        # Update _orig with the decrypted filename and refresh the info card
        self._orig = os.path.basename(fname) if fname else None
        # Add to recent files list
        try:
            from quantacrypt.ui.shared import RecentFiles
            RecentFiles.add(self._qcx_path, self._meta)
        except Exception:
            pass
        for w in self._info_wrap.winfo_children(): w.destroy()
        if self._meta:
            FileInfoCard(self._info_wrap, self._meta, self._orig,
                         sz=sz, ts=ts).pack(fill="x")
        # Clear all share inputs from UI after successful decryption (security)
        cleared_shares = False
        for inp in self._inputs:
            try: inp.clear(); cleared_shares = True
            except Exception: pass
        # Also clear raw QCSHARE- entry widgets (used in raw mode)
        for entry in getattr(self, "_entries", []):
            try:
                entry.config(state="normal")
                entry.delete(0, "end")
            except Exception: pass
        ok = tk.Frame(self._results, bg=C["surface"],
                      highlightbackground=C["success"], highlightthickness=1)
        ok.pack(fill="x", pady=(14,0))
        ok_in = tk.Frame(ok, bg=C["surface"]); ok_in.pack(fill="x", padx=14, pady=12)
        tk.Label(ok_in, text="✓  Decrypted successfully", font=F["body_b"],
                 bg=C["surface"], fg=C["success"]).pack(side="left")
        tk.Label(ok_in, text=fmt_size(size), font=F["caption"],
                 bg=C["surface"], fg=C["text3"]).pack(side="right")
        # Sanitize: apply basename so metadata-embedded paths can't mislead user
        display_name = (os.path.basename(fname) if fname else None) or os.path.basename(path)
        # Only show separate filename line when it differs from the output path basename
        if display_name != os.path.basename(path):
            tk.Label(ok, text=display_name, font=F["mono"],
                     bg=C["surface"], fg=C["text2"]).pack(anchor="w", padx=14, pady=(0,2))
        # Show full output path so user knows exactly where it went
        tk.Label(ok, text=path, font=F["caption"],
                 bg=C["surface"], fg=C["text3"], anchor="w",
                 wraplength=490, justify="left").pack(anchor="w", padx=14, pady=(2,0))
        # Show original size and timestamp if available
        if sz or ts:
            info_parts = []
            if sz: info_parts.append(f"Original: {fmt_size(sz)}")
            if ts:
                try: info_parts.append(f"Encrypted: {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(ts))}")
                except Exception: pass
            if info_parts:
                tk.Label(ok, text="  ·  ".join(info_parts), font=F["caption"],
                         bg=C["surface"], fg=C["text3"]).pack(anchor="w", padx=14, pady=(4,0))
        # Note that shares were cleared for security
        if cleared_shares:
            tk.Label(ok, text="Share inputs cleared after decryption.",
                     font=F["caption"], bg=C["surface"], fg=C["text3"]).pack(anchor="w", padx=14, pady=(2,0))
        # Label the button so it's clear re-running needs "Decrypt another →"
        self._btn.config(text="Decrypt again →")
        # Reveal + decrypt another
        btn_row = tk.Frame(ok, bg=C["surface"]); btn_row.pack(fill="x", padx=14, pady=(8,12))
        FlatButton(btn_row, "Decrypt another →", self._reset, primary=False, small=True).pack(side="left")
        # If output looks like a folder-encrypted zip, offer one-click extraction
        import zipfile as _zf
        _is_folder_zip = (fname or "").endswith(".zip") and os.path.isfile(path) and _zf.is_zipfile(path)
        if _is_folder_zip:
            def _extract(p=path):
                import zipfile, tkinter.messagebox as _mb
                out_dir = os.path.dirname(os.path.abspath(p))
                try:
                    with zipfile.ZipFile(p) as zf:
                        names = zf.namelist()
                        # Validate paths to prevent directory traversal attacks
                        real_out = os.path.realpath(out_dir)
                        for member in names:
                            target = os.path.realpath(os.path.join(out_dir, member))
                            if not target.startswith(real_out + os.sep) and target != real_out:
                                raise ValueError(f"Path traversal detected in archive: {member}")
                        zf.extractall(out_dir)
                    top = os.path.join(out_dir, names[0].split("/")[0]) if names else out_dir
                    _reveal(top)
                    _mb.showinfo("Extracted", f"Folder extracted to:\n{out_dir}", parent=self)
                except Exception as ex:
                    _mb.showerror("Extraction failed", str(ex), parent=self)
            FlatButton(btn_row, "Extract folder", _extract, primary=True, small=True).pack(side="left", padx=(8,0))
        else:
            FlatButton(btn_row, "Open file", lambda: _open_file(path), primary=False, small=True).pack(side="left", padx=(8,0))
        FlatButton(btn_row, "Show in folder", lambda: _reveal(path), primary=False, small=True).pack(side="left", padx=(8,0))
        self.after(50, lambda: self._cv.yview_moveto(1.0))

    def _reset(self):
        self._payload  = None; self._meta = None; self._orig = None
        self._mode_val = None; self._inputs = []; self._entries = []
        self._sz = 0; self._ts = 0
        # Clear trace ID so next file load does not attempt to remove a stale ID
        if self._imode_trace_id:
            try: self._imode.trace_remove("write", self._imode_trace_id)
            except Exception: pass
            self._imode_trace_id = None
        self._out.delete(0, "end")
        self._out_hint.config(text="Open a file first to set output path.")
        self._err.config(text="")
        for w in self._results.winfo_children(): w.destroy()
        for w in self._info_wrap.winfo_children(): w.destroy()
        for w in self._inspect_row.winfo_children(): w.destroy()
        for w in self._sec_wrap.winfo_children(): w.destroy()
        self._verify_btn.enable(False)
        tk.Label(self._sec_wrap, text="Open a file to see decryption options.",
                 font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")
        # Use FileCard.reset() — no destroy/recreate needed
        self._file_card.reset("Select an encrypted file",
                              "Click anywhere · .qcx files · or drag & drop")
        # btn stays disabled — re-enabled by _load_payload when a valid file is opened
        self._btn.config(text="Open a file to begin")  # Neutral text while disabled
        self._prog.pack_forget(); self._wiz.set_step(0)
        self.title("QuantaCrypt · Decrypt")
        self.after(10, lambda: self._cv.yview_moveto(0))
        self.after(20, self._file_card.focus_set)  # Restore focus after reset

    def _request_cancel(self):
        """User hit Cancel — flag the worker; it raises CancelledOperation
        at the next chunk boundary."""
        if not self._busy:
            return
        self._cancel = True
        try:
            self._cancel_btn.enable(False)
        except Exception:
            pass
        self._err.config(text="Cancelling — finishing the current chunk…")

    def _cancelled(self):
        """Post-cancel UI reset."""
        self._busy = False
        self._cancel = False
        self._tmp_path = None
        self._prog.stop()
        self._prog.pack_forget()
        self._cancel_row.pack_forget()
        self._thaw()
        self._wiz.set_step(2)
        self._err.config(text="Decryption cancelled — no output was written.")

    def _fail(self, msg):
        self._busy=False; self._cancel=False; self._tmp_path=None
        self._prog.stop(); self._prog.pack_forget(); self._cancel_row.pack_forget(); self._thaw()
        self._wiz.set_step(2)  # stay at Decrypt step — error is shown there
        if "InvalidTag" in msg:
            hint = ("Wrong password — please re-enter and try again."
                    if self._mode_val == "single" else
                    "Wrong shares — check you have the correct shares for this file.")
            self._err.config(text=hint)
            # Auto-select the password field so the user can immediately retype
            if self._mode_val == "single" and hasattr(self, "_pw"):
                # Defer focus so _thaw's state=normal is processed first
                def _refocus():
                    try: self._pw.focus_set(); self._pw.selection_range(0, "end")
                    except Exception: pass
                self.after(10, _refocus)
        elif "older format" in msg.lower() or "no longer supported" in msg.lower():
            self._err.config(text=msg)
        elif "Checksum" in msg:
            self._err.config(text="One of your shares has a checksum error — it may be damaged or for a different file.")
        elif "threshold mismatch" in msg.lower() or "doesn't match this file" in msg.lower():
            self._err.config(text=msg)  # our own descriptive message
        elif "newer version" in msg.lower():
            self._err.config(text=msg)  # Safe — our own message
        elif "No space left" in msg or "disk" in msg.lower():
            self._err.config(text="Not enough disk space. Free up some storage and try again.")
        elif "Permission" in msg or "Access is denied" in msg:
            self._err.config(text="Can't write to that folder — check permissions or choose a different output folder.")
        elif "Not a QuantaCrypt" in msg or "truncated" in msg.lower():
            self._err.config(text="This doesn't appear to be a valid .qcx file. Make sure you selected the right file.")
        elif "out of range" in msg.lower():
            self._err.config(text="These shares don't work — they may be damaged or from a different file.")
        elif "Metadata authentication" in msg or "tampered" in msg.lower():
            self._err.config(text="This file appears to have been modified or corrupted. It can't be safely decrypted.")
        elif "Authentication failed" in msg or "chunk" in msg.lower():
            self._err.config(text="File integrity check failed — the file may be damaged or corrupted.")
        else:
            self._err.config(text="Something went wrong. Double-check your inputs and try again.")
        # Scroll to bottom so the error label is visible
        self.after(50, lambda: self._cv.yview_moveto(1.0))  # Reflow delay


def main():
    payload = qcx_path = None
    if getattr(sys,"frozen",False):
        try: payload = load_pkg(sys.executable); qcx_path = sys.executable
        except ValueError: pass
    DecryptorApp(payload=payload, qcx_path=qcx_path).mainloop()

if __name__ == "__main__":
    main()
