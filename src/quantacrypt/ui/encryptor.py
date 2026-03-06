#!/usr/bin/env python3
"""QuantaCrypt Encryptor — encryption GUI with password and Shamir modes."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import zipfile

import tkinter as tk
from tkinter import filedialog, messagebox

from quantacrypt.core import crypto as cc
from quantacrypt.ui.shared import (
    C, F,
    styled_entry, bind_context_menu, fmt_size, rule, section_label,
    FlatButton, SegmentedControl, StagedProgressBar,
    PasswordStrengthBar, FileCard, WizardSteps, ClipboardTimer,
    notify,
)


def _folder_stats(folder):
    """Return (file_count, total_bytes) for a folder tree."""
    count, total = 0, 0
    for dirpath, _, filenames in os.walk(folder):
        for fn in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
            count += 1
    return count, total


def _zip_folder(folder, dst_path, progress_cb=None):
    """Zip folder into dst_path with paths relative to folder's parent.

    The top-level directory name is preserved inside the archive.
    Fires progress_cb(msg) every file.  Returns bytes written.
    """
    parent = os.path.dirname(os.path.abspath(folder))
    total_files, _ = _folder_stats(folder)
    done = 0
    with zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for dirpath, dirnames, filenames in os.walk(folder):
            dirnames.sort()
            filenames.sort()
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                arcname = os.path.relpath(full, parent)
                zf.write(full, arcname)
                done += 1
                if progress_cb and total_files:
                    pct = done / total_files
                    progress_cb(
                        f"Compressing folder… {int(pct * 100)}%"
                        f" ({done}/{total_files} files)"
                    )

STAGES = [
    ("Compressing folder",    0.10, "Compressing"),  # folder-only; skipped for plain files
    ("Securing password",     0.50, "Argon2id"),
    ("Generating protection", 0.13, "Kyber"),
    ("Locking key",           0.04, "private key"),
    ("Encrypting file",       0.18, "payload"),
    ("Saving",                0.05, "Writing"),
]
# Indices for stages that carry semantic meaning in the code
STAGE_COMPRESS = 0
STAGE_ARGON    = 1
STAGE_KEM      = 2
STAGE_ENCKEY   = 3
STAGE_PAYLOAD  = 4
STAGE_WRITE    = 5

def _find_stage(msg):
    for i,(name,_,kw) in enumerate(STAGES):
        if kw.lower() in msg.lower(): return i, msg
    return None, None

def _reveal(path, open_file=False):
    """Open the containing folder (or the file itself) in the OS."""
    try:
        if open_file:
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["open", "-R", path])
    except Exception:
        pass


class ShareCard(tk.Frame):
    def __init__(self, parent, idx, raw, mnemonic=None, **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        self._raw=raw; self._mn=mnemonic
        self._use_mn=bool(mnemonic)  # default: show mnemonic when available
        hdr=tk.Frame(self,bg=C["surface"])
        hdr.pack(fill="x",padx=14,pady=(12,6))
        tk.Label(hdr,text=f"Share {idx}",font=F["body_b"],
                 bg=C["surface"],fg=C["text"]).pack(side="left")
        if mnemonic:
            # Prominent toggle button — much more discoverable than a tiny checkbox
            self._fmt_btn=FlatButton(hdr,"Switch to code",self._toggle_fmt,
                                     primary=False,small=True)
            self._fmt_btn.pack(side="right")
        self._txt=tk.Text(self,font=F["mono_s"],bg=C["surface2"],fg=C["text2"],
                          relief="flat",bd=0,highlightthickness=0,wrap="word",
                          selectbackground=C["accent_dim"])
        bind_context_menu(self._txt)
        self._txt.pack(fill="x",padx=14,pady=(0,4))
        self._refresh()
        btn_row = tk.Frame(self, bg=C["surface"]); btn_row.pack(fill="x", padx=14, pady=(0,10))
        self._copy_btn = FlatButton(btn_row,"Copy",self._copy,primary=False,small=True)
        self._copy_btn.pack(side="left")
        # Clipboard auto-clear countdown label
        self._clip_lbl = tk.Label(btn_row, text="", font=F["small"],
                                   bg=C["surface"], fg=C["text3"])
        self._clip_lbl.pack(side="left", padx=(8,0))
        self._clip_timer = ClipboardTimer(self, self._clip_lbl)

    def _current(self):
        return self._mn if (self._use_mn and self._mn) else self._raw

    def _toggle_fmt(self):
        self._use_mn = not self._use_mn
        self._fmt_btn.config(text="Switch to words" if not self._use_mn else "Switch to code")
        self._refresh()

    def _refresh(self):
        is_w=self._use_mn and self._mn
        self._txt.config(height=5 if is_w else 2,state="normal")
        self._txt.delete("1.0","end"); self._txt.insert("1.0",self._current())
        self._txt.config(state="disabled")

    def _copy(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self._current())
            self._copy_btn.config(text="✓ Copied")
            self.after(1500, lambda: self._copy_btn.config(text="Copy") if self.winfo_exists() else None)
            self._clip_timer.start()  # 60-second auto-clear countdown
        except Exception:
            self._copy_btn.config(text="⚠ Failed")
            self.after(2000, lambda: self._copy_btn.config(text="Copy") if self.winfo_exists() else None)

    def mark_saved(self):
        """Visually indicate this share has been written to a file."""
        try:
            self._clip_timer.cancel()
            self._copy_btn.enable(False)
            self._copy_btn.config(text="✓ Saved")
            self.config(highlightbackground=C["success"])
        except Exception: pass


# DnD support — works when the root Tk was created as TkinterDnD.Tk
try:
    from tkinterdnd2 import DND_FILES as _DND_FILES
except ImportError:
    _DND_FILES = None


class EncryptorApp(tk.Toplevel):
    STEPS = ["File", "Mode", "Secret", "Output", "Encrypt"]
    _P    = 24   # Single class-level padding constant

    def __init__(self, master=None, on_close=None, center_at=None):
        super().__init__(master)
        self.title("QuantaCrypt · Encrypt")
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.geometry("620x780")
        self.minsize(560, 560)
        self._path=None; self._is_folder=False; self._batch_paths=[]; self._mode=tk.StringVar(value="single")
        self._n=tk.IntVar(value=3); self._k=tk.IntVar(value=2)
        self._pw1v=tk.StringVar(); self._pw2v=tk.StringVar()
        self._embed_dec=tk.BooleanVar(value=False)
        self._shares_pending=False   # True after Shamir encrypt until shares saved/dismissed
        self._pending_shares=[]
        self._scroll_job=None  # Track pending scroll so _reset can cancel it
        self._busy=False; self._on_close=on_close
        self._out_auto=False  # True when output path was auto-generated
        # Always wire WM_DELETE_WINDOW through _close so share guard fires
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._build()
        self._center(center_at=center_at)
        self.update()  # macOS: force canvas embedded-window Configure event so form renders
        # Register DnD (only works when base class is TkinterDnD.Tk)
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass
        # Ctrl+O to open file (guarded: no-op while busy)
        def _ctrl_o(e):
            if self._busy:
                self._err.config(text="Busy — please wait for encryption to finish")
                self.after(2000, lambda: self._err.config(text="") if self._err.cget("text").startswith("Busy") else None)
            else:
                self._file_card._pick()
        self.bind("<Control-o>", _ctrl_o)
        self.bind("<Control-O>", _ctrl_o)
        # Ctrl+Return to start encryption (shows busy message if already running)
        def _ctrl_ret(e):
            if self._busy:
                self._err.config(text="Busy — please wait for encryption to finish")
                self.after(2000, lambda: self._err.config(text="")
                           if self._err.cget("text").startswith("Busy") else None)
            else:
                self._start()
        self.bind("<Control-Return>", _ctrl_ret)
        # Escape closes the window — safe even without a launcher (on_close may be None)
        self.bind("<Escape>", lambda e: self._close())

    def _check_shares_saved(self):
        """Return True if safe to proceed; prompt if shares may be unsaved."""
        if not self._shares_pending:
            return True
        if not messagebox.askyesno(
                "Shares not saved",
                "You haven't saved the shares yet.\n\n"
                "If you leave now, the shares will be lost and nobody will be able "
                "to unlock the encrypted file.\n\n"
                "Leave anyway?",
                icon="warning", default="no"):
            return False
        return True

    def _close(self):
        if self._busy:
            self._err.config(text="Encryption in progress — please wait until it finishes")
            self.after(3000, lambda: self._err.config(text="")
                       if self._err.cget("text").startswith("Encryption in progress") else None)
            return
        if not self._check_shares_saved(): return
        self.destroy()
        if self._on_close:
            self._on_close()
        else:
            self.master.destroy()  # no launcher — quit app

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
        """Handle drag-and-drop file or folder."""
        if self._busy: return
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
        path = raw.split("} {")[0]
        if os.path.isdir(path):
            # Auto-switch toggle to folder mode and load
            self._src_type.set("folder")
            self._on_folder(path)
        elif os.path.isfile(path):
            self._src_type.set("file")
            self._file_card.load(path)
            self._on_file(path)

    def _build(self):
        P = self._P  # Local alias so all padx=P in _build use class constant
        hdr=tk.Frame(self,bg=C["bg"])
        hdr.pack(fill="x",padx=P,pady=(18,0))
        tk.Label(hdr,text="QuantaCrypt",font=F["display"],bg=C["bg"],fg=C["text"]).pack(side="left")
        tk.Label(hdr,text="Encrypt",font=F["heading"],bg=C["bg"],fg=C["text3"]).pack(side="left",padx=(10,0),pady=3)
        if self._on_close:
            FlatButton(hdr,"← Home",self._close,primary=False,small=True).pack(side="right")
        self._wiz=WizardSteps(self,self.STEPS)
        self._wiz.pack(fill="x",padx=P,pady=(12,0))
        rule(self,pady=0)

        outer=tk.Frame(self,bg=C["bg"]); outer.pack(fill="both",expand=True)
        cv=tk.Canvas(outer,bg=C["bg"],bd=0,highlightthickness=0)
        vsb=tk.Scrollbar(outer,orient="vertical",command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); cv.pack(side="left",fill="both",expand=True)
        b=self._body=tk.Frame(cv,bg=C["bg"])
        self._cv=cv  # store for scroll-to-top on reset
        wid=cv.create_window((0,0),window=b,anchor="nw")
        b.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>",lambda e:cv.itemconfig(wid,width=e.width))
        # Focus-aware scroll: only scroll this canvas when focus is not in a Toplevel dropdown
        def _scroll(delta):
            fw = self.focus_get()
            if fw and fw.winfo_toplevel() is not self: return
            cv.yview_scroll(delta, "units")
        cv.bind_all("<MouseWheel>", lambda e: _scroll(int(-e.delta)))

        # 1. File/Folder/Batch picker
        section_label(b,"1  SOURCE",padx=P)
        self._src_type = tk.StringVar(value="file")
        self._src_toggle = SegmentedControl(b,
            [("file","Single File"),("folder","Entire Folder"),("batch","Multiple Files")],
            self._src_type)
        self._src_toggle.pack(fill="x",padx=P,pady=(0,8))
        self._src_type.trace_add("write", self._on_src_type)
        self._file_card=FileCard(b, self._on_file,
                                 prompt="Select a file to encrypt",
                                 sub="Click anywhere · or drag & drop")
        self._file_card.pack(fill="x",padx=P)
        # Batch file list (shown only in batch mode)
        self._batch_frame = tk.Frame(b, bg=C["bg"])
        # (packed/unpacked by _on_src_type)

        # 2. Mode
        section_label(b,"2  PROTECTION TYPE",padx=P)
        self._mode_w=SegmentedControl(b,[("single","Single Password"),("shamir","Split Between People")],
                         self._mode)
        self._mode_w.pack(fill="x",padx=P)
        self._mode_hint=tk.Label(b,text="",font=F["caption"],bg=C["bg"],fg=C["text3"],
                                  anchor="w",wraplength=500)
        self._mode_hint.pack(fill="x",padx=P,pady=(5,0))
        self._mode.trace_add("write",self._on_mode)

        # 3. Secret
        section_label(b,"3  PASSWORD",padx=P)
        self._sec_wrap=tk.Frame(b,bg=C["bg"]); self._sec_wrap.pack(fill="x",padx=P)
        self._pw_panel=tk.Frame(self._sec_wrap,bg=C["bg"])
        tk.Label(self._pw_panel,text="Password",font=F["caption"],bg=C["bg"],
                 fg=C["text3"]).pack(anchor="w",pady=(0,3))

        # Password row with per-field show/hide toggle
        pw1_row=tk.Frame(self._pw_panel,bg=C["bg"]); pw1_row.pack(fill="x",pady=(0,4))
        self._pw1=styled_entry(pw1_row,textvariable=self._pw1v,show="•")
        self._pw1.pack(side="left",fill="x",expand=True,ipady=8,ipadx=10)
        self._eye1_btn=FlatButton(pw1_row,"Show",lambda:self._toggle_pw(1),primary=False,small=True)
        self._eye1_btn.pack(side="left",padx=(4,0))
        self._pw1.bind("<Return>", lambda e: self._pw2.focus())

        self._strength=PasswordStrengthBar(self._pw_panel,self._pw1v)
        self._strength.pack(fill="x",pady=(0,10))
        tk.Label(self._pw_panel,text="Confirm password",font=F["caption"],
                 bg=C["bg"],fg=C["text3"]).pack(anchor="w",pady=(0,3))

        pw2_row=tk.Frame(self._pw_panel,bg=C["bg"]); pw2_row.pack(fill="x")
        self._pw2=styled_entry(pw2_row,textvariable=self._pw2v,show="•")
        self._pw2.pack(side="left",fill="x",expand=True,ipady=8,ipadx=10)
        self._eye2_btn=FlatButton(pw2_row,"Show",lambda:self._toggle_pw(2),primary=False,small=True)
        self._eye2_btn.pack(side="left",padx=(4,0))
        self._pw2.bind("<Return>", lambda e: self._start())

        self._match_lbl=tk.Label(self._pw_panel,text="",font=F["caption"],
                                  bg=C["bg"],fg=C["text3"])
        self._match_lbl.pack(anchor="w",pady=(3,0))
        self._pw1v.trace_add("write", self._check_match)
        self._pw2v.trace_add("write",self._check_match)

        self._sh_panel=tk.Frame(self._sec_wrap,bg=C["bg"])
        self._build_shamir(self._sh_panel)

        # 4. Output — wrapped in _out_section so batch mode can hide it
        self._out_section = tk.Frame(b, bg=C["bg"])
        self._out_section.pack(fill="x", padx=0)
        section_label(self._out_section,"4  OUTPUT FILE",padx=P)
        out_row=tk.Frame(self._out_section,bg=C["bg"]); out_row.pack(fill="x",padx=P)
        self._out=styled_entry(out_row)
        self._out.pack(side="left",fill="x",expand=True,ipady=8,ipadx=10)
        self._browse_btn = FlatButton(out_row,"…",self._browse_out,primary=False,small=True)
        self._browse_btn.pack(side="left",padx=(6,0))
        # Any manual edit marks the path as user-supplied (don't auto-replace)
        self._out.bind("<Key>", lambda e: setattr(self, "_out_auto", False))
        self._out_hint = tk.Label(self._out_section,
            text=".qcx is QuantaCrypt's encrypted format — safe to store or share",
            font=F["small"], bg=C["bg"], fg=C["text3"], anchor="w")
        self._out_hint.pack(fill="x", padx=P, pady=(4, 0))

        # 5. Embed decryptor — only shown when a binary is available or app is frozen
        if getattr(sys,"frozen",False) or self._find_dec():
            section_label(b,"5  PORTABLE FILE",padx=P)
            embed_row=tk.Frame(b,bg=C["bg"]); embed_row.pack(fill="x",padx=P)
            self._embed_chk=tk.Checkbutton(
                embed_row, variable=self._embed_dec,
                text="Embed decryptor so recipients can run the .qcx file directly",
                font=F["body"], bg=C["bg"], fg=C["text"],
                selectcolor=C["surface2"], activebackground=C["bg"],
                activeforeground=C["text"], relief="flat", bd=0,
                cursor="hand2", command=self._on_embed_toggle,
            )
            self._embed_chk.pack(anchor="w")
            self._embed_hint=tk.Label(embed_row,text="",
                font=F["caption"],bg=C["bg"],fg=C["text3"],anchor="w",justify="left")
            self._embed_hint.pack(fill="x",pady=(4,0))
            self._on_embed_toggle()
        else:
            # Running from source without a built binary — skip this section entirely
            self._embed_hint=tk.Label(b)  # dummy so _on_embed_toggle refs don't crash

        self._act_rule = rule(b,pady=18,padx=P)
        act=tk.Frame(b,bg=C["bg"]); act.pack(fill="x",padx=P,pady=(0,4))
        self._btn=FlatButton(act,"Encrypt File →",self._start)
        self._btn.pack(side="left")
        self._on_src_type()   # set initial button label
        # Error label on its own row so long messages wrap cleanly
        self._err=tk.Label(b,text="",font=F["caption"],bg=C["bg"],fg=C["error"],
                           anchor="w",justify="left",wraplength=490)
        self._err.pack(fill="x",padx=P,pady=(0,8))

        self._prog=StagedProgressBar(b,[(n,w) for n,w,_ in STAGES])
        self._results=tk.Frame(b,bg=C["bg"]); self._results.pack(fill="x",padx=P,pady=(0,12))
        # Keyboard shortcut hint
        tk.Label(b, text="Ctrl+O  Open file  ·  Ctrl+↵  Encrypt",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(0,16))
        self._on_mode()

    # Per-field show/hide toggle with text button
    def _toggle_pw(self, field=0):
        if field == 1:
            vis = self._pw1.cget("show") == "•"
            self._pw1.config(show="" if vis else "•")
            self._eye1_btn.config(text="Hide" if vis else "Show")
        elif field == 2:
            vis = self._pw2.cget("show") == "•"
            self._pw2.config(show="" if vis else "•")
            self._eye2_btn.config(text="Hide" if vis else "Show")

    def _on_embed_toggle(self, *_):
        dec = self._find_dec()
        if self._embed_dec.get():
            if dec:
                try:
                    dec_sz = fmt_size(os.path.getsize(dec))
                except OSError:
                    dec_sz = "some bytes"
                self._embed_hint.config(
                    text=f"The .qcx will be {dec_sz} larger. "
                         f"Recipients on macOS can run it directly — no separate app needed.",
                    fg=C["text3"])
            else:
                self._embed_dec.set(False)
                self._embed_hint.config(text="Decryptor binary not found. Build with: python3 build.py",
                                        fg=C["error"])
        else:
            # Always show hint so user understands the checkbox even without a file
            self._embed_hint.config(text="Recipients will need the quantacrypt app to open this file.",
                                    fg=C["text3"])

    def _build_shamir(self,parent):
        # Header row: hint + collapsible ? help button
        hdr=tk.Frame(parent,bg=C["bg"]); hdr.pack(fill="x",pady=(0,4))
        tk.Label(hdr,text="Choose how many people hold a share, and how many are needed to unlock.",
            font=F["caption"],bg=C["bg"],fg=C["text3"]).pack(side="left")
        self._shamir_help_visible=False
        help_btn=tk.Label(hdr,text=" ? ",font=F["caption"],bg=C["surface2"],
                          fg=C["accent"],cursor="hand2")
        help_btn.pack(side="left",padx=(8,0))
        help_btn.bind("<Button-1>",lambda e:self._toggle_shamir_help())

        # Help box — packed here so it sits between header and grid in document order.
        # Starts hidden; _toggle_shamir_help reveals/hides it.
        self._shamir_help=tk.Frame(parent,bg=C["surface"],
                                   highlightbackground=C["border"],highlightthickness=1)
        tk.Label(self._shamir_help,
            text="Imagine a vault that needs multiple keys to open:\n\n"
                 "• You give each person a unique share (like a unique key)\n"
                 "• No single person can open the file alone\n"
                 "• Only when enough people combine their shares can the file be unlocked\n\n"
                 "Example: Give 3 family members a share, require any 2 to unlock — "
                 "great for wills, team backups, or shared secrets.",
            font=F["caption"],bg=C["surface"],fg=C["text2"],
            justify="left",wraplength=480,anchor="w").pack(padx=12,pady=10,fill="x")
        # Don't pack yet — _toggle_shamir_help will do it when needed

        # Preset buttons for the three most common Shamir configurations
        preset_row = tk.Frame(parent, bg=C["bg"])
        preset_row.pack(fill="x", pady=(4,6))
        tk.Label(preset_row, text="Quick presets:", font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(0,8))
        for lbl,(pn,pk) in [("2-of-3",(3,2)),("3-of-5",(5,3)),("3-of-7",(7,3))]:
            FlatButton(preset_row, lbl,
                       lambda n=pn,k=pk: (self._n.set(n), self._k.set(k)),
                       primary=False, small=True).pack(side="left", padx=(0,6))
        tk.Label(preset_row, text="or set below", font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(8,0))

        self._shamir_grid=tk.Frame(parent,bg=C["bg"])  # stored ref avoids winfo_children()[-1] fragility
        self._shamir_grid.pack(fill="x",pady=(0,0))
        self._shamir_grid.columnconfigure(0,weight=1); self._shamir_grid.columnconfigure(1,weight=1)
        for col,(lbl,var,tip) in enumerate([
            ("Required to unlock",self._k,"Minimum people needed"),
            ("Total people",self._n,"How many shares to create"),
        ]):
            card=tk.Frame(self._shamir_grid,bg=C["surface"],highlightbackground=C["border"],highlightthickness=1)
            card.grid(row=0,column=col,padx=(0 if col==0 else 8,0),sticky="ew")
            tk.Label(card,text=lbl,font=F["caption"],bg=C["surface"],fg=C["text3"]).pack(anchor="w",padx=12,pady=(10,2))
            # Wrap Spinbox in a focus-ring Frame so keyboard users get a
            # visible accent outline matching the rest of the form's style.
            sp_wrap = tk.Frame(card, bg=C["surface"],
                               highlightbackground=C["border"], highlightthickness=1)
            sp_wrap.pack(anchor="w", padx=12, pady=(0,4))
            sp = tk.Spinbox(sp_wrap, from_=2, to=20, textvariable=var, width=3,
                font=F["heading"], bg=C["surface"], fg=C["text"],
                insertbackground=C["accent"], relief="flat", bd=0,
                highlightthickness=0, buttonbackground=C["surface2"])
            sp.pack(ipady=5)
            sp.bind("<FocusIn>",  lambda e, w=sp_wrap: w.config(highlightbackground=C["accent"], highlightthickness=2))
            sp.bind("<FocusOut>", lambda e, w=sp_wrap: w.config(highlightbackground=C["border"], highlightthickness=1))
            tk.Label(card,text=tip,font=F["caption"],bg=C["surface"],fg=C["text3"]).pack(anchor="w",padx=12,pady=(2,10))
        # Live summary label showing current threshold interpretation
        self._shamir_summary = tk.Label(parent,
            text=f"Any {self._k.get()} of {self._n.get()} people can unlock the file",
            font=F["caption"], bg=C["bg"], fg=C["accent"], anchor="w")
        self._shamir_summary.pack(fill="x", pady=(6,0))
        # Live K≤N clamping: whenever N or K changes, keep K ≤ N
        self._n.trace_add("write", self._clamp_k)
        self._k.trace_add("write", self._clamp_k)

    def _toggle_shamir_help(self):
        self._shamir_help_visible = not self._shamir_help_visible
        if self._shamir_help_visible:
            self._shamir_help.pack(fill="x", pady=(0,8), before=self._shamir_grid)
        else:
            self._shamir_help.pack_forget()

    def _clamp_k(self, *_):
        """Clamp N/K with a short debounce so that typing a two-digit
        number (e.g. "10") doesn't flash the minimum value after the first digit.
        The actual clamping is deferred by 400 ms and cancelled if another
        keystroke arrives first."""
        if hasattr(self, "_clamp_job") and self._clamp_job:
            try: self.after_cancel(self._clamp_job)
            except Exception: pass
        # Always update the summary label immediately so it tracks the current
        # raw value — but don't force-set the IntVar (which would overwrite typing).
        try:
            n, k = self._n.get(), self._k.get()
            if hasattr(self, "_shamir_summary"):
                # Show clamped values in the label without changing the spinbox
                nd = max(2, min(20, n))
                kd = max(2, min(nd, k))
                self._shamir_summary.config(
                    text=f"Any {kd} of {nd} people can unlock the file")
        except (tk.TclError, ValueError):
            pass
        self._clamp_job = self.after(400, self._do_clamp)

    def _do_clamp(self):
        """Deferred actual clamping — runs 400 ms after the last keystroke."""
        self._clamp_job = None
        try:
            n, k = self._n.get(), self._k.get()
            if n < 2: n = 2; self._n.set(n)
            if n > 20: n = 20; self._n.set(n)
            if k < 2: k = 2; self._k.set(k)
            if k > n: k = n; self._k.set(k)
            if hasattr(self, "_shamir_summary"):
                self._shamir_summary.config(
                    text=f"Any {k} of {n} people can unlock the file")
        except (tk.TclError, ValueError):
            pass

    def _on_mode(self,*_):
        if self._mode.get()=="single":
            # Show pw panel and re-enable its fields for Tab navigation
            self._pw_panel.pack(fill="x")
            self._pw1.config(state="normal"); self._pw2.config(state="normal")
            self._sh_panel.pack_forget()
            self._mode_hint.config(text="Choose a strong password. It's the only way to unlock the file — we never store it.")
        else:
            # Hide pw panel and disable its fields to remove them from Tab order
            self._pw_panel.pack_forget()
            self._pw1.config(state="disabled"); self._pw2.config(state="disabled")
            self._sh_panel.pack(fill="x")
            self._mode_hint.config(text="Give each person a unique share. The file can only be unlocked when enough people combine their shares.")
            # Re-show help panel if it was open before mode was switched away
            if self._shamir_help_visible:
                self._shamir_help.pack(fill="x", pady=(0,8), before=self._shamir_grid)

    def _check_match(self, *_):
        """Live password match indicator. Suppressed until pw1 has content."""
        p1, p2 = self._pw1v.get(), self._pw2v.get()
        if not p1 or not p2:
            self._match_lbl.config(text="")
        elif p1 == p2:
            self._match_lbl.config(text="✓  Passwords match", fg=C["success"])
        else:
            self._match_lbl.config(text="✗  Don't match", fg=C["error"])

    def _freeze(self):
        """Disable all interactive controls while encryption runs."""
        self._btn.enable(False)
        try: self._browse_btn.enable(False)  # Prevent browse during encrypt
        except Exception: pass
        for w in [self._pw1, self._pw2, self._out]:
            try: w.config(state="disabled")
            except Exception: pass
        # Disable FileCard so changing the file mid-encryption is blocked
        try:
            self._file_card.config(cursor="")
            for w in [self._file_card, self._file_card._icon,
                      self._file_card._line1, self._file_card._line2]:
                w.unbind("<Button-1>")
            # Suppress hover highlight during encryption
            self._file_card.unbind("<Enter>")
            self._file_card.unbind("<Leave>")
        except Exception: pass
        # Dim the mode control and embed checkbox
        try:
            for lbl in self._mode_w._labels.values():
                lbl.config(cursor="", fg=C["text3"])
            self._mode_w.unbind("<Left>"); self._mode_w.unbind("<Right>")
            self._mode_w.config(takefocus=0)  # Skip frozen control on Tab
        except Exception: pass
        try:
            for lbl in self._src_toggle._labels.values():
                lbl.config(cursor="", fg=C["text3"])
            self._src_toggle.unbind("<Left>"); self._src_toggle.unbind("<Right>")
            self._src_toggle.config(takefocus=0)
        except Exception: pass
        try: self._embed_chk.config(state="disabled")
        except Exception: pass

    def _thaw(self):
        """Re-enable all interactive controls after encryption completes or fails."""
        self._btn.enable(True)
        try: self._browse_btn.enable(True)  # Restore browse button
        except Exception: pass
        # Only re-enable pw fields in single mode — Shamir mode keeps them disabled
        if self._mode.get() == "single":
            for w in [self._pw1, self._pw2]:
                try: w.config(state="normal")
                except Exception: pass
        try: self._out.config(state="normal")
        except Exception: pass
        # Re-enable FileCard
        try:
            self._file_card.config(cursor="hand2")
            for w in [self._file_card, self._file_card._icon,
                      self._file_card._line1, self._file_card._line2]:
                w.bind("<Button-1>", lambda e: self._file_card._pick())
            # Restore hover bindings after encryption
            self._file_card.bind("<Enter>", lambda e: self._file_card._hl(True))
            self._file_card.bind("<Leave>", lambda e: self._file_card._hl(False))
        except Exception: pass
        try:
            self._mode_w._refresh()  # restores proper fg colours
            for val, lbl in self._mode_w._labels.items():
                lbl.config(cursor="hand2")
            self._mode_w.bind("<Left>",  lambda e: self._mode_w._step(-1))
            self._mode_w.bind("<Right>", lambda e: self._mode_w._step(1))
            self._mode_w.config(takefocus=1)  # Restore Tab focus
        except Exception: pass
        try:
            self._src_toggle._refresh()
            for val, lbl in self._src_toggle._labels.items():
                lbl.config(cursor="hand2")
            self._src_toggle.bind("<Left>",  lambda e: self._src_toggle._step(-1))
            self._src_toggle.bind("<Right>", lambda e: self._src_toggle._step(1))
            self._src_toggle.config(takefocus=1)
        except Exception: pass
        try: self._embed_chk.config(state="normal")
        except Exception: pass
        # Only restore match label in single mode — Shamir has no password fields
        if self._mode.get() == "single":
            self._check_match()

    def _on_src_type(self, *_):
        """Show the correct picker widget for the current source type (file/folder/batch)."""
        mode = self._src_type.get()
        if mode == "batch":
            self._file_card.pack_forget()
            self._batch_frame.pack(fill="x", padx=self._P, after=self._src_toggle)
            if not self._batch_paths:
                self._build_batch_ui()
            # Clear any single-file/folder selection
            self._path = None; self._is_folder = False
        else:
            self._batch_frame.pack_forget()
            self._file_card.pack(fill="x", padx=self._P, after=self._src_toggle)
            if mode == "folder":
                self._file_card._is_folder_mode = True
                if not self._is_folder:
                    self._file_card.reset("Select a folder to encrypt",
                                          "Click anywhere · or drag & drop a folder")
                    self._path = None; self._is_folder = False
            else:  # file
                self._file_card._is_folder_mode = False
                if self._is_folder:
                    self._file_card.reset("Select a file to encrypt",
                                          "Click anywhere · or drag & drop")
                    self._path = None; self._is_folder = False
        # Update button label and section-4 visibility to match source mode
        try:
            if mode == "batch":
                n = len(self._batch_paths)
                label = f"Encrypt {n} Files →" if n else "Encrypt Files →"
                # Hide section 4 — batch has its own output folder row
                if hasattr(self, "_out_section"):
                    self._out_section.pack_forget()
            elif mode == "folder":
                label = "Encrypt Folder →"
                if hasattr(self, "_out_section") and not self._out_section.winfo_ismapped():
                    self._out_section.pack(fill="x", padx=0,
                                           before=self._act_rule)
            else:
                label = "Encrypt File →"
                if hasattr(self, "_out_section") and not self._out_section.winfo_ismapped():
                    self._out_section.pack(fill="x", padx=0,
                                           before=self._act_rule)
            self._btn.config(text=label)
        except Exception:
            pass

    def _build_batch_ui(self):
        """Render the batch-mode file list inside _batch_frame."""
        for w in self._batch_frame.winfo_children(): w.destroy()
        if not self._batch_paths:
            btn_row = tk.Frame(self._batch_frame, bg=C["bg"]); btn_row.pack(fill="x")
            FlatButton(btn_row, "Select files →", self._on_batch_select,
                       primary=False, small=False).pack(side="left")
            tk.Label(btn_row, text="Select multiple files to encrypt with the same settings.",
                     font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(10,0))
            return
        # Show file list
        hdr = tk.Frame(self._batch_frame, bg=C["bg"]); hdr.pack(fill="x", pady=(0,6))
        tk.Label(hdr, text=f"{len(self._batch_paths)} files selected",
                 font=F["body_b"], bg=C["bg"], fg=C["text"]).pack(side="left")
        FlatButton(hdr, "Change", self._on_batch_select,
                   primary=False, small=True).pack(side="right")
        total = sum(os.path.getsize(p) for p in self._batch_paths if os.path.isfile(p))
        tk.Label(hdr, text=fmt_size(total), font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="right", padx=(0,8))
        # File list capped at 5 visible rows
        list_frame = tk.Frame(self._batch_frame, bg=C["surface"],
                              highlightbackground=C["border"], highlightthickness=1)
        list_frame.pack(fill="x")
        visible = min(len(self._batch_paths), 5)
        for p in self._batch_paths[:visible]:
            row = tk.Frame(list_frame, bg=C["surface"]); row.pack(fill="x", padx=10, pady=3)
            tk.Label(row, text=os.path.basename(p), font=F["caption"],
                     bg=C["surface"], fg=C["text"]).pack(side="left")
            try: sz = fmt_size(os.path.getsize(p))
            except OSError: sz = "?"
            tk.Label(row, text=sz, font=F["small"], bg=C["surface"],
                     fg=C["text3"]).pack(side="right")
        if len(self._batch_paths) > visible:
            tk.Label(list_frame,
                     text=f"  … and {len(self._batch_paths)-visible} more files",
                     font=F["small"], bg=C["surface"], fg=C["text3"],
                     anchor="w").pack(fill="x", padx=10, pady=(0,4))
        # Output directory row
        out_row = tk.Frame(self._batch_frame, bg=C["bg"]); out_row.pack(fill="x", pady=(8,0))
        tk.Label(out_row, text="Output folder:", font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left")
        if not hasattr(self, "_batch_out_var"):
            self._batch_out_var = tk.StringVar()
        if not self._batch_out_var.get():
            self._batch_out_var.set(os.path.dirname(os.path.abspath(self._batch_paths[0])))
        e = styled_entry(out_row, textvariable=self._batch_out_var)
        e.pack(side="left", fill="x", expand=True, ipady=7, ipadx=8, padx=(6,0))
        FlatButton(out_row, "…", self._browse_batch_out, primary=False, small=True).pack(side="left", padx=(4,0))
        tk.Label(self._batch_frame,
                 text="Each file will be saved as <filename>.qcx in the output folder.",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(4,0))
        self._wiz.set_step(1)

    def _on_batch_select(self):
        # Warn before discarding an existing non-trivial selection
        if len(self._batch_paths) > 1:
            if not messagebox.askyesno(
                    "Replace selection?",
                    f"You have {len(self._batch_paths)} files selected.\n\n"
                    "Replace them with a new selection?",
                    icon="question", default="yes"):
                return
        paths = filedialog.askopenfilenames(
            title="Select files to encrypt",
            filetypes=[("All files", "*")],
            initialdir=os.path.expanduser("~"))
        if paths:
            self._batch_paths = list(paths)
            if hasattr(self, "_batch_out_var"):
                self._batch_out_var.set(os.path.dirname(os.path.abspath(paths[0])))
            self._build_batch_ui()
            self._wiz.set_step(1)
            # Update button label with file count
            try:
                self._btn.config(text=f"Encrypt {len(self._batch_paths)} Files →")
            except Exception:
                pass

    def _browse_batch_out(self):
        d = filedialog.askdirectory(title="Output folder for encrypted files")
        if d and hasattr(self, "_batch_out_var"):
            self._batch_out_var.set(d)

    def _validate_batch(self):
        if not self._batch_paths: return "Select at least one file"
        missing = [p for p in self._batch_paths if not os.path.isfile(p)]
        if missing: return f"{len(missing)} file(s) no longer exist — re-select"
        out_dir = getattr(self, "_batch_out_var", None) and self._batch_out_var.get().strip()
        if not out_dir: return "Specify an output folder"
        if not os.path.isdir(out_dir): return f"Output folder does not exist: {out_dir}"
        if not os.access(out_dir, os.W_OK): return f"Output folder is not writable: {out_dir}"
        if self._mode.get() == "single":
            if not self._pw1v.get(): return "Password cannot be empty"
            if self._pw1v.get() != self._pw2v.get(): return "Passwords don't match"
        else:
            if self._n.get() < 2: return "Total shares must be at least 2"
            if self._k.get() > self._n.get(): return "Threshold can't exceed total shares"
            if self._k.get() < 2: return "Threshold must be at least 2"
        return None

    def _on_folder(self, path):
        """Called when a directory is selected (parallel to _on_file)."""
        self._path = path; self._is_folder = True
        count, total = _folder_stats(path)
        if self._out_auto or not self._out.get().strip():
            base = os.path.join(os.path.dirname(os.path.abspath(path)),
                                os.path.basename(path))
            self._out.delete(0,"end"); self._out.insert(0, base + ".qcx")
            self._out_auto = True
        self._file_card._selected = True
        self._file_card._icon.config(text="📁", fg=C["success"])
        self._file_card._line1.config(text=os.path.basename(path), fg=C["text"], font=F["body_b"])
        self._file_card._line2.config(
            text=f"{count} file{'s' if count!=1 else ''}  ·  {fmt_size(total)}  ·  Click to change",
            fg=C["accent"])
        for w in [self._file_card, self._file_card._icon,
                  self._file_card._line1, self._file_card._line2]:
            w.config(bg=C["surface"])
        self._err.config(text=""); self._wiz.set_step(1)
        self._on_embed_toggle()
        self.title(f"{os.path.basename(path)}/ — QuantaCrypt · Encrypt")
        self.after(80, lambda: self._cv.yview_moveto(0.55))

    def _on_file(self,path):
        self._path=path; self._is_folder=False
        # Refresh output path when auto-generated or empty; preserve manual edits
        if self._out_auto or not self._out.get().strip():
            base = os.path.splitext(path)[0]  # Strip source extension
            self._out.delete(0,"end"); self._out.insert(0, base + ".qcx")
            self._out_auto = True  # still auto-generated
            self._out_hint.config(text="Auto-generated — click … to choose a different location")
        self._err.config(text=""); self._wiz.set_step(1)
        self._on_embed_toggle()
        self.title(f"{os.path.basename(path)} — QuantaCrypt · Encrypt")
        self.after(80, lambda: self._cv.yview_moveto(0.55))  # Nudge to reveal lower form

    def _browse_out(self):
        # Pre-seed directory from current output field
        cur=self._out.get().strip()
        init_dir=os.path.dirname(os.path.abspath(cur)) if cur else ""
        p=filedialog.asksaveasfilename(initialdir=init_dir,defaultextension=".qcx",
            filetypes=[("QuantaCrypt","*.qcx"),("All files","*")])
        if p:
            self._out.delete(0,"end"); self._out.insert(0,p)
            self._out_auto = False  # Browsed path is user-supplied
            self._out_hint.config(text=".qcx is QuantaCrypt's encrypted format — safe to store or share")

    def _validate(self):
        if self._src_type.get() == "batch": return self._validate_batch()
        if not self._path: return "Select a file or folder first"
        if self._is_folder:
            if not os.path.isdir(self._path): return "Folder no longer exists — please re-select"
        else:
            if not os.path.isfile(self._path): return "Select a file first"
        out=self._out.get().strip()
        if not out: return "Specify an output path"
        try:
            if not self._is_folder and os.path.exists(out) and os.path.samefile(self._path,out):
                return "Output path is the same as the input — choose a different location"
        except OSError: pass
        # Validate output directory exists and is writable
        out_dir = os.path.dirname(os.path.abspath(out)) or "."
        if not os.path.isdir(out_dir):
            return f"Output directory does not exist: {out_dir}"
        if not os.access(out_dir, os.W_OK):
            return f"Output directory is not writable: {out_dir}"
        if self._mode.get()=="single":
            if not self._pw1v.get(): return "Password cannot be empty"
            if self._pw1v.get()!=self._pw2v.get(): return "Passwords don't match"
        else:
            if self._n.get()<2: return "Total shares must be at least 2"
            if self._k.get()>self._n.get(): return "Threshold can't exceed total shares"
            if self._k.get()<2: return "Threshold must be at least 2"
        return None

    def _start(self):
        if self._busy: return
        # Batch mode: encrypt each file individually with the same settings
        if self._src_type.get() == "batch":
            self._start_batch(); return
        err=self._validate()
        if err:
            self._err.config(text=err)
            self.after(50, lambda: self._cv.yview_moveto(1.0))  # Scroll after layout reflow
            return
        out=self._out.get().strip()
        # Warn if password is rated Weak (zxcvbn score 0 or 1)
        if self._mode.get() == "single":
            pw = self._pw1v.get()
            try:
                from zxcvbn import zxcvbn as _zx
                score = _zx(pw)["score"]
            except ImportError:
                score = 4  # zxcvbn not available — skip check
            if score < 2:
                if not messagebox.askyesno(
                        "Weak password",
                        "Your password is rated Weak.\n\n"
                        "A weak password could be guessed relatively easily. "
                        "Consider using a longer password with a mix of words, numbers, and symbols.\n\n"
                        "Continue with this password anyway?",
                        icon="warning", default="no"):
                    return
        # K=N means every shareholder must participate — unusual and worth confirming.
        if self._mode.get() == "shamir":
            k, n = self._k.get(), self._n.get()
            if k == n:
                if not messagebox.askyesno(
                        "All people required",
                        f"You've set \"required to unlock\" and \"total people\" both to {n}.\n\n"
                        f"This means every single person must participate — "
                        f"if even one person loses their share, the file can never be unlocked.\n\n"
                        f"If you want some safety margin, set \"required to unlock\" lower than \"total people\".\n\n"
                        f"Continue with {k}-of-{n}?",
                        icon="warning", default="no"):
                    return
        if os.path.exists(out):
            if not messagebox.askyesno("Overwrite?",
                    f"{os.path.basename(out)} already exists. Overwrite it?",icon="warning"):
                return
        self._err.config(text=""); self._busy=True
        self._prog.pack(fill="x",padx=self._P,pady=(0,4),before=self._results)
        self._prog.start(); self._freeze(); self._wiz.set_step(4)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        for w in self._results.winfo_children(): w.destroy()
        # Capture all Tk widget state on the main thread before spawning worker
        params = {
            "path":      self._path,
            "out":       out,
            "mode":      self._mode.get(),
            "pw":        self._pw1v.get(),
            "n":         self._n.get(),
            "k":         self._k.get(),
            "embed":     self._embed_dec.get(),
            "is_folder": self._is_folder,
        }
        threading.Thread(target=self._run, args=(params,), daemon=True).start()

    def _start_batch(self):
        """Encrypt all selected files in sequence with the same settings.
        Each file becomes its own .qcx in the output folder."""
        err = self._validate_batch()
        if err:
            self._err.config(text=err)
            self.after(50, lambda: self._cv.yview_moveto(1.0))
            return
        out_dir = self._batch_out_var.get().strip()
        # Warn about overwrite for any files that would be clobbered
        would_overwrite = []
        for p in self._batch_paths:
            dest = os.path.join(out_dir, os.path.splitext(os.path.basename(p))[0] + ".qcx")
            if os.path.exists(dest):
                would_overwrite.append(os.path.basename(dest))
        if would_overwrite:
            names = ", ".join(would_overwrite[:3])
            if len(would_overwrite) > 3: names += f" … (+{len(would_overwrite)-3} more)"
            if not messagebox.askyesno("Overwrite?",
                    f"These files already exist and will be overwritten:\n{names}\n\nContinue?",
                    icon="warning"):
                return
        self._err.config(text=""); self._busy = True
        self._prog.pack(fill="x", padx=self._P, pady=(0,4), before=self._results)
        self._prog.start(); self._freeze(); self._wiz.set_step(4)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        for w in self._results.winfo_children(): w.destroy()
        batch_params = {
            "paths":   list(self._batch_paths),
            "out_dir": out_dir,
            "mode":    self._mode.get(),
            "pw":      self._pw1v.get(),
            "n":       self._n.get(),
            "k":       self._k.get(),
            "embed":   self._embed_dec.get(),
        }
        threading.Thread(target=self._run_batch, args=(batch_params,), daemon=True).start()

    def _run_batch(self, bp):
        """Worker: encrypt each file in bp["paths"] one by one."""
        out_dir = bp["out_dir"]
        succeeded, failed = [], []
        total = len(bp["paths"])
        for i, path in enumerate(bp["paths"], 1):
            orig = os.path.basename(path)
            stem = os.path.splitext(orig)[0]
            out  = os.path.join(out_dir, stem + ".qcx")
            tmp  = out + ".tmp"
            self.after(0, self._prog.advance, STAGE_COMPRESS,
                       f"Encrypting file {i} of {total}: {orig}")
            try:
                dec = self._find_dec() if bp["embed"] else None
                with open(tmp, "wb") as f:
                    if dec:
                        with open(dec, "rb") as df:
                            while True:
                                c = df.read(1 << 20)
                                if not c: break
                                f.write(c)
                    payload_offset = f.tell()
                    if bp["mode"] == "single":
                        meta = cc.encrypt_single_streaming(
                            path, f, bp["pw"], filename=orig,
                            progress_cb=self._prog_cb)
                        shares = []
                    else:
                        meta, shares = cc.encrypt_shamir_streaming(
                            path, f, bp["n"], bp["k"], filename=orig,
                            progress_cb=self._prog_cb)
                    meta["payload_offset"] = payload_offset
                    self.after(0, self._prog.advance, STAGE_WRITE, "Writing binary...")
                    blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
                    f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
                os.replace(tmp, out)
                try:
                    m = os.stat(out).st_mode
                    os.chmod(out, m | stat.S_IXUSR | stat.S_IXGRP)
                except OSError: pass
                succeeded.append((out, shares))
            except Exception as ex:
                try: os.remove(tmp)
                except OSError: pass
                failed.append((orig, str(ex)))
        self.after(0, self._done_batch, succeeded, failed, bp)

    def _done_batch(self, succeeded, failed, bp):
        """Show batch completion summary."""
        self._busy = False; self._prog.complete(); self._thaw()
        self._wiz.set_step(len(self.STEPS))
        self._err.config(text="")
        self._pw1v.set(""); self._pw2v.set("")
        if failed:
            notify("Batch encryption finished",
                   f"{len(succeeded)} succeeded, {len(failed)} failed")
        else:
            notify("Batch encryption complete",
                   f"{len(succeeded)} file{'s' if len(succeeded)!=1 else ''} encrypted")
        ok = tk.Frame(self._results, bg=C["surface"],
                      highlightbackground=C["success"] if not failed else C["warning"],
                      highlightthickness=1)
        ok.pack(fill="x", pady=(14,0))
        ok_in = tk.Frame(ok, bg=C["surface"]); ok_in.pack(fill="x", padx=14, pady=12)
        n_ok, n_fail = len(succeeded), len(failed)
        summary = f"✓  {n_ok} file{'s' if n_ok!=1 else ''} encrypted"
        if n_fail:
            summary += f"  ·  {n_fail} failed"
        tk.Label(ok_in, text=summary, font=F["body_b"], bg=C["surface"],
                 fg=C["success"] if not n_fail else C["warning"]).pack(side="left")
        tk.Label(ok_in, text=bp["out_dir"], font=F["caption"],
                 bg=C["surface"], fg=C["text3"], wraplength=380).pack(anchor="w", padx=14, pady=(0,4))
        for out_path, shares in succeeded[:5]:
            row = tk.Frame(ok, bg=C["surface"]); row.pack(fill="x", padx=14, pady=1)
            tk.Label(row, text=f"  ✓  {os.path.basename(out_path)}", font=F["caption"],
                     bg=C["surface"], fg=C["success"]).pack(side="left")
            try: sz = fmt_size(os.path.getsize(out_path))
            except OSError: sz = ""
            if sz: tk.Label(row, text=sz, font=F["small"], bg=C["surface"],
                            fg=C["text3"]).pack(side="right")
        if len(succeeded) > 5:
            tk.Label(ok, text=f"  … and {len(succeeded)-5} more",
                     font=F["small"], bg=C["surface"], fg=C["text3"],
                     anchor="w").pack(fill="x", padx=14, pady=(0,2))
        for orig, err_msg in failed:
            tk.Label(ok, text=f"  ✗  {orig}: {err_msg}", font=F["caption"],
                     bg=C["surface"], fg=C["error"], anchor="w",
                     wraplength=490).pack(fill="x", padx=14, pady=1)
        # Shamir shares: render a share section per file that had shares generated
        files_with_shares = [(out_path, shares) for out_path, shares in succeeded if shares]
        if files_with_shares:
            from quantacrypt.core import crypto as _cc
            warn = tk.Frame(self._results, bg=C["surface"],
                            highlightbackground=C["warning"], highlightthickness=1)
            warn.pack(fill="x", pady=(8,0))
            w_hdr = tk.Frame(warn, bg=C["surface"]); w_hdr.pack(fill="x", padx=14, pady=(10,4))
            k = self._k.get()
            tk.Label(w_hdr,
                     text=f"Save key shares — {len(files_with_shares)} file{'s' if len(files_with_shares)!=1 else ''} need share distribution",
                     font=F["body_b"], bg=C["surface"], fg=C["warning"]).pack(anchor="w")
            tk.Label(warn,
                     text="Each file has its own set of shares. Save individual share files "
                          "for each encrypted file before closing.",
                     font=F["caption"], bg=C["surface"], fg=C["text3"],
                     wraplength=490, anchor="w").pack(fill="x", padx=14, pady=(0,8))
            for out_path, shares in files_with_shares:
                # Per-file collapsible section
                sec = tk.Frame(self._results, bg=C["surface"],
                               highlightbackground=C["border"], highlightthickness=1)
                sec.pack(fill="x", pady=(0,6))
                sec_hdr = tk.Frame(sec, bg=C["surface"]); sec_hdr.pack(fill="x", padx=14, pady=(8,4))
                tk.Label(sec_hdr, text=os.path.basename(out_path),
                         font=F["body_b"], bg=C["surface"], fg=C["text"]).pack(side="left")
                FlatButton(sec_hdr, "Save individual files →",
                           lambda _p=out_path, _s=shares, _sec=sec: self._save_individual_shares(
                               _s, os.path.splitext(os.path.basename(_p))[0], qcx_path=_p, banner_frame=_sec),
                           primary=True, small=False).pack(side="right")
                # Share cards (collapsed — just the save button is enough for batch)
                mnemonics = []
                for s in shares:
                    try:
                        mnemonics.append(_cc.share_to_mnemonic({**_cc.decode_share(s), "threshold": k}))
                    except Exception:
                        mnemonics.append(None)
                for i, sh in enumerate(shares, 1):
                    mn = mnemonics[i-1] if i-1 < len(mnemonics) else None
                    ShareCard(sec, i, sh, mnemonic=mn).pack(fill="x", padx=8, pady=(0,6))
            self._shares_pending = True
        btn_row = tk.Frame(ok, bg=C["surface"]); btn_row.pack(fill="x", padx=14, pady=(6,12))
        FlatButton(btn_row, "Encrypt another batch →", self._reset,
                   primary=False, small=True).pack(side="left")
        FlatButton(btn_row, "Open folder",
                   lambda: _reveal(succeeded[0][0]) if succeeded else None,
                   primary=False, small=True).pack(side="left", padx=(8,0))
        self.after(50, lambda: self._cv.yview_moveto(1.0))

    def _prog_cb(self,msg):
        idx,_=_find_stage(msg)
        if idx is not None: self.after(0,self._prog.advance,idx,msg)

    def _run(self, p):
        """Worker thread — streaming: O(64 KB) RAM regardless of file size.
        For folder inputs, zips the folder to a temp file first, then encrypts
        the zip.  The temp zip is always deleted before returning."""
        out = p["out"]; tmp = out + ".tmp"
        zip_tmp = None   # path to temporary zip (folder mode only)
        try:
            dec = self._find_dec() if p["embed"] else None

            # ── Folder: compress to a temporary zip first ─────────────────────
            if p["is_folder"]:
                folder_name = os.path.basename(os.path.abspath(p["path"]))
                orig        = folder_name + ".zip"
                self.after(0, self._prog.advance, STAGE_COMPRESS,
                           f"Compressing {folder_name}/…")
                fd, zip_tmp = tempfile.mkstemp(suffix=".zip")
                os.close(fd)
                _zip_folder(p["path"], zip_tmp,
                            progress_cb=lambda msg: self.after(
                                0, self._prog.advance, STAGE_COMPRESS, msg))
                src_path = zip_tmp
            else:
                orig     = os.path.basename(p["path"])
                src_path = p["path"]

            with open(tmp, "wb") as f:
                # Write embedded decryptor binary first (if requested)
                if dec:
                    with open(dec, "rb") as df:
                        while True:
                            chunk = df.read(1 << 20)
                            if not chunk: break
                            f.write(chunk)

                # Record where the chunk payload starts (for decryptor seeking)
                payload_offset = f.tell()

                # Stream-encrypt the source (file or zip) into the output file
                if p["mode"] == "single":
                    meta = cc.encrypt_single_streaming(
                        src_path, f, p["pw"], filename=orig, progress_cb=self._prog_cb)
                    shares = []
                else:
                    meta, shares = cc.encrypt_shamir_streaming(
                        src_path, f, p["n"], p["k"], filename=orig,
                        progress_cb=self._prog_cb)

                # Store payload_offset so decryptor can seek directly to chunks
                meta["payload_offset"] = payload_offset

                self.after(0, self._prog.advance, STAGE_WRITE, "Writing encrypted binary...")
                # Write metadata tail: MAGIC + uint32 length + JSON
                pkg  = {"meta": meta}
                blob = json.dumps(pkg, separators=(",", ":")).encode()
                f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

            os.replace(tmp, out)   # atomic replace
            try:
                m = os.stat(out).st_mode; os.chmod(out, m | stat.S_IXUSR | stat.S_IXGRP)
            except OSError: pass
            try:
                dec_size = os.path.getsize(dec) if dec else 0
            except OSError:
                dec_size = 0
            self.after(0, self._done, out, shares, bool(dec), dec_size)
        except Exception as ex:
            try: os.remove(tmp)
            except OSError: pass
            self.after(0, self._fail, str(ex))
        finally:
            # Always remove the temporary zip regardless of success or failure
            if zip_tmp:
                try: os.remove(zip_tmp)
                except OSError: pass
            # Clear password from worker params to reduce memory exposure
            p["pw"] = None

    def _find_dec(self):
        if getattr(sys,"frozen",False): return sys.executable
        d=os.path.dirname(os.path.abspath(__file__))
        for name in [".quantacrypt-decryptor","quantacrypt-decryptor","quantacrypt"]:
            for base in [d,os.path.join(d,"dist")]:
                p=os.path.join(base,name)
                if os.path.isfile(p): return p
        return None

    def _done(self,out,shares,embedded=True,dec_size=0):
        self._busy=False; self._prog.complete(); self._thaw()
        # set_step past the last step index → all circles show ✓ (complete state)
        self._wiz.set_step(len(self.STEPS))
        self._err.config(text="")                # Clear any stale busy/error message
        self._pw1v.set(""); self._pw2v.set("")  # Clear passwords after success
        self._match_lbl.config(text="")          # clear "✓ Passwords match" residue
        notify("Encryption complete", os.path.basename(out))

        ok=tk.Frame(self._results,bg=C["surface"],highlightbackground=C["success"],highlightthickness=1)
        ok.pack(fill="x",pady=(14,12 if shares else 0))
        ok_in=tk.Frame(ok,bg=C["surface"]); ok_in.pack(fill="x",padx=14,pady=12)
        try:
            out_size = os.path.getsize(out)
        except OSError:
            out_size = 0
        if embedded:
            # Use dec_size passed from _run (computed at write time)
            payload_size = out_size - dec_size
            size_label = (f"{fmt_size(out_size)}  ({fmt_size(dec_size)} decryptor + "
                          f"{fmt_size(max(0, payload_size))} data)")
        else:
            size_label = fmt_size(out_size)
        tk.Label(ok_in,text="✓  Encrypted successfully",font=F["body_b"],bg=C["surface"],fg=C["success"]).pack(side="left")
        tk.Label(ok_in,text=size_label,font=F["caption"],bg=C["surface"],fg=C["text3"]).pack(side="right")
        tk.Label(ok,text=os.path.basename(out),font=F["mono"],bg=C["surface"],fg=C["text2"]).pack(anchor="w",padx=14,pady=(0,2))
        # Confirm which source was encrypted
        if self._path:
            src_label = (os.path.basename(self._path) + "/"
                         if self._is_folder else os.path.basename(self._path))
            tk.Label(ok,text=f"from  {src_label}",font=F["caption"],
                     bg=C["surface"],fg=C["text3"]).pack(anchor="w",padx=14,pady=(0,4))
        if embedded:
            embed_lines = [
                "Includes the decryptor — recipients can run this file directly on the same OS,",
                "or open it via quantacrypt on any platform.",
                # Recipients need execute permission
                f"Recipients may need to run  chmod +x {os.path.basename(out)}  before executing.",
                # OS security warnings
                "If macOS blocks it, right-click → Open to bypass the security warning.",
            ]
            tk.Label(ok, text="\n".join(embed_lines),
                font=F["caption"], bg=C["surface"], fg=C["text3"],
                justify="left").pack(anchor="w", padx=14, pady=(0,8))
        else:
            # Informational note, not a warning — use text3 (gray) not warning (yellow)
            tk.Label(ok,text="Recipients will need the quantacrypt app to open this file.",
                font=F["caption"],bg=C["surface"],fg=C["text3"],justify="left").pack(anchor="w",padx=14,pady=(0,8))
        btn_row=tk.Frame(ok,bg=C["surface"]); btn_row.pack(fill="x",padx=14,pady=(0,12))
        FlatButton(btn_row,"Encrypt another →",self._reset,primary=False,small=True).pack(side="left")
        FlatButton(btn_row,"Show in folder",lambda:_reveal(out),primary=False,small=True).pack(side="left",padx=(8,0))
        # Open the output file directly (mirrors open-file on decrypt success)
        FlatButton(btn_row,"Open file",lambda:_reveal(out,open_file=True),primary=False,small=True).pack(side="left",padx=(8,0))
        if not shares:
            self.after(50, lambda: self._cv.yview_moveto(1.0))
            return
        self._shares_pending = True   # guard: warn if user navigates away
        self._pending_shares = shares  # keep ref for save dialog
        k=self._k.get(); n=self._n.get()
        self._shares_warn=tk.Frame(self._results,bg=C["surface"],highlightbackground=C["warning"],highlightthickness=1)
        warn = self._shares_warn
        warn.pack(fill="x",pady=(0,10))
        # Summary text on its own row
        tk.Label(warn, text=f"Send each person their share. Any {k} of {n} can unlock the file.",
                 font=F["body_b"], bg=C["surface"], fg=C["warning"],
                 anchor="w").pack(fill="x", padx=14, pady=(10,6))
        # Buttons on a separate row so they don't overlap the text
        btn_grp = tk.Frame(warn, bg=C["surface"]); btn_grp.pack(fill="x", padx=14, pady=(0,6))
        # Primary: save one file per person (new feature)
        FlatButton(btn_grp, "Save individual files →",
                   lambda: self._save_individual_shares(shares, os.path.basename(self._path or ""),
                                                        banner_frame=self._shares_warn),
                   primary=True, small=False).pack(side="left")
        # Secondary: save all shares in one combined file (original behaviour)
        FlatButton(btn_grp, "Save combined file",
                   lambda: self._save_shares(shares, os.path.basename(self._path or "")),
                   primary=False, small=False).pack(side="left", padx=(6,0))
        # Copy all shares to clipboard in one click
        self._copy_all_btn = FlatButton(btn_grp, "Copy all",
                   lambda: self._copy_all_shares(shares), primary=False, small=True)
        self._copy_all_btn.pack(side="left", padx=(6,0))
        # Clipboard timer label on its own row to avoid collision with share-count label
        timer_row = tk.Frame(warn, bg=C["surface"]); timer_row.pack(fill="x", padx=14, pady=(0,4))
        self._copy_all_clip_lbl = tk.Label(timer_row, text="", font=F["small"],
                                            bg=C["surface"], fg=C["text3"])
        self._copy_all_clip_lbl.pack(side="left")
        self._copy_all_timer = ClipboardTimer(self, self._copy_all_clip_lbl)
        tk.Label(warn,text="Keep a backup of these shares somewhere safe. We recommend testing that you can unlock the file before sending shares to others.",
                 font=F["caption"],bg=C["surface"],fg=C["text3"],wraplength=500
                 ).pack(anchor="w",padx=14,pady=(0,10))
        try:
            # Inject threshold so the mnemonic's embedded threshold byte is correct.
            # decode_share returns {index, value, modulus} — no threshold field.
            # Without this injection, every mnemonic encodes threshold=0 and the
            # self-check in decryptor._collect_shares is always bypassed.
            mnemonics = []
            for s in shares:
                mnemonics.append(cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k}))
        except Exception:
            # Pad to full length so indexing below never fails
            while len(mnemonics) < len(shares):
                mnemonics.append(None)
        for i,sh in enumerate(shares,1):
            mn=mnemonics[i-1] if i-1<len(mnemonics) else None
            ShareCard(self._results,i,sh,mnemonic=mn).pack(fill="x",pady=(0,8))
        # Next-steps checklist — guides non-technical users through what to do now
        steps = tk.Frame(self._results, bg=C["surface"],
                         highlightbackground=C["accent"], highlightthickness=1)
        steps.pack(fill="x", pady=(4, 8))
        tk.Label(steps, text="What to do next", font=F["body_b"],
                 bg=C["surface"], fg=C["accent"]).pack(anchor="w", padx=14, pady=(10, 6))
        checklist = [
            f"1.  Save the shares using the buttons above (one file per person, or combined)",
            f"2.  Send each person ONLY their own share — never share the others",
            f"3.  Keep the encrypted .qcx file — it's safe to store anywhere",
            f"4.  Test unlocking: collect {k} shares and try decrypting the file",
            f"5.  Once confirmed, distribute shares to their holders",
        ]
        for line in checklist:
            tk.Label(steps, text=line, font=F["caption"],
                     bg=C["surface"], fg=C["text2"], anchor="w",
                     wraplength=480, justify="left").pack(fill="x", padx=14, pady=1)
        tk.Label(steps, text="", font=F["small"], bg=C["surface"]).pack(pady=(0, 8))
        # Force geometry to settle, then schedule cancellable scroll
        self._body.update_idletasks()
        if self._scroll_job is not None:
            try: self.after_cancel(self._scroll_job)
            except Exception: pass
        self._scroll_job = self.after(150, lambda: self._cv.yview_moveto(1.0))

    def _copy_all_shares(self, shares):
        """Copy all share strings to the clipboard as one share per line."""
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(shares))
            self._copy_all_btn.config(text="✓ Copied")
            self.after(1500, lambda: self._copy_all_btn.config(text="Copy all")
                       if self._copy_all_btn.winfo_exists() else None)
            if hasattr(self, "_copy_all_timer"): self._copy_all_timer.start()
        except Exception:
            pass

    def _reset(self):
        if not self._check_shares_saved(): return
        # Cancel any pending scroll-to-bottom from _done
        if self._scroll_job is not None:
            try: self.after_cancel(self._scroll_job)
            except Exception: pass
            self._scroll_job = None
        self._shares_pending=False; self._pending_shares=[]
        self._path=None; self._is_folder=False; self._batch_paths=[]
        self._src_type.set("file")   # restore toggle to File mode
        self._out.delete(0,"end")
        self._out_auto=False
        self._pw1v.set(""); self._pw2v.set("")
        self._pw1.config(show="•"); self._pw2.config(show="•")
        self._eye1_btn.config(text="Show"); self._eye2_btn.config(text="Show")
        # Remember last-used mode and Shamir config across "Encrypt another"
        last_mode = self._mode.get()
        last_n    = self._n.get()
        last_k    = self._k.get()
        self._mode.set(last_mode); self._embed_dec.set(False); self._err.config(text="")
        self._n.set(last_n); self._k.set(last_k)
        for w in self._results.winfo_children(): w.destroy()
        self._file_card.pack(fill="x", padx=self._P, after=self._src_toggle)   # ensure visible after batch mode
        self._batch_frame.pack_forget()
        if hasattr(self, "_batch_out_var"): self._batch_out_var.set("")
        self._file_card.reset("Select a file to encrypt","Click anywhere · or drag & drop")  # No destroy/recreate
        self._prog.pack_forget(); self._wiz.set_step(0)
        self._on_embed_toggle()
        self.title("QuantaCrypt · Encrypt")
        self.after(10, lambda: self._cv.yview_moveto(0))  # Scroll back to top
        # Restore focus to file card so keyboard users have a clear starting point
        self.after(20, self._file_card.focus_set)

    def _fail(self,msg):
        self._busy=False; self._prog.stop(); self._prog.pack_forget(); self._thaw(); self._wiz.set_step(4)
        if "No space left" in msg or "disk" in msg.lower():
            self._err.config(text="Not enough disk space. Free up some storage and try again.")
        elif "Permission" in msg or "Access is denied" in msg:
            self._err.config(text="Can't write to that location — check permissions or choose a different output path.")
        elif "FileNotFoundError" in msg or "No such file" in msg:
            self._err.config(text="The source file was moved or deleted. Please re-select it and try again.")
        elif "too large" in msg.lower() or "MemoryError" in msg:
            self._err.config(text="File is too large to process. Try a smaller file or free up memory.")
        else:
            self._err.config(text="Something went wrong during encryption. Try a different output location or restart the app.")
        # Scroll to bottom so the error label is visible
        self.after(50, lambda: self._cv.yview_moveto(1.0))  # Reflow delay

    def _save_individual_shares(self, shares, orig, qcx_path=None, banner_frame=None):
        """Save each share as its own file in a chosen folder.
        Files are named  <stem>.share-1-of-N.txt, .share-2-of-N.txt, etc.
        Each file contains ONLY that person's share + instructions, so you can
        hand each file directly to the recipient without exposing other shares."""
        # Derive initial dir from the .qcx file when available (handles batch mode where
        # self._out may be stale or hidden); fall back to self._out for single-file mode.
        if qcx_path and os.path.isfile(qcx_path):
            out_dir = os.path.dirname(os.path.abspath(qcx_path))
        elif self._out.get().strip():
            out_dir = os.path.dirname(os.path.abspath(self._out.get().strip()))
        else:
            out_dir = ""
        folder = filedialog.askdirectory(
            initialdir=out_dir,
            title="Choose a folder to save individual share files")
        if not folder: return
        k = self._k.get(); n = self._n.get()
        stem = os.path.splitext(orig)[0] if orig else "shares"
        # Compute fingerprint of the .qcx file so recipients can match their share
        if qcx_path is None:
            qcx_path = self._out.get().strip()
        qcx_name = os.path.basename(qcx_path) if qcx_path else ""
        fingerprint = ""
        if qcx_path and os.path.isfile(qcx_path):
            try:
                import hashlib
                with open(qcx_path, "rb") as fh:
                    fingerprint = hashlib.sha256(fh.read(65536)).hexdigest()[:12]
            except Exception: pass
        mnemonics = []
        for s in shares:
            try:
                mnemonics.append(cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k}))
            except Exception:
                mnemonics.append(None)
        saved = []
        try:
            for i, s in enumerate(shares, 1):
                fname = os.path.join(folder, f"{stem}.share-{i}-of-{n}.txt")
                mn = mnemonics[i-1] if i-1 < len(mnemonics) else None
                fp_line = (f"File fingerprint:  {fingerprint}...\n") if fingerprint else ""
                with open(fname, "w") as f:
                    f.write(
                        f"QuantaCrypt Share {i} of {n}\n"
                        f"{'='*60}\n"
                        f"Encrypted file:    {qcx_name}\n"
                        f"{fp_line}"
                        f"Threshold:         Any {k} of {n} shares are needed to decrypt\n"
                        f"{'='*60}\n\n"
                        f"KEEP THIS FILE PRIVATE. Do not share it with other shareholders.\n\n"
                        f"── QCSHARE- code (for copy-paste) ──────────────────────\n"
                        f"{s}\n\n"
                    )
                    if mn:
                        f.write(
                            f"── 50-word mnemonic (for offline backup) ───────────────\n"
                            f"{mn}\n\n"
                        )
                    f.write(
                        f"── How to decrypt ───────────────────────────────────────\n"
                        f"1. Collect {k} share files from {k} of the {n} shareholders.\n"
                        f"2. Open quantacrypt and load the encrypted file.\n"
                        f"3. Paste each QCSHARE- code (or type the 50 words) into the\n"
                        f"   corresponding share slot.\n"
                        f"4. Click Decrypt.\n"
                    )
                saved.append(fname)
        except OSError as e:
            messagebox.showerror("Save failed",
                f"Could not write share file:\n{e}\n\n"
                f"Saved {len(saved)} of {n} files before the error.")
            if saved: self._shares_pending = False
            return
        self._shares_pending = False
        # Dim ShareCards (single-file mode — they live in self._results directly)
        if banner_frame is getattr(self, "_shares_warn", None):
            try:
                for w in self._results.winfo_children():
                    if isinstance(w, ShareCard):
                        w.mark_saved()
            except Exception: pass
        # Update the warning banner to show success.
        # banner_frame may be self._shares_warn (single-file) or a per-file sec frame (batch).
        target = banner_frame if banner_frame is not None else getattr(self, "_shares_warn", None)
        try:
            if target and target.winfo_exists():
                for w in target.winfo_children(): w.destroy()
                target.config(highlightbackground=C["success"])
                done_row = tk.Frame(target, bg=C["surface"])
                done_row.pack(fill="x", padx=14, pady=(10,4))
                tk.Label(done_row, text=f"✓  {n} share files saved", font=F["body_b"],
                         bg=C["surface"], fg=C["success"]).pack(side="left")
                tk.Label(done_row, text=os.path.basename(folder), font=F["caption"],
                         bg=C["surface"], fg=C["text3"]).pack(side="right")
                tk.Label(target,
                         text=f"Each recipient gets their own file. Distribute one file per person.\n"
                              f"Recommended: test decryption before distributing.",
                         font=F["caption"], bg=C["surface"], fg=C["text3"],
                         anchor="w", justify="left").pack(fill="x", padx=14, pady=(0,10))
                FlatButton(target, "Open folder",
                           lambda: _reveal(saved[0] if saved else folder),
                           primary=False, small=True).pack(anchor="w", padx=14, pady=(0,10))
        except Exception: pass

    def _save_shares(self,shares,orig):
        out_dir=os.path.dirname(os.path.abspath(self._out.get().strip())) if self._out.get().strip() else ""
        p=filedialog.asksaveasfilename(initialdir=out_dir,
            initialfile=os.path.splitext(orig)[0]+".shares.txt",defaultextension=".txt")
        if not p: return
        k=self._k.get(); n=self._n.get()
        mnemonics = []
        for s in shares:
            try:
                mnemonics.append(cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k}))
            except Exception:
                mnemonics.append(None)
        # Compute a short fingerprint of the .qcx file to help match shares to file later
        qcx_ref = ""
        qcx_path = self._out.get().strip()
        if qcx_path and os.path.isfile(qcx_path):
            try:
                import hashlib
                with open(qcx_path, "rb") as fh:
                    digest = hashlib.sha256(fh.read(65536)).hexdigest()[:12]
                qcx_ref = f"\nFile:      {os.path.basename(qcx_path)}\nFingerprint (SHA-256 prefix): {digest}..."
            except Exception:
                qcx_ref = f"\nFile:      {os.path.basename(qcx_path)}"
        # Wrap the file write in try/except so a full disk or
        # permission error doesn't leave _shares_pending=True forever, trapping
        # the user in an unsaved-shares dialog they can never clear.
        try:
            with open(p,"w") as f:
                f.write(f"QuantaCrypt Key Shares\nThreshold: {k} of {n}{qcx_ref}\n{'='*60}\n\n")
                for i,s in enumerate(shares,1):
                    f.write(f"Share {i} — QCSHARE- code:\n{s}\n\n")
                    mn=mnemonics[i-1]
                    if mn: f.write(f"Share {i} — 50-word mnemonic:\n{mn}\n\n")
                    f.write("-"*60+"\n\n")
        except OSError as _e:
            messagebox.showerror("Save failed",
                f"Could not write shares file:\n{_e}\n\n"
                "Your shares have NOT been saved. Please try a different location.")
            return
        self._shares_pending=False   # shares are now saved
        # Update the warning banner to confirm save succeeded
        try:
            for w in self._shares_warn.winfo_children(): w.destroy()
            self._shares_warn.config(highlightbackground=C["success"])
            done_row = tk.Frame(self._shares_warn, bg=C["surface"])
            done_row.pack(fill="x", padx=14, pady=(10,4))
            tk.Label(done_row, text="✓  Shares saved", font=F["body_b"],
                     bg=C["surface"], fg=C["success"]).pack(side="left")
            tk.Label(done_row, text=os.path.basename(p), font=F["caption"],
                     bg=C["surface"], fg=C["text3"]).pack(side="right")
            # Nudge the user to test decryption before distributing shares
            tk.Label(self._shares_warn,
                     text="Recommended: test decryption with one share set before distributing.",
                     font=F["caption"], bg=C["surface"], fg=C["text3"],
                     anchor="w").pack(fill="x", padx=14, pady=(0,10))
        except Exception:
            pass

def main(): EncryptorApp().mainloop()
if __name__=="__main__": main()
