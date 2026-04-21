#!/usr/bin/env python3
"""QuantaCrypt Volume Manager — create, mount, and unmount encrypted volumes."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable

from quantacrypt.core import volume as vol
from quantacrypt.ui.shared import (
    C, F, UI,
    styled_entry, bind_context_menu, fmt_size, rule, friendly_error,
    FlatButton, SegmentedControl, StagedProgressBar,
    PasswordStrengthBar, WizardSteps, ClipboardTimer,
    notify,
)


# ── Volume Creation Stages ──────────────────────────────────────────────────

STAGES = [
    ("Securing password", 0.60, "Argon2id"),
    ("Generating keys",   0.20, "Kyber"),
    ("Writing volume",    0.20, "Writing"),
]


def _find_stage(msg: str):
    for i, (name, _, kw) in enumerate(STAGES):
        if kw.lower() in msg.lower():
            return i, msg
    return None, None


# ── Volume Manager Window ────────────────────────────────────────────────────

class VolumeManagerApp(tk.Toplevel):
    """Combined volume creation wizard and mount/unmount panel."""

    def __init__(self, master: tk.Misc, on_close: Callable | None = None,
                 center_at: tuple[int, int] | None = None,
                 volume_path: str | None = None):
        super().__init__(master)
        self.title("QuantaCrypt — Encrypted Volumes")
        self.configure(bg=C["bg"])
        self.resizable(False, False)

        self._on_close = on_close
        self._center_at = center_at
        self._mode_var = tk.StringVar(value="mount" if volume_path else "create")

        self._build()
        self._center()

        # If a .qcv path was provided, pre-fill the mount panel
        if volume_path and hasattr(self, "_mount_path_var"):
            self._mount_path_var.set(volume_path)

        self.protocol("WM_DELETE_WINDOW", self._close)
        self.bind("<Escape>", lambda e: self._close())
        # Keyboard shortcuts: Ctrl+N → Create, Ctrl+M → Mount
        self.bind("<Control-n>", lambda e: self._mode_var.set("create"))
        self.bind("<Control-N>", lambda e: self._mode_var.set("create"))
        self.bind("<Control-m>", lambda e: self._mode_var.set("mount"))
        self.bind("<Control-M>", lambda e: self._mode_var.set("mount"))

    def _close(self):
        self.destroy()
        if self._on_close:
            self._on_close()

    def _center(self):
        self.update_idletasks()
        if self._center_at:
            cx, cy = self._center_at
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{cx - w // 2}+{cy - h // 2}")
        else:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    def _build(self):
        P = 28

        # ── Header ──
        tk.Label(self, text="Encrypted Volumes", font=F["display"],
                 bg=C["bg"], fg=C["text"]).pack(padx=P, pady=(24, 4))
        tk.Label(self, text="Create or mount encrypted virtual drives",
                 font=F["body"], bg=C["bg"], fg=C["text3"]).pack(padx=P)

        rule(self, pady=16, padx=P)

        # ── Mode toggle ──
        seg_frame = tk.Frame(self, bg=C["bg"])
        seg_frame.pack(padx=P, fill="x")
        SegmentedControl(seg_frame,
                         [("create", "Create New"), ("mount", "Mount Existing")],
                         self._mode_var).pack(fill="x")
        self._mode_var.trace_add("write", lambda *_: self._on_mode_change())

        # ── Content frames ──
        self._create_frame = tk.Frame(self, bg=C["bg"])
        self._mount_frame = tk.Frame(self, bg=C["bg"])

        self._build_create_panel(self._create_frame, P)
        self._build_mount_panel(self._mount_frame, P)

        # Show the panel matching the initial mode
        if self._mode_var.get() == "mount":
            self._mount_frame.pack(fill="both", expand=True, padx=P, pady=(12, P))
        else:
            self._create_frame.pack(fill="both", expand=True, padx=P, pady=(12, P))

    def _on_mode_change(self):
        mode = self._mode_var.get()
        self._create_frame.pack_forget()
        self._mount_frame.pack_forget()
        P = 28
        if mode == "create":
            self._create_frame.pack(fill="both", expand=True, padx=P, pady=(12, P))
        else:
            self._mount_frame.pack(fill="both", expand=True, padx=P, pady=(12, P))

    # ── Create Panel ─────────────────────────────────────────────────────────

    def _build_create_panel(self, parent: tk.Frame, P: int):
        # Auth mode
        self._auth_var = tk.StringVar(value="password")
        auth_frame = tk.Frame(parent, bg=C["bg"])
        auth_frame.pack(fill="x", pady=(8, 0))
        tk.Label(auth_frame, text="Protection mode", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        SegmentedControl(auth_frame,
                         [("password", "Password"), ("shamir", "Split Key")],
                         self._auth_var).pack(fill="x", pady=(6, 0))
        self._auth_var.trace_add("write", lambda *_: self._on_auth_change())

        # Location
        loc_frame = tk.Frame(parent, bg=C["bg"])
        loc_frame.pack(fill="x", pady=(14, 0))
        tk.Label(loc_frame, text="Save volume as", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        row = tk.Frame(loc_frame, bg=C["bg"])
        row.pack(fill="x", pady=(4, 0))
        self._loc_var = tk.StringVar()
        e = styled_entry(row, textvariable=self._loc_var)
        e.pack(side="left", fill="x", expand=True)
        FlatButton(row, "Browse…", self._browse_save_location,
                   primary=False, small=True).pack(side="left", padx=(8, 0))

        # Password fields (shown for password mode)
        self._pw_frame = tk.Frame(parent, bg=C["bg"])
        self._pw_frame.pack(fill="x", pady=(14, 0))
        tk.Label(self._pw_frame, text="Password", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        self._pw_var = tk.StringVar()
        pw_e = styled_entry(self._pw_frame, textvariable=self._pw_var, show="●")
        pw_e.pack(fill="x", pady=(4, 0))
        PasswordStrengthBar(self._pw_frame, self._pw_var).pack(fill="x", pady=(4, 0))

        tk.Label(self._pw_frame, text="Confirm password", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(10, 0))
        self._pw2_var = tk.StringVar()
        pw2_e = styled_entry(self._pw_frame, textvariable=self._pw2_var, show="●")
        pw2_e.pack(fill="x", pady=(4, 0))

        # Shamir fields (hidden by default)
        self._shamir_frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(self._shamir_frame, text="Total shares (n)",
                 font=F["body_b"], bg=C["bg"], fg=C["text"]).pack(anchor="w")
        self._n_var = tk.StringVar(value="3")
        styled_entry(self._shamir_frame, textvariable=self._n_var,
                     width=6).pack(anchor="w", pady=(4, 8))
        tk.Label(self._shamir_frame, text="Required to unlock (k)",
                 font=F["body_b"], bg=C["bg"], fg=C["text"]).pack(anchor="w")
        self._k_var = tk.StringVar(value="2")
        styled_entry(self._shamir_frame, textvariable=self._k_var,
                     width=6).pack(anchor="w", pady=(4, 0))

        # Progress bar (hidden until creation starts)
        self._progress = StagedProgressBar(
            parent,
            [(name, w) for name, w, _ in STAGES],
        )

        # Create button
        self._create_btn = FlatButton(parent, "Create Encrypted Volume",
                                       self._do_create)
        self._create_btn.pack(fill="x", pady=(18, 0))

    def _on_auth_change(self):
        mode = self._auth_var.get()
        if mode == "password":
            self._shamir_frame.pack_forget()
            self._pw_frame.pack(fill="x", pady=(14, 0))
        else:
            self._pw_frame.pack_forget()
            self._shamir_frame.pack(fill="x", pady=(14, 0))

    def _browse_save_location(self):
        p = filedialog.asksaveasfilename(
            title="Save encrypted volume",
            defaultextension=".qcv",
            filetypes=[("QuantaCrypt Volume", "*.qcv"), ("All files", "*")],
            initialdir=os.path.expanduser("~"),
        )
        if p:
            self._loc_var.set(p)

    def _do_create(self):
        path = self._loc_var.get().strip()
        if not path:
            messagebox.showwarning("Missing location",
                                   "Choose where to save the volume.",
                                   parent=self)
            return

        auth = self._auth_var.get()

        if auth == "password":
            pw = self._pw_var.get()
            pw2 = self._pw2_var.get()
            if not pw:
                messagebox.showwarning("Missing password",
                                       "Enter a password.", parent=self)
                return
            if pw != pw2:
                messagebox.showwarning("Mismatch",
                                       "Passwords do not match.", parent=self)
                return
        else:
            try:
                n = int(self._n_var.get())
                k = int(self._k_var.get())
            except ValueError:
                messagebox.showwarning("Invalid",
                                       "N and K must be integers.", parent=self)
                return
            if k < 2 or k > n:
                messagebox.showwarning("Invalid",
                                       "K must be between 2 and N.", parent=self)
                return

        # Disable button, show progress
        self._create_btn.enable(False)
        self._progress.pack(fill="x", pady=(12, 0))
        self._progress.start()

        def _worker():
            try:
                if auth == "password":
                    meta = vol.create_volume_single(path, pw, progress_cb=_progress)
                    self.after(0, lambda: self._on_create_done(path, meta))
                else:
                    meta, shares = vol.create_volume_shamir(
                        path, n, k, progress_cb=_progress)
                    self.after(0, lambda: self._on_create_done(
                        path, meta, shares=shares))
            except Exception as e:
                self.after(0, lambda exc=e: self._on_create_error(exc))

        def _progress(msg):
            idx, label = _find_stage(msg)
            if idx is not None:
                self.after(0, lambda: self._progress.advance(idx, label))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_create_done(self, path: str, meta: dict, shares: list | None = None):
        self._progress.complete()
        notify("Volume Created",
               f"Encrypted volume saved to {os.path.basename(path)}")

        if shares:
            # Show shares in a dialog
            self._show_shares_dialog(shares, meta)
        else:
            messagebox.showinfo(
                "Volume Created",
                f"Your encrypted volume has been created:\n{path}\n\n"
                "You can mount it using the Mount tab.",
                parent=self,
            )
        self._create_btn.enable(True)

    def _on_create_error(self, err):
        self._progress.stop()
        self._create_btn.enable(True)
        # Accept either an exception or a raw string; translate to a
        # user-friendly message before displaying.
        if isinstance(err, BaseException):
            msg = friendly_error(err)
        else:
            msg = str(err)
        messagebox.showerror("Volume creation failed", msg, parent=self)

    def _show_shares_dialog(self, shares: list[str], meta: dict):
        win = tk.Toplevel(self)
        win.title("Recovery Shares")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        P = 24
        k = meta.get("threshold", 2)
        n = meta.get("total", 3)

        tk.Label(win, text="Save Your Recovery Shares", font=F["heading"],
                 bg=C["bg"], fg=C["text"]).pack(padx=P, pady=(20, 4))
        tk.Label(win, text=f"You need {k} of {n} shares to unlock this volume.",
                 font=F["body"], bg=C["bg"], fg=C["text3"]).pack(padx=P)
        tk.Label(win, text="Give each share to a different person. Never store "
                           "all shares together.",
                 font=F["caption"], bg=C["bg"], fg=C["warning"]).pack(padx=P, pady=(8, 12))

        for i, share in enumerate(shares):
            frame = tk.Frame(win, bg=C["surface"],
                             highlightbackground=C["border"], highlightthickness=1)
            frame.pack(fill="x", padx=P, pady=(0, 6))
            tk.Label(frame, text=f"Share {i + 1}",
                     font=F["body_b"], bg=C["surface"], fg=C["text"]).pack(
                anchor="w", padx=12, pady=(8, 2))
            txt = tk.Text(frame, height=2, wrap="word", font=F["mono_s"],
                          bg=C["surface2"], fg=C["text"], relief="flat",
                          insertbackground=C["accent"])
            txt.insert("1.0", share)
            txt.config(state="disabled")
            txt.pack(fill="x", padx=12, pady=(0, 8))
            bind_context_menu(txt)

        FlatButton(win, "I've saved all shares", win.destroy).pack(
            padx=P, pady=(8, 20))

        win.update_idletasks()
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        w, h = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{cx - w // 2}+{cy - h // 2}")

    # ── Mount Panel ──────────────────────────────────────────────────────────

    def _build_mount_panel(self, parent: tk.Frame, P: int):
        # FUSE check — show setup screen if components are missing
        from quantacrypt.core.fuse_ops import check_fuse_components
        components = check_fuse_components()

        all_ok = all(c["ok"] for c in components.values())

        if not all_ok:
            self._setup_frame = tk.Frame(parent, bg=C["bg"])
            self._setup_frame.pack(fill="both", expand=True)
            self._build_setup_screen(self._setup_frame, components)

            # Mount UI container (built but hidden until setup is done)
            self._mount_inner = tk.Frame(parent, bg=C["bg"])
            self._build_mount_ui(self._mount_inner)
            return

        # Everything available — build mount UI directly
        self._setup_frame = None
        self._mount_inner = None
        self._build_mount_ui(parent)

    def _build_setup_screen(self, parent: tk.Frame,
                            components: dict[str, dict]):
        """Guided dependency setup screen shown when FUSE components are missing."""
        tk.Label(parent, text="Setup Required", font=F["heading"],
                 bg=C["bg"], fg=C["warning"]).pack(pady=(12, 4))
        tk.Label(parent, text="Encrypted volumes need a couple of components "
                               "to mount as real drives.",
                 font=F["body"], bg=C["bg"], fg=C["text3"],
                 wraplength=420, justify="center").pack(pady=(0, 16))

        # Component rows
        self._comp_widgets: dict[str, dict] = {}

        for key, label, install_cmd, install_label, hint in [
            ("fuse_backend",
             "FUSE backend",
             None,  # platform-specific — handled in _install_fuse_backend
             "Install…",
             "macOS: macFUSE or FUSE-T  •  Linux: libfuse"),
            ("fusepy",
             "fusepy (Python package)",
             [sys.executable, "-m", "pip", "install", "fusepy"],
             "Install fusepy",
             "pip install fusepy"),
        ]:
            info = components.get(key, {"ok": False, "detail": "unknown"})
            row = tk.Frame(parent, bg=C["surface"],
                           highlightbackground=C["border"],
                           highlightthickness=1)
            row.pack(fill="x", pady=(0, 8))

            top = tk.Frame(row, bg=C["surface"])
            top.pack(fill="x", padx=14, pady=(10, 0))

            # Status icon + label
            icon = "✓" if info["ok"] else "✗"
            icon_color = C["success"] if info["ok"] else C["error"]
            tk.Label(top, text=icon, font=F["body_b"],
                     bg=C["surface"], fg=icon_color).pack(side="left")
            tk.Label(top, text=f"  {label}", font=F["body_b"],
                     bg=C["surface"], fg=C["text"]).pack(side="left")

            # Detail text
            detail_lbl = tk.Label(row, text=info["detail"], font=F["caption"],
                                   bg=C["surface"], fg=C["text3"])
            detail_lbl.pack(anchor="w", padx=14, pady=(2, 0))

            # Install button (only if not already available)
            btn = None
            if not info["ok"]:
                btn_frame = tk.Frame(row, bg=C["surface"])
                btn_frame.pack(anchor="w", padx=14, pady=(6, 10))
                if key == "fuse_backend":
                    btn = FlatButton(
                        btn_frame, install_label,
                        lambda: self._install_fuse_backend(),
                        small=True)
                else:
                    btn = FlatButton(
                        btn_frame, install_label,
                        lambda c=install_cmd, k=key: self._run_install(c, k),
                        small=True)
                btn.pack(side="left")

                hint_lbl = tk.Label(btn_frame, text=hint, font=F["caption"],
                                     bg=C["surface"], fg=C["text3"])
                hint_lbl.pack(side="left", padx=(10, 0))
            else:
                # Pad bottom for installed components
                tk.Frame(row, bg=C["surface"], height=10).pack()

            self._comp_widgets[key] = {
                "row": row, "icon_lbl": top.winfo_children()[0],
                "detail_lbl": detail_lbl, "btn": btn,
            }

        # Recheck button
        self._recheck_btn = FlatButton(
            parent, "Recheck dependencies",
            self._recheck_dependencies, primary=False)
        self._recheck_btn.pack(fill="x", pady=(12, 0))

    def _run_install(self, cmd: list[str], component_key: str):
        """Run a pip install command in a background thread."""
        widgets = self._comp_widgets[component_key]
        if widgets["btn"]:
            widgets["btn"].enable(False)
        widgets["detail_lbl"].config(text="Installing…", fg=C["warning"])

        def _worker():
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    self.after(0, lambda: self._on_install_ok(component_key))
                else:
                    err = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "Unknown error"
                    self.after(0, lambda: self._on_install_fail(
                        component_key, err))
            except Exception as e:
                self.after(0, lambda: self._on_install_fail(
                    component_key, str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _install_fuse_backend(self):
        """Guide the user to install a FUSE backend (requires admin)."""
        widgets = self._comp_widgets["fuse_backend"]
        if sys.platform == "darwin":
            msg = (
                "A FUSE backend requires administrator privileges to install.\n\n"
                "Option 1 — FUSE-T (recommended, kext-free):\n"
                "  brew install --cask fuse-t\n\n"
                "Option 2 — macFUSE:\n"
                "  brew install --cask macfuse\n\n"
                "After installing, click \"Recheck dependencies\" below."
            )
            # Try to open Terminal with the brew command
            answer = messagebox.askyesno(
                "Install FUSE backend",
                f"{msg}\n\nWould you like to open Terminal with the "
                "install command?",
                parent=self,
            )
            if answer:
                try:
                    subprocess.Popen([
                        "osascript", "-e",
                        'tell app "Terminal" to do script '
                        '"brew install --cask fuse-t"',
                    ])
                    widgets["detail_lbl"].config(
                        text="Check Terminal — install in progress…",
                        fg=C["warning"])
                except Exception:
                    messagebox.showinfo(
                        "Manual install needed",
                        "Could not open Terminal automatically.\n"
                        "Please run the command manually:\n\n"
                        "  brew install --cask fuse-t",
                        parent=self,
                    )
        else:
            msg = (
                "A FUSE backend requires administrator privileges to install.\n\n"
                "Run this command in a terminal:\n"
                "  sudo apt install libfuse-dev\n\n"
                "After installing, click \"Recheck dependencies\" below."
            )
            messagebox.showinfo("Install FUSE backend", msg, parent=self)

    def _on_install_ok(self, component_key: str):
        widgets = self._comp_widgets[component_key]
        widgets["icon_lbl"].config(text="✓", fg=C["success"])
        widgets["detail_lbl"].config(text="Installed successfully", fg=C["success"])
        if widgets["btn"]:
            widgets["btn"].pack_forget()
        # Auto-recheck
        self._recheck_dependencies()

    def _on_install_fail(self, component_key: str, err: str):
        widgets = self._comp_widgets[component_key]
        widgets["detail_lbl"].config(text=f"Install failed: {err}", fg=C["error"])
        if widgets["btn"]:
            widgets["btn"].enable(True)

    def _recheck_dependencies(self):
        """Re-run component checks and update the setup screen or switch to mount UI."""
        from quantacrypt.core.fuse_ops import check_fuse_components
        components = check_fuse_components()

        all_ok = all(c["ok"] for c in components.values())

        # Update existing component widgets
        for key, info in components.items():
            if key in self._comp_widgets:
                w = self._comp_widgets[key]
                icon = "✓" if info["ok"] else "✗"
                icon_color = C["success"] if info["ok"] else C["error"]
                w["icon_lbl"].config(text=icon, fg=icon_color)
                w["detail_lbl"].config(
                    text=info["detail"],
                    fg=C["success"] if info["ok"] else C["text3"])
                if info["ok"] and w["btn"]:
                    w["btn"].pack_forget()

        if all_ok:
            # Hide setup, show mount UI
            self._setup_frame.pack_forget()
            self._recheck_btn.pack_forget()
            self._mount_inner.pack(fill="both", expand=True)

    def _build_mount_ui(self, parent: tk.Frame):
        """Build the actual volume mount/unmount controls."""
        # Volume file selection
        tk.Label(parent, text="Volume file (.qcv)", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(8, 0))
        row = tk.Frame(parent, bg=C["bg"])
        row.pack(fill="x", pady=(4, 0))
        self._mount_path_var = tk.StringVar()
        self._mount_path_var.trace_add("write",
                                        lambda *_: self._on_volume_selected())
        styled_entry(row, textvariable=self._mount_path_var).pack(
            side="left", fill="x", expand=True)
        FlatButton(row, "Browse…", self._browse_volume,
                   primary=False, small=True).pack(side="left", padx=(8, 0))

        # Volume info hint (shown after a valid .qcv is selected)
        self._vol_info_lbl = tk.Label(parent, text="", font=F["caption"],
                                       bg=C["bg"], fg=C["text3"])
        self._vol_info_lbl.pack(anchor="w", pady=(2, 0))

        # Mount point
        tk.Label(parent, text="Mount point", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(10, 0))
        row2 = tk.Frame(parent, bg=C["bg"])
        row2.pack(fill="x", pady=(4, 0))
        self._mount_point_var = tk.StringVar(value="/Volumes/QuantaCrypt")
        styled_entry(row2, textvariable=self._mount_point_var).pack(
            side="left", fill="x", expand=True)
        FlatButton(row2, "Choose…", self._browse_mount_point,
                   primary=False, small=True).pack(side="left", padx=(8, 0))

        # Auth mode for mounting
        self._mount_auth_var = tk.StringVar(value="password")
        self._auth_frame = tk.Frame(parent, bg=C["bg"])
        self._auth_frame.pack(fill="x", pady=(12, 0))
        self._auth_label = tk.Label(self._auth_frame, text="Authentication",
                                     font=F["body_b"],
                                     bg=C["bg"], fg=C["text"])
        self._auth_label.pack(anchor="w")
        self._auth_seg = SegmentedControl(
            self._auth_frame,
            [("password", "Password"), ("shamir", "Shares")],
            self._mount_auth_var)
        self._auth_seg.pack(fill="x", pady=(6, 0))
        self._mount_auth_var.trace_add("write",
                                        lambda *_: self._on_mount_auth_change())

        # Password input
        self._mount_pw_frame = tk.Frame(parent, bg=C["bg"])
        self._mount_pw_frame.pack(fill="x", pady=(10, 0))
        self._mount_pw_var = tk.StringVar()
        styled_entry(self._mount_pw_frame, textvariable=self._mount_pw_var,
                     show="●").pack(fill="x")

        # Shares input (hidden by default)
        self._mount_shares_frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(self._mount_shares_frame, text="Paste shares (one per line)",
                 font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")
        self._mount_shares_text = tk.Text(
            self._mount_shares_frame, height=4, wrap="word",
            font=F["mono_s"], bg=C["surface2"], fg=C["text"],
            relief="flat", insertbackground=C["accent"])
        self._mount_shares_text.pack(fill="x", pady=(4, 0))
        bind_context_menu(self._mount_shares_text)

        # Mount button
        self._mount_btn = FlatButton(parent, "Mount Volume", self._do_mount)
        self._mount_btn.pack(fill="x", pady=(18, 0))

        # Status label
        self._mount_status = tk.Label(parent, text="", font=F["caption"],
                                       bg=C["bg"], fg=C["text3"])
        self._mount_status.pack(anchor="w", pady=(8, 0))

        # ── Mounted volumes list ──
        self._mounted_list_frame = tk.Frame(parent, bg=C["bg"])
        self._mounted_list_frame.pack(fill="x", pady=(8, 0))
        self._refresh_mounted_list()

    def _on_volume_selected(self):
        """Called when the volume path field changes.

        Auto-detects auth mode from the volume's unencrypted auth params,
        switches the UI to Password or Shares accordingly, and generates
        a smart mount-point default from the filename.
        """
        path = self._mount_path_var.get().strip()
        if not path or not os.path.isfile(path):
            self._vol_info_lbl.config(text="")
            return

        try:
            _header, auth_params = vol.read_volume_auth_params(path)
        except (ValueError, OSError):
            self._vol_info_lbl.config(text="Not a valid .qcv file", fg=C["error"])
            return

        mode = auth_params.get("mode", "single")

        # File size hint
        try:
            size_hint = f"  ({fmt_size(os.path.getsize(path))})"
        except OSError:
            size_hint = ""

        # Auto-switch auth mode toggle
        if mode == "shamir":
            self._mount_auth_var.set("shamir")
            k = auth_params.get("threshold", "?")
            n = auth_params.get("total", "?")
            self._vol_info_lbl.config(
                text=f"Split-key volume — needs {k} of {n} shares{size_hint}",
                fg=C["text3"])
        else:
            self._mount_auth_var.set("password")
            self._vol_info_lbl.config(
                text=f"Password-protected volume{size_hint}",
                fg=C["text3"])

        # Smart mount point from filename (e.g. "Secrets.qcv" → "/Volumes/Secrets")
        basename = os.path.splitext(os.path.basename(path))[0]
        if basename:
            if sys.platform == "darwin":
                mp = f"/Volumes/{basename}"
            else:
                mp = os.path.join("/tmp", f"qcv-{basename}")
            self._mount_point_var.set(mp)

    def _on_mount_auth_change(self):
        mode = self._mount_auth_var.get()
        if mode == "password":
            self._mount_shares_frame.pack_forget()
            self._mount_pw_frame.pack(fill="x", pady=(10, 0))
        else:
            self._mount_pw_frame.pack_forget()
            self._mount_shares_frame.pack(fill="x", pady=(10, 0))

    def _browse_volume(self):
        p = filedialog.askopenfilename(
            title="Select encrypted volume",
            filetypes=[("QuantaCrypt Volume", "*.qcv"), ("All files", "*")],
            initialdir=os.path.expanduser("~"),
        )
        if p:
            self._mount_path_var.set(p)

    def _browse_mount_point(self):
        p = filedialog.askdirectory(title="Select mount point")
        if p:
            self._mount_point_var.set(p)

    def _do_mount(self):
        vol_path = self._mount_path_var.get().strip()
        mount_point = self._mount_point_var.get().strip()

        if not vol_path or not os.path.isfile(vol_path):
            messagebox.showwarning("Missing volume",
                                   "Select a valid .qcv file.", parent=self)
            return
        if not mount_point:
            messagebox.showwarning("Missing mount point",
                                   "Choose a mount point directory.", parent=self)
            return

        self._mount_btn.enable(False)
        self._mount_status.config(text="Reading volume…", fg=C["text3"])

        def _worker():
            try:
                # Read unencrypted auth params (no key needed)
                header, auth_params = vol.read_volume_auth_params(vol_path)
                mode = auth_params.get("mode", "single")

                # Derive key from credentials + auth params
                if mode == "single":
                    pw = self._mount_pw_var.get()
                    if not pw:
                        self.after(0, lambda: self._mount_error("Enter password."))
                        return
                    self.after(0, lambda: self._mount_status.config(
                        text="Deriving key (this takes a few seconds)…",
                        fg=C["text3"]))
                    final_key = vol.derive_volume_key_single(pw, auth_params)
                else:
                    shares_text = self._mount_shares_text.get("1.0", "end").strip()
                    if not shares_text:
                        self.after(0, lambda: self._mount_error(
                            "Paste your recovery shares."))
                        return
                    share_lines = [
                        s.strip() for s in shares_text.splitlines() if s.strip()
                    ]
                    self.after(0, lambda: self._mount_status.config(
                        text="Recovering key from shares…", fg=C["text3"]))
                    final_key = vol.derive_volume_key_shamir(
                        share_lines, auth_params)

                # Mount via FUSE (mount_volume opens the volume internally)
                self.after(0, lambda: self._mount_status.config(
                    text="Mounting…", fg=C["text3"]))
                from quantacrypt.core.fuse_ops import mount_volume
                mount_volume(vol_path, final_key, mount_point)

                self.after(0, lambda: self._on_mount_done(mount_point))

            except Exception as e:
                self.after(0, lambda exc=e: self._mount_error(exc))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_mount_done(self, mount_point: str):
        self._mount_btn.enable(True)
        self._mount_status.config(
            text=f"Mounted at {mount_point}", fg=C["success"])
        notify("Volume Mounted",
               f"Encrypted volume mounted at {mount_point}")
        self._refresh_mounted_list()

    def _mount_error(self, msg):
        self._mount_btn.enable(True)
        self._mount_status.config(text="", fg=C["text3"])
        if isinstance(msg, BaseException):
            msg = friendly_error(msg)
        messagebox.showerror("Mount failed", msg, parent=self)

    def _do_unmount(self, mount_point: str):
        """Unmount a specific volume and refresh the list."""
        try:
            from quantacrypt.core.fuse_ops import unmount_volume
            unmount_volume(mount_point)
            self._mount_status.config(
                text=f"Unmounted {mount_point}", fg=C["success"])
        except Exception as e:
            messagebox.showerror("Unmount failed", friendly_error(e), parent=self)
        self._refresh_mounted_list()

    @staticmethod
    def _reveal_path(path: str):
        """Open a path in the platform file manager."""
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", path])
            elif sys.platform == "win32":
                subprocess.Popen(["explorer", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    def _refresh_mounted_list(self):
        """Rebuild the list of currently mounted volumes."""
        for w in self._mounted_list_frame.winfo_children():
            w.destroy()

        from quantacrypt.core.fuse_ops import get_mounted_volumes
        mounted = get_mounted_volumes()
        if not mounted:
            return

        rule(self._mounted_list_frame, pady=8)
        tk.Label(self._mounted_list_frame, text="MOUNTED VOLUMES",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(
            anchor="w", pady=(0, 6))

        for mp, info in mounted.items():
            vol_name = os.path.basename(info.get("volume_path", "?"))
            row = tk.Frame(self._mounted_list_frame, bg=C["surface"],
                           highlightbackground=C["border"],
                           highlightthickness=1)
            row.pack(fill="x", pady=(0, 4))

            # Top row: name, mount point, buttons
            inner = tk.Frame(row, bg=C["surface"])
            inner.pack(fill="x", padx=12, pady=(8, 0))

            tk.Label(inner, text=vol_name, font=F["caption"],
                     bg=C["surface"], fg=C["text"]).pack(side="left")
            tk.Label(inner, text=mp, font=F["small"],
                     bg=C["surface"], fg=C["text3"]).pack(
                side="left", padx=(8, 0))

            btn_frame = tk.Frame(inner, bg=C["surface"])
            btn_frame.pack(side="right")
            FlatButton(btn_frame, "Reveal",
                       lambda p=mp: self._reveal_path(p),
                       primary=False, small=True).pack(side="left", padx=(0, 4))
            FlatButton(btn_frame, "Unmount",
                       lambda p=mp: self._do_unmount(p),
                       primary=False, small=True).pack(side="left")

            # Stats row: file count, dir count, sizes
            vc = info.get("volume")
            if vc is not None:
                try:
                    stats = vc.stat()
                    parts = []
                    fc = stats.get("file_count", 0)
                    dc = stats.get("dir_count", 0)
                    parts.append(f"{fc} file{'s' if fc != 1 else ''}")
                    if dc:
                        parts.append(f"{dc} folder{'s' if dc != 1 else ''}")
                    pt = stats.get("total_plaintext_size", 0)
                    parts.append(fmt_size(pt))
                    cs = stats.get("container_size", 0)
                    if cs:
                        parts.append(f"container {fmt_size(cs)}")
                    stats_text = "  ·  ".join(parts)
                    tk.Label(row, text=stats_text, font=F["small"],
                             bg=C["surface"], fg=C["text3"]).pack(
                        anchor="w", padx=12, pady=(2, 8))
                except Exception:
                    tk.Frame(row, bg=C["surface"], height=8).pack()
