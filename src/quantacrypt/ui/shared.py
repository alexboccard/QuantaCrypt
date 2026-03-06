"""QuantaCrypt Shared UI Design System"""
import os
import tkinter as tk
import time

# ── Colors ────────────────────────────────────────────────────────────────────
C = {
    "bg":         "#1c1c1e",
    "surface":    "#2c2c2e",
    "surface2":   "#3a3a3c",
    "surface3":   "#48484a",
    "border":     "#48484a",
    "accent":     "#4a90d9",
    "accent_dim": "#2d5a8a",
    "text":       "#f5f5f7",
    "text2":      "#c8c8cc",
    "text3":      "#8e8e93",
    "success":    "#30d158",
    "error":      "#ff453a",
    "warning":    "#ffd60a",
    "warn_dim":   "#7a6500",
}

UI   = "DejaVu Sans"
MONO = "DejaVu Sans Mono"

F = {
    "display": (UI, 17, "bold"),
    "heading": (UI, 12, "bold"),
    "body":    (UI, 10),
    "body_b":  (UI, 10, "bold"),
    "caption": (UI,  9),
    "small":   (UI,  8),
    "mono":    (MONO, 9),
    "mono_s":  (MONO, 8),
}


def styled_entry(parent, **kw):
    return tk.Entry(
        parent, bg=C["surface2"], fg=C["text"],
        insertbackground=C["accent"], relief="flat",
        highlightbackground=C["border"], highlightcolor=C["accent"],
        highlightthickness=1, font=F["body"], **kw)


def fmt_size(n: int) -> str:
    """Consistent binary-prefixed file size string used across all size labels."""
    if n < 1024:           return f"{n:,} B"
    if n < 1_048_576:      return f"{n/1024:.1f} KB"
    if n < 1_073_741_824:  return f"{n/1_048_576:.1f} MB"
    return f"{n/1_073_741_824:.1f} GB"


def rule(parent, color=None, pady=12, padx=0):
    f = tk.Frame(parent, bg=color or C["border"], height=1)
    f.pack(fill="x", pady=pady, padx=padx)
    return f


def section_label(parent, text, padx=24):
    row = tk.Frame(parent, bg=C["bg"])
    row.pack(fill="x", padx=padx, pady=(18, 6))
    tk.Label(row, text=text, font=F["small"], bg=C["bg"],
             fg=C["text3"]).pack(side="left")
    tk.Frame(row, bg=C["border"], height=2).pack(
        side="left", fill="x", expand=True, padx=(10,0), pady=1)


try:
    from zxcvbn import zxcvbn as _zxcvbn_fn
except ImportError:
    _zxcvbn_fn = None


class FlatButton(tk.Label):
    """Flat filled button with hover effect."""
    def __init__(self, parent, text, command=None, primary=True,
                 danger=False, small=False, **kw):
        if danger:
            bg, fg, hov = C["error"],   C["text"],  "#ff6961"
        elif primary:
            bg, fg, hov = C["accent"],  C["text"],  "#5ba3e8"
        else:
            bg, fg, hov = C["surface2"], C["text2"], C["surface3"]

        font = F["small"] if small else F["body_b"]
        padx = 12 if small else 20
        pady = 5  if small else 9

        super().__init__(parent, text=text, font=font,
                         bg=bg, fg=fg, cursor="hand2",
                         padx=padx, pady=pady, **kw)
        self._cmd = command
        self._bg = bg; self._hov = hov; self._fg = fg
        self.config(takefocus=1)
        self.bind("<Button-1>", lambda e: command() if command else None)
        self.bind("<Return>",   lambda e: (command() if command else None))
        self.bind("<space>",    lambda e: (command() if command else None))
        self.bind("<Enter>",    lambda e: self.config(bg=hov))
        self.bind("<Leave>",    lambda e: self.config(bg=bg))
        self.bind("<FocusIn>",  lambda e: self.config(highlightbackground=C["accent"],
                                                       highlightthickness=1))
        self.bind("<FocusOut>", lambda e: self.config(highlightbackground=bg,
                                                       highlightthickness=0))

    def enable(self, on=True):
        self._enabled = on
        if on:
            self.config(fg=self._fg, cursor="hand2", bg=self._bg, takefocus=1)
            self.bind("<Button-1>", lambda e: self._cmd() if self._cmd else None)
            self.bind("<Return>",   lambda e: (self._cmd() if self._cmd else None))
            self.bind("<space>",    lambda e: (self._cmd() if self._cmd else None))
            self.bind("<Enter>",    lambda e: self.config(bg=self._hov))
            self.bind("<Leave>",    lambda e: self.config(bg=self._bg))
            self.bind("<FocusIn>",  lambda e: self.config(highlightbackground=C["accent"],
                                                           highlightthickness=1))
            self.bind("<FocusOut>", lambda e: self.config(highlightbackground=self._bg,
                                                           highlightthickness=0))
            # If mouse is already over the button, apply hover colour immediately
            try:
                x, y = self.winfo_pointerxy()
                wx, wy = self.winfo_rootx(), self.winfo_rooty()
                ww, wh = self.winfo_width(), self.winfo_height()
                if wx <= x <= wx + ww and wy <= y <= wy + wh:
                    self.config(bg=self._hov)
            except Exception:
                pass
        else:
            # Fix 29: use 'arrow' explicitly — cursor='' may inherit from parent
            self.config(fg=C["text3"], cursor="arrow", bg=C["surface2"], takefocus=0,
                        highlightthickness=0)
            self.bind("<Button-1>", lambda e: None)
            self.bind("<Return>",   lambda e: None)
            self.bind("<space>",    lambda e: None)
            self.bind("<Enter>",    lambda e: None)
            self.bind("<Leave>",    lambda e: None)
            self.bind("<FocusIn>",  lambda e: None)  # suppress ring on disabled btn
            self.bind("<FocusOut>", lambda e: None)


class SegmentedControl(tk.Frame):
    """Pill-style mode toggle with keyboard navigation."""
    def __init__(self, parent, options, variable, **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"],
                         highlightthickness=1, **kw)
        self._var = variable
        self._opt_vals = [val for val, _ in options]
        self._labels = {}
        for i, (val, text) in enumerate(options):
            lbl = tk.Label(self, text=text, font=F["body_b"],
                           padx=0, pady=10, cursor="hand2")
            lbl.grid(row=0, column=i, sticky="nsew")
            self.columnconfigure(i, weight=1)
            lbl.bind("<Button-1>", lambda e, v=val: variable.set(v))
            self._labels[val] = lbl
        variable.trace_add("write", lambda *_: self._refresh())
        self._refresh()

        # Keyboard: Tab focuses the control, Left/Right arrows switch options
        self.config(takefocus=True)
        self.bind("<FocusIn>",  lambda e: self.config(highlightbackground=C["accent"], highlightthickness=2))
        self.bind("<FocusOut>", lambda e: self.config(highlightbackground=C["border"], highlightthickness=1))
        self.bind("<Left>",  lambda e: self._step(-1))
        self.bind("<Right>", lambda e: self._step(1))
        self.bind("<Return>", lambda e: None)  # absorb so form doesn't submit on focus

    def _step(self, direction):
        opts = self._opt_vals
        try:
            idx = opts.index(self._var.get())
        except ValueError:
            idx = 0
        self._var.set(opts[(idx + direction) % len(opts)])

    def _refresh(self):
        v = self._var.get()
        for val, lbl in self._labels.items():
            lbl.config(bg=C["accent"] if val==v else C["surface"],
                       fg=C["text"]   if val==v else C["text3"])


class StagedProgressBar(tk.Frame):
    """
    A real progress bar that tracks named stages.
    Shows: [=====>      ] Stage name  2.1s / ~3.5s
    """
    def __init__(self, parent, stages, **kw):
        """
        stages: list of (name, weight) tuples, weights relative (sum = 1.0)
        """
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"],
                         highlightthickness=1, **kw)
        self._stages    = stages          # [(name, weight), ...]
        self._current   = -1
        self._pct       = 0.0             # 0.0 – 1.0
        self._start_t   = None
        self._stage_t   = None
        self._total_est = None
        self._running   = False
        self._pulse_base = None  # G-C: base label text for animated dot pulse
        self._pulse_job  = None  # G-C: pending after() id for pulse
        self._stage_pcts = self._build_stage_pcts()

        # Stage name label
        self._stage_lbl = tk.Label(self, text="", font=F["body_b"],
                                   bg=C["surface"], fg=C["text"])
        self._stage_lbl.pack(anchor="w", padx=16, pady=(12, 4))

        # Progress bar canvas
        self._bar_cv = tk.Canvas(self, height=6, bg=C["surface2"],
                                  highlightthickness=0)
        self._bar_cv.pack(fill="x", padx=16, pady=(0, 6))
        self._bar_cv.bind("<Configure>", lambda e: self._draw_bar())

        # Bottom row: stage progress + time
        bottom = tk.Frame(self, bg=C["surface"])
        bottom.pack(fill="x", padx=16, pady=(0, 12))

        self._pct_lbl  = tk.Label(bottom, text="", font=F["caption"],
                                   bg=C["surface"], fg=C["text2"])
        self._pct_lbl.pack(side="left")

        self._time_lbl = tk.Label(bottom, text="", font=F["caption"],
                                   bg=C["surface"], fg=C["text3"])
        self._time_lbl.pack(side="right")

        # Stage dots row
        self._dots_frame = tk.Frame(self, bg=C["surface"])
        self._dots_frame.pack(fill="x", padx=16, pady=(0, 14))
        self._dot_cvs = []
        self._connector_cvs = []  # UX-4: dynamic colour connectors
        for i, (name, _) in enumerate(stages):
            cv = tk.Canvas(self._dots_frame, width=8, height=8,
                           bg=C["surface"], bd=0, highlightthickness=0)
            cv.pack(side="left", padx=(0, 4))
            self._dot_cvs.append(cv)
            if i < len(stages) - 1:
                # UX-4: use Canvas so colour can be updated as stages complete
                con = tk.Canvas(self._dots_frame, width=20, height=2,
                                bg=C["border"], bd=0, highlightthickness=0)
                con.pack(side="left", pady=3)
                self._connector_cvs.append(con)

        self._draw_dots()

    def _build_stage_pcts(self):
        """Pre-compute cumulative percentage at start of each stage."""
        total = sum(w for _, w in self._stages)
        pcts = []
        acc = 0.0
        for _, w in self._stages:
            pcts.append(acc / total)
            acc += w
        return pcts

    def start(self):
        self._start_t = time.time()
        self._stage_t = time.time()
        self._running = True
        # Fix 19: reset all visual state so a second operation doesn't inherit stale
        # "Complete" label/colours from a previous run
        self._current  = -1
        self._pct      = 0.0
        self._stage_lbl.config(text="Starting…", fg=C["text"])
        self._pct_lbl.config(text="0%", fg=C["text2"])
        self._time_lbl.config(text="", fg=C["text3"])
        self._draw_bar()
        self._draw_dots()
        self._update_time()

    def advance(self, stage_idx, stage_name=None):
        """Called when a new stage begins."""
        self._current  = stage_idx
        self._stage_t  = time.time()
        name = stage_name or (self._stages[stage_idx][0] if stage_idx < len(self._stages) else "")
        self._stage_lbl.config(text=name)
        self._pulse_base = name  # G-C: base text for animated dots
        self._pct = self._stage_pcts[stage_idx] if stage_idx < len(self._stage_pcts) else 1.0
        self._draw_bar()
        self._draw_dots()
        self._update_time()
        self._pulse_tick(0)      # G-C: start/restart dot-pulse for this stage

    def stop(self):
        """Halt the timer loop without marking as complete (used on failure/reset)."""
        self._running = False
        self._pulse_base = None  # G-C: stop pulse loop

    def complete(self):
        self._pct = 1.0
        self._running = False
        self._pulse_base = None  # G-C: stop pulse loop
        elapsed = time.time() - self._start_t if self._start_t else 0
        self._stage_lbl.config(text="Complete", fg=C["success"])
        self._pct_lbl.config(text="100%", fg=C["success"])
        self._time_lbl.config(text=f"{elapsed:.1f}s", fg=C["success"])
        self._draw_bar(complete=True)
        self._draw_dots(complete=True)

    def _draw_bar(self, complete=False):
        self._bar_cv.update_idletasks()
        w = self._bar_cv.winfo_width()
        if w < 2: return
        self._bar_cv.delete("all")
        # Background
        self._bar_cv.create_rectangle(0, 0, w, 6, fill=C["surface2"], outline="")
        # Fill
        fill_w = int(w * self._pct)
        if fill_w > 0:
            col = C["success"] if complete else C["accent"]
            self._bar_cv.create_rectangle(0, 0, fill_w, 6, fill=col, outline="")

    def _draw_dots(self, complete=False):
        for i, cv in enumerate(self._dot_cvs):
            cv.delete("all")
            if complete or i < self._current:
                col = C["success"]
            elif i == self._current:
                col = C["accent"]
            else:
                col = C["surface3"]
            cv.create_oval(0, 0, 8, 8, fill=col, outline="")
        # UX-4: update connector colour — green when left stage is done
        for i, con in enumerate(self._connector_cvs):
            done = complete or i < self._current
            con.config(bg=C["success"] if done else C["border"])

    def _update_time(self):
        if not self._running or not self._start_t: return
        elapsed = time.time() - self._start_t
        pct = self._pct
        if pct > 0.01:
            est_total = elapsed / pct
            remaining = max(0, est_total - elapsed)
            self._pct_lbl.config(text=f"{int(pct*100)}%")
            if remaining > 0.5:
                self._time_lbl.config(text=f"~{remaining:.0f}s left")
            else:
                self._time_lbl.config(text="almost done...")
        else:
            self._pct_lbl.config(text="0%")
            self._time_lbl.config(text="calculating...")
        if self._running and pct < 1.0:
            self.after(250, self._update_time)


    def _pulse_tick(self, dot_count):
        """G-C: Animate a cycling '…' suffix on the stage label when there is no
        sub-progress to display (pct == 0, e.g. during the Argon2id KDF stage).
        Stops automatically when _pulse_base is cleared by advance/stop/complete."""
        if self._pulse_base is None: return          # stopped
        if self._pct > 0.01:                         # real progress arrived — stop pulse
            self._stage_lbl.config(text=self._pulse_base)
            return
        dots = "." * ((dot_count % 3) + 1)
        try:
            self._stage_lbl.config(text=self._pulse_base.rstrip(".… ") + dots)
        except Exception:
            pass
        self._pulse_job = self.after(450, self._pulse_tick, dot_count + 1)


class PasswordStrengthBar(tk.Frame):
    """Live password strength estimator using zxcvbn for realistic scoring."""
    _LABELS = ["Very Weak", "Weak", "Fair", "Good", "Strong"]

    def __init__(self, parent, entry_var, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        self._var = entry_var

        bar_row = tk.Frame(self, bg=C["bg"])
        bar_row.pack(fill="x")

        self._bar_cv = tk.Canvas(bar_row, height=3, bg=C["surface2"],
                                  highlightthickness=0)
        self._bar_cv.pack(side="left", fill="x", expand=True)
        self._bar_cv.bind("<Configure>", lambda e: self._schedule_refresh())

        self._lbl = tk.Label(bar_row, text="", font=F["small"],
                              bg=C["bg"], fg=C["text3"], width=8, anchor="e")
        self._lbl.pack(side="left", padx=(8,0))

        self._tip = tk.Label(self, text=" ", font=F["small"],  # pre-allocated height
                              bg=C["bg"], fg=C["text3"], anchor="w",
                              wraplength=400, justify="left")
        self._tip.pack(fill="x", pady=(2,0))

        self._refresh_job = None  # UX-9: debounce handle
        entry_var.trace_add("write", lambda *_: self._schedule_refresh())

    def _schedule_refresh(self):
        """UX-9: debounce — run zxcvbn 150 ms after last keystroke."""
        if self._refresh_job is not None:
            try: self.after_cancel(self._refresh_job)
            except Exception: pass
        self._refresh_job = self.after(150, self._refresh)

    def _score(self, pw):
        if not pw: return 0, "", ""
        if _zxcvbn_fn is not None:
            r = _zxcvbn_fn(pw)
            score = r["score"]  # 0-4
            fb = r.get("feedback", {})
            tips = []
            if fb.get("warning"): tips.append(fb["warning"])
            tips.extend(fb.get("suggestions", [])[:1])
            tip = tips[0] if tips else ""
            return score, self._LABELS[score], tip
        else:
            # Fallback entropy estimator when zxcvbn is not installed
            import math, re
            pool = sum([26 if re.search(p, pw) else 0
                        for p in [r'[a-z]', r'[A-Z]']] +
                       [10 if re.search(r'[0-9]', pw) else 0,
                        32 if re.search(r'[^a-zA-Z0-9]', pw) else 0])
            e = len(pw) * math.log2(pool) if pool else 0
            s = 1 if e < 28 else 2 if e < 36 else 3 if e < 60 else 4
            return s, self._LABELS[s], ""

    def _refresh(self):
        pw = self._var.get()
        score, label, tip = self._score(pw)
        colors = [C["error"], C["error"], C["warning"], C["accent"], C["success"]]
        pct    = score / 4
        color  = colors[score] if pw else C["surface3"]

        self._lbl.config(text=label, fg=color)
        self._tip.config(text=tip)
        self._bar_cv.update_idletasks()
        w = self._bar_cv.winfo_width()
        if w < 2: return
        self._bar_cv.delete("all")
        self._bar_cv.create_rectangle(0, 0, w, 3, fill=C["surface2"], outline="")
        fill = int(w * pct)
        if fill > 0:
            self._bar_cv.create_rectangle(0, 0, fill, 3, fill=color, outline="")


class FileCard(tk.Frame):
    """A1: Consolidated drop-zone / file picker used by both encryptor and decryptor.
    
    Parameters
    ----------
    parent      : tk widget
    on_select   : callable(path) — fired when a file is chosen
    prompt      : str  — headline text before selection
    sub         : str  — subtext / accepted types hint
    filetypes   : list of (label, pattern) for the file dialog
    """

    def __init__(self, parent, on_select, *,
                 prompt="Select a file",
                 sub="Click anywhere in this box",
                 filetypes=None,
                 **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"], highlightthickness=1,
                         cursor="hand2", **kw)
        self._cb        = on_select
        self._selected  = False
        self._filetypes = filetypes or [("All files", "*")]

        self._icon  = tk.Label(self, text="+", font=(UI, 26, "bold"),
                                bg=C["surface"], fg=C["surface3"])
        self._icon.pack(pady=(20, 4))
        self._line1 = tk.Label(self, text=prompt,
                                font=F["body_b"], bg=C["surface"], fg=C["text3"])
        self._line1.pack()
        self._line2 = tk.Label(self, text=sub,
                                font=F["caption"], bg=C["surface"], fg=C["text3"])
        self._line2.pack(pady=(2, 20))

        for w in [self, self._icon, self._line1, self._line2]:
            w.bind("<Button-1>", lambda e: self._pick())
        # UX-13: bind hover only on self (Frame) to avoid flicker when cursor
        # crosses child label boundaries (each child fires its own Enter/Leave)
        self.bind("<Enter>", lambda e: self._hl(True))
        self.bind("<Leave>", lambda e: self._hl(False))

        # Keyboard accessibility: Tab can focus the card, Enter/Space activates it
        self.config(takefocus=True)
        self.bind("<Return>", lambda e: self._pick())
        self.bind("<space>",  lambda e: self._pick())
        self.bind("<FocusIn>",  lambda e: self.config(
            highlightbackground=C["accent"],
            highlightthickness=2))
        self.bind("<FocusOut>", lambda e: self.config(
            highlightbackground=C["success"] if self._selected else C["border"],
            highlightthickness=1))

    def _pick(self):
        from tkinter import filedialog
        if getattr(self, "_is_folder_mode", False):
            p = filedialog.askdirectory()
            if p and hasattr(self._cb, "__self__"):
                # The encryptor wires _on_folder separately — call it if available
                owner = self._cb.__self__
                if hasattr(owner, "_on_folder"):
                    owner._on_folder(p)
                    return
            # Fallback: treat folder path like a file path
            if p:
                self._cb(p)
        else:
            import os as _os
            p = filedialog.askopenfilename(
                filetypes=self._filetypes,
                initialdir=_os.path.expanduser("~"))
            if p:
                self.load(p)
                self._cb(p)

    def load(self, path):
        """Pre-populate card (used when app is launched with a file argument)."""
        self._selected = True
        self._icon.config(text="✓", fg=C["success"])
        self._line1.config(text=os.path.basename(path), fg=C["text"], font=F["body_b"])
        try:
            size_str = fmt_size(os.path.getsize(path))
        except OSError:
            size_str = "unknown size"
        self._line2.config(text=f"{size_str}  ·  Click to change",
                           fg=C["accent"])
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=C["surface"])

    def reset(self, prompt, sub):
        """Restore to unselected state (used by _reset flows)."""
        self._selected = False
        self._icon.config(text="+", fg=C["surface3"])
        self._line1.config(text=prompt, fg=C["text3"], font=F["body_b"])
        self._line2.config(text=sub,    fg=C["text3"])
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=C["surface"])

    def _hl(self, on):
        if self._selected: return
        col = C["surface2"] if on else C["surface"]
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=col)


class WizardSteps(tk.Canvas):
    """Horizontal step tracker. Steps: list of names. Active = current step."""
    def __init__(self, parent, steps, **kw):
        nsteps = len(steps)
        super().__init__(parent, width=nsteps*100, height=44,
                         bg=C["bg"], bd=0, highlightthickness=0, **kw)
        self._steps  = steps
        self._active = 0
        self._min_w  = nsteps * 100  # renamed: self._w is reserved by Tkinter for widget path
        self.config(takefocus=0)  # UX-L13: informational only — skip in Tab order
        self.bind("<Configure>", lambda e: self._draw())
        self._draw()

    def set_step(self, n):
        self._active = n
        self._draw()

    def _draw(self):
        self.delete("all")
        n  = len(self._steps)
        self.update_idletasks()
        w  = max(self.winfo_width(), self._min_w)
        sw = w // n
        cy = 22
        r  = 10

        for i, name in enumerate(self._steps):
            cx     = i * sw + sw // 2
            # When _active is set past the last step index, all steps are "done"
            done   = i < self._active
            active = i == self._active

            # Connector line
            if i < n - 1:
                lx = cx + r + 4
                rx = (i+1) * sw + sw//2 - r - 4
                self.create_line(lx, cy, rx, cy,
                                 fill=C["success"] if done else C["border"], width=1)

            # Circle — Fix 20: done circles use success green (matches connectors)
            if done:
                self.create_oval(cx-r, cy-r, cx+r, cy+r,
                                  fill=C["success"], outline="")
                self.create_text(cx, cy, text="✓", font=F["small"],
                                  fill=C["text"])
            elif active:
                self.create_oval(cx-r, cy-r, cx+r, cy+r,
                                  fill=C["accent"], outline="")
                self.create_text(cx, cy, text=str(i+1), font=F["small"],
                                  fill=C["text"])
            else:
                self.create_oval(cx-r, cy-r, cx+r, cy+r,
                                  fill=C["surface2"], outline=C["border"], width=1)
                self.create_text(cx, cy, text=str(i+1), font=F["small"],
                                  fill=C["text3"])

            # Label below — truncate if too wide for its slot
            max_chars = max(6, sw // 8)
            label_text = name if len(name) <= max_chars else name[:max_chars-1] + "…"
            self.create_text(cx, cy+r+8, text=label_text, font=F["small"],
                              fill=C["success"] if done else
                              (C["accent"] if active else C["text3"]))


class ClipboardTimer:
    """Auto-clears the clipboard after `seconds` and shows a countdown label.
    
    Usage:
        timer = ClipboardTimer(widget, label_widget, seconds=60)
        timer.start()     # call after clipboard_append()
        timer.cancel()    # call if the user manually clears or copies something else
    
    The label_widget text is updated every second: "Clipboard clears in 42s"
    When the timer fires, the clipboard is cleared and the label reset.
    """
    _SECS = 60

    def __init__(self, root, label, seconds=60):
        self._root   = root    # any Tk widget with after()/clipboard_clear()
        self._label  = label
        self._secs   = seconds
        self._job    = None
        self._remain = 0

    def start(self):
        self.cancel()
        self._remain = self._secs
        self._tick()

    def cancel(self):
        if self._job is not None:
            try: self._root.after_cancel(self._job)
            except Exception: pass
            self._job = None
        self._remain = 0
        try:
            if self._label.winfo_exists():
                self._label.config(text="")
        except Exception: pass

    def _tick(self):
        if self._remain <= 0:
            self._clear()
            return
        try:
            if self._label.winfo_exists():
                self._label.config(text=f"Clipboard clears in {self._remain}s", fg=C["text3"])
        except Exception:
            return
        self._remain -= 1
        self._job = self._root.after(1000, self._tick)

    def _clear(self):
        self._job = None
        try: self._root.clipboard_clear()
        except Exception: pass
        try:
            if self._label.winfo_exists():
                self._label.config(text="Clipboard cleared ✓", fg=C["success"])
                self._root.after(2000, lambda: (
                    self._label.config(text="") if self._label.winfo_exists() else None))
        except Exception: pass


class RecentFiles:
    """Persist recently used .qcx files between sessions.

    Pure-classmethods API so callers don't need to instantiate; the storage
    path is a class attribute (``_PATH``) making it trivial to monkeypatch
    in tests.

    ``load()`` returns a list of (path, meta_dict) tuples ordered most-recent
    first, filtered to files that still exist on disk.

    ``add(path, meta=None)`` inserts/bumps an entry and persists immediately.
    ``remove(path)`` removes a single entry.
    ``clear()`` wipes the list.
    """
    MAX_ITEMS = 10
    _PATH: str = ""   # resolved lazily so tests can monkeypatch before first use

    # ── Internal helpers ──────────────────────────────────────────────────────

    @classmethod
    def _resolve_path(cls):
        if cls._PATH:
            return cls._PATH
        base = os.path.expanduser("~/Library/Application Support")
        d = os.path.join(base, "QuantaCrypt")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "recent.json")

    @classmethod
    def _read_raw(cls):
        import json
        try:
            with open(cls._resolve_path()) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        return []

    @classmethod
    def _write_raw(cls, entries):
        import json
        try:
            with open(cls._resolve_path(), "w") as f:
                json.dump(entries, f, indent=2)
        except Exception:
            pass

    # ── Public API ────────────────────────────────────────────────────────────

    @classmethod
    def load(cls):
        """Return list of (path, meta_dict) tuples, newest first, existing only."""
        raw = cls._read_raw()
        valid = [(e["path"], e) for e in raw
                 if isinstance(e, dict) and os.path.isfile(e.get("path", ""))]
        # Persist filtered list if anything was trimmed
        if len(valid) != len(raw):
            cls._write_raw([e for _, e in valid])
        return valid

    @classmethod
    def add(cls, path, meta=None):
        """Insert path at front, deduplicate, trim to MAX_ITEMS, save."""
        import time
        raw = cls._read_raw()
        raw = [e for e in raw if isinstance(e, dict) and e.get("path") != path]
        entry = {"path": path, "ts": time.time()}
        if meta:
            entry["mode"]      = meta.get("mode", "single")
            entry["threshold"] = meta.get("threshold", 0)
            entry["total"]     = meta.get("total", 0)
        raw.insert(0, entry)
        cls._write_raw(raw[:cls.MAX_ITEMS])

    @classmethod
    def remove(cls, path):
        raw = [e for e in cls._read_raw() if isinstance(e, dict) and e.get("path") != path]
        cls._write_raw(raw)

    @classmethod
    def clear(cls):
        cls._write_raw([])
