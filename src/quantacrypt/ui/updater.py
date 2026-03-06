"""Background update checker — queries GitHub Releases API.

Usage from the launcher:

    from quantacrypt.ui.updater import check_for_update
    check_for_update(parent_widget, current_version)

The check runs in a daemon thread so the UI is never blocked.  If a newer
release is found, a small banner is inserted into *parent_widget* with a
clickable link to the release page.  If the check fails (no network, API
error, etc.) it silently does nothing — the user should never be bothered
by update-check failures.
"""

import json
import threading
import tkinter as tk
import urllib.request
import webbrowser
from typing import Optional, Tuple

from quantacrypt.ui.shared import C, F

_REPO = "alexboccard/QuantaCrypt"
_API_URL = f"https://api.github.com/repos/{_REPO}/releases/latest"
_TIMEOUT = 5  # seconds


def _parse_version(tag: str) -> Tuple[int, ...]:
    """Turn 'v1.2.3' or '1.2.3-beta' into a comparable tuple (1, 2, 3)."""
    tag = tag.lstrip("vV")
    # Strip any pre-release suffix (e.g. '-beta', '-rc1')
    tag = tag.split("-")[0]
    parts = []
    for p in tag.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) or (0,)


def _fetch_latest() -> Optional[dict]:
    """Query GitHub for the latest release.  Returns None on any error."""
    try:
        req = urllib.request.Request(
            _API_URL,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "QuantaCrypt-UpdateCheck"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def check_for_update(parent: "tk.Toplevel", current_version: str) -> None:
    """Spawn a background thread to check for updates.

    If a newer version is found, schedule a banner to be added to *parent*
    on the main thread via ``after()``.  The banner shows the new version
    and a clickable link to the release page.
    """

    def _worker():
        data = _fetch_latest()
        if not data:
            return

        tag = data.get("tag_name", "")
        html_url = data.get("html_url", "")

        if not tag:
            return

        try:
            latest = _parse_version(tag)
            current = _parse_version(current_version)
        except Exception:
            return

        if latest <= current:
            return  # already up to date

        display_ver = tag.lstrip("vV")

        # Schedule the UI update on the main thread
        try:
            parent.after(0, _show_banner, parent, display_ver, html_url)
        except Exception:
            pass  # widget may have been destroyed

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _show_banner(parent: "tk.Toplevel", version: str, url: str) -> None:
    """Insert a subtle update banner near the top of the parent widget."""
    banner = tk.Frame(parent, bg=C["surface"], highlightbackground=C["accent"],
                      highlightthickness=1)
    # Pack after the first two children (logo section + divider) so the banner
    # appears near the top of the window rather than below the recent files list.
    children = parent.pack_slaves()
    if len(children) >= 2:
        banner.pack(fill="x", padx=32, pady=(0, 10), after=children[1])
    else:
        banner.pack(fill="x", padx=32, pady=(0, 10))

    inner = tk.Frame(banner, bg=C["surface"])
    inner.pack(fill="x", padx=12, pady=8)

    tk.Label(inner, text=f"Update available: v{version}",
             font=F["caption"], bg=C["surface"], fg=C["text2"]).pack(side="left")

    link = tk.Label(inner, text="Download", font=F["caption"],
                    bg=C["surface"], fg=C["accent"], cursor="hand2")
    link.pack(side="right")
    link.bind("<Button-1>", lambda e: webbrowser.open(url))
    link.bind("<Enter>", lambda e: link.config(font=(F["caption"][0], F["caption"][1], "underline")))
    link.bind("<Leave>", lambda e: link.config(font=F["caption"]))

    # Dismiss "x" button
    dismiss = tk.Label(inner, text="✕", font=F["small"],
                       bg=C["surface"], fg=C["text3"], cursor="hand2")
    dismiss.pack(side="right", padx=(0, 8))
    dismiss.bind("<Button-1>", lambda e: banner.destroy())

    # Re-centre the window after the banner changes its height
    try:
        parent.update_idletasks()
        sw, sh = parent.winfo_screenwidth(), parent.winfo_screenheight()
        w, h = parent.winfo_width(), parent.winfo_height()
        parent.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")
    except Exception:
        pass
