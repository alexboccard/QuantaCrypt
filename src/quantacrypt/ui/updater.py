"""Background update checker — queries GitHub Releases API.

Usage from the launcher:

    from quantacrypt.ui.updater import check_for_update
    check_for_update(parent_widget, current_version)

The check runs in a daemon thread so the UI is never blocked.  If a newer
release is found, a small banner is inserted into *parent_widget* with a
button that opens the release page.  If the check fails (no network, API
error, etc.) it silently does nothing — the user should never be bothered
by update-check failures.  Dismissing a release is remembered (``AppPrefs``)
so the same banner does not come back every launch.
"""

import json
import threading
import tkinter as tk
import urllib.request
import webbrowser
from typing import Optional, Tuple

from quantacrypt.ui.shared import C, F, SP, ICON, FlatButton, AppPrefs

_REPO = "alexboccard/QuantaCrypt"
_API_URL = f"https://api.github.com/repos/{_REPO}/releases/latest"
_TIMEOUT = 5  # seconds
_PREF_DISMISSED = "dismissed_update"


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

    If a newer version is found (and the user hasn't dismissed that exact
    release before), schedule a banner to be added to *parent* on the main
    thread via ``after()``.
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

        if AppPrefs.get(_PREF_DISMISSED) == tag:
            return  # the user already said "not this one"

        display_ver = tag.lstrip("vV")
        current_disp = current_version.lstrip("vV")

        # Schedule the UI update on the main thread
        try:
            parent.after(0, _show_banner, parent, display_ver, current_disp,
                         tag, html_url)
        except Exception:
            pass  # widget may have been destroyed

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _show_banner(parent: "tk.Toplevel", version: str, current: str,
                 tag: str, url: str) -> None:
    """Insert a subtle update banner near the top of the parent widget.

    Prefers a ``_banner_slot`` frame provided by the parent; otherwise packs
    after the parent's second child (logo section + divider)."""
    slot = getattr(parent, "_banner_slot", None)
    if slot is not None:
        banner = tk.Frame(slot, bg=C["surface"], highlightbackground=C["accent"],
                          highlightthickness=1)
        banner.pack(fill="x", pady=(0, SP["s"]))
    else:
        banner = tk.Frame(parent, bg=C["surface"], highlightbackground=C["accent"],
                          highlightthickness=1)
        children = parent.pack_slaves()
        if len(children) >= 2:
            banner.pack(fill="x", padx=SP["xxl"], pady=(0, SP["s"]), after=children[1])
        else:
            banner.pack(fill="x", padx=SP["xxl"], pady=(0, SP["s"]))

    inner = tk.Frame(banner, bg=C["surface"])
    inner.pack(fill="x", padx=SP["m"], pady=SP["s"])

    tk.Label(inner, text=f"Update available — v{version} (you have v{current})",
             font=F["caption"], bg=C["surface"], fg=C["text2"]).pack(side="left")

    def _dismiss():
        AppPrefs.set(_PREF_DISMISSED, tag)
        banner.destroy()

    FlatButton(inner, ICON["close"], _dismiss, primary=False, small=True).pack(
        side="right")
    FlatButton(inner, "See what's new", lambda: webbrowser.open(url),
               primary=False, small=True).pack(side="right", padx=(0, SP["s"]))
