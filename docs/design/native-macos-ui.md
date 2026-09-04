# Native macOS UI — options and recommendation

Date: 2026-09-02. Status: **implemented** — steps 1–3 of the staged plan below.
Shipped in `e9bcba7` (the `qc-core` service, the SwiftUI shell, the bundled
helper), with `d2042b7` (native-shell review fixes and the 2026-09 UI audit)
and `0a080be` (render the `.icns` files before the shell build) following. It is
built by `scripts/build.py --native`, by the `macos-shell` job in `ci.yml` and by
`build-native` in `release.yml`. Step 4 — parity, then deleting
`src/quantacrypt/ui/` — is still open, so the Tkinter app remains the shipped UI.

## Problem

QuantaCrypt's UI is Tkinter with a hand-painted dark design system. After the
2026-09 audit it is coherent and usable, but it will never read as a *macOS*
app: no system toolbar or sidebar, no menu-bar-driven commands, no sheets,
no SF Symbols, no materials, no system accent colour, dark-only regardless of
the user's appearance setting, and no Liquid Glass. The question is what a
"modern macOS app following proper standards" requires in 2026 and whether
that forces a move to Swift.

Environment verified on this machine: macOS 26.6 (Tahoe), Xcode 26.1.1,
Swift 6.2.1. The venv's Python 3.14 and the CI's python.org 3.13.2 both
bundle **Tcl/Tk 8.6.17** — not Tk 9.

## What "modern macOS app" means (macOS 26, from the HIG and the Liquid Glass adoption guide)

Checklist an app is judged against today:

1. **Standard window** with system frame, unified toolbar, arbitrary resizing,
   rounder corners; one primary window plus auxiliary windows for tasks.
   Never custom window chrome. Title is the content, not the app name.
2. **Sidebar navigation** (split view) for top-level areas — here: Encrypt,
   Decrypt, Volumes — with the content layer distinct from the navigation
   layer. Liquid Glass applies to that navigation layer automatically when
   you use system components.
3. **Toolbar** of SF Symbols in logical groups, at most one `.prominent`
   action on the trailing side, no custom toolbar backgrounds or tints.
4. **Menu bar** carrying every command with its shortcut (File / Edit / View
   / Window / Help), an About panel, and a Settings window on ⌘,.
5. **System semantics**: system font (SF), semantic colours, the user's
   accent colour, automatic light/dark, vibrancy and materials, and respect
   for Reduce Transparency / Reduce Motion / Increase Contrast.
6. **Sheets attached to the window** for confirmations and short tasks;
   `NSAlert`-style alerts; native open/save panels; system drag-and-drop
   highlighting.
7. **Grouped forms** with title-case section headers, standard control sizes
   and spacing (metrics changed under Liquid Glass; don't hard-code them).
8. **Layered app icon** built in Icon Composer (light / dark / clear / tinted
   variants).
9. Platform integration that a security utility is expected to have: Touch
   ID for unlock (LocalAuthentication), Finder Quick Actions / Services
   ("Encrypt with QuantaCrypt"), user notifications, document types (already
   done).

Liquid Glass and the new control metrics appear **only for binaries built
against the macOS 26 SDK**; an app linked against an older SDK keeps the
pre-Tahoe look (that is the documented `UIDesignRequiresCompatibility`
behaviour). This matters for every Python option below.

## Options

| | Approach | Reaches the checklist? | Effort | Risk |
|---|---|---|---|---|
| A | Keep Tk, keep polishing | No. 8.6 Aqua has no toolbar, sidebar, sheets, symbols, materials, or dark-mode ttk. Ceiling reached with the audit. | 0 | Reads as a cross-platform toolkit app forever |
| B | Tk + PyObjC for extras (Touch ID, Services, native menu bar) | Marginal: the window body stays Tk. | Small | Two UI worlds in one window |
| C | Rewrite the UI in **PyObjC / AppKit** (Python, no Swift) | Mostly. `NSToolbar`, `NSSplitViewController` sidebar, SF Symbols, sheets, materials are all reachable from Python. | Large: ~6k lines of Tk → programmatic AppKit with manual Auto Layout; sparse docs (per the appkitgui write-up) | Liquid Glass depends on the **main executable's linked SDK** — the PyInstaller bootloader and python.org framework are built against old SDKs, so the app may render the legacy look unless the bootloader is rebuilt with Xcode 26. Unverified. |
| D | **BeeWare Toga** (AppKit via rubicon-objc, 0.5.6) | Partly. Native controls, but a generic cross-platform widget set: no toolbar customisation, no split-view sidebar, no SF Symbols API, no sheets. | Medium | Ends up looking like a plain AppKit form, not a Tahoe app; same SDK caveat as C |
| E | **SwiftUI shell + Python core** (embedded via `Python.xcframework`/PythonKit, or the core as a helper process) | Yes, all nine items, and Liquid Glass comes free from Xcode 26. | Medium-large: new Xcode target, JSON protocol around the existing core, ~3–4k lines of Swift | Two languages; progress/cancel cross the boundary; ~100 MB bundle if Python is embedded |
| F | Full Swift rewrite incl. crypto | Yes | Very large | Loses the 534-test / 95% core; Argon2id and Shamir have no first-party Swift; `.qcx` compatibility risk. CryptoKit does now expose ML-KEM-768 (WWDC25), but that is one of four primitives. |

## Recommendation: E, staged

**You do not strictly need Swift** — option C proves AppKit is drivable from
Python. But for a *modern* (Tahoe-era) app, Swift/SwiftUI is the practical
answer: the new appearance is granted by the build toolchain, not by the
framework you call, and the PyObjC route is more code for a worse and less
certain result. Alex already maintains a 128-file / 32k-line SwiftUI macOS
client (`stock-trader-automator/clients/macos`) that talks to a Python
daemon over `URLSession`, so the language and the architecture are both
known quantities.

Keep the Python core exactly where it is. Its crypto, the `.qcx`/`.qcv`
formats, FUSE, and the test suite are the asset; the Tk UI is the liability.

### Staged plan (strangler fig)

1. **Core as a service** — add `quantacrypt.cli` (or `qc-core`): one process,
   JSON-lines over stdin/stdout, commands `encrypt`, `decrypt`, `verify`,
   `inspect`, `volume create|mount|unmount|list`, streaming progress events,
   cancellation on SIGINT/EOF. Pure Python, unit-tested, no Tk import. The
   existing UI can switch to it too. This step is valuable on its own.
2. **Xcode target `QuantaCrypt.app`** — SwiftUI, `NavigationSplitView`
   sidebar (Encrypt / Decrypt / Volumes), toolbar with one prominent action
   per screen, Settings scene, full `.commands` menu, sheets for the
   Shamir share step and confirmations, `SecureField`, drag-and-drop,
   Touch ID for volume unlock, Icon Composer icon.
3. **Bundle the core** — simplest: PyInstaller-onefile `qc-core` copied into
   `Contents/Helpers/`, launched as a subprocess (same pattern as the trading
   client). Embedding via `Python.xcframework` is the alternative if a
   single signed binary matters more than bundle size.
4. **Parity, then delete** — ship both UIs behind `--classic` until the Swift
   app covers the four journeys; then remove `src/quantacrypt/ui/` and the
   Tk-specific build steps. Notarization moves to the standard Xcode path,
   which also unblocks the long-standing notarization TODO.

### What changes for the build/CI

- `scripts/build.py` shrinks to building the helper; the app is built by
  `xcodebuild` on the macOS runner (already macOS).
- Cross-platform ambitions (Linux .deb, Windows) are unaffected: the core
  stays portable; only the Mac shell is Swift.

## Not chosen, and why

- **C (PyObjC)** if avoiding Swift were a hard constraint: acceptable native
  result, but the Liquid Glass/SDK question would need a spike (rebuild the
  PyInstaller bootloader with Xcode 26 and confirm `NSToolbar` renders the
  Tahoe style) before committing.
- **D (Toga)** is the right tool for a cross-platform GUI that must be one
  codebase; it is not a way to a first-class Mac app.

## Sources

- HIG: Designing for macOS, Windows, Toolbars — developer.apple.com/design/human-interface-guidelines/{designing-for-macos,windows,toolbars}
- Adopting Liquid Glass — developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass
- WWDC25 219 "Meet Liquid Glass", 356 "Get to know the new design system", 310 "Build an AppKit app with the new design"
- Tcl/Tk 9.0 release notes (dark-mode ttk, semantic colours) — tcl-lang.org/software/tcltk/9.0.html; CPython issue #124111 (3.13 → Tk 8.6.x, 3.14 → Tk 9.0.4 upstream; python.org 3.13.2/3.14.0 installers here report 8.6.17)
- PyObjC programmatic AppKit example — github.com/RhetTbull/appkitgui
- Toga macOS backend (toga-cocoa via rubicon-objc) — toga.beeware.org/en/stable/reference/platforms/macOS/
- Embedding Python in a Mac app: PythonKit (github.com/pvieito/PythonKit), Python-Apple-support (github.com/beeware/Python-Apple-support), App Store-published example (medium.com/swift2go/embedding-python-interpreter-inside-a-macos-app-and-publish-to-app-store-successfully-309be9fb96a5)
