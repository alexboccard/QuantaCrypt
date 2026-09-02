# UI audit — 2026-09-01

Review-mode audit of the Tkinter UI (`src/quantacrypt/ui/`). Method: interface
inventory → flow walkthrough of the four critical journeys (encrypt, decrypt,
create/mount a volume, launcher) → Nielsen heuristics → token/consistency greps
→ accessibility pass → visual pass on a real render of the launcher. Severity is
Nielsen 0–4 (4 = catastrophe, 3 = major, 2 = minor, 1 = cosmetic). Effort S/M/L.

**Scope.** All five UI modules, macOS as the primary platform, keyboard + pointer.
Out of scope: core crypto, FUSE, build.

**Coverage caveat.** Each wizard and the volume manager was walked once by an
independent reader; the launcher and design system were walked twice (code +
render). Every severity-3+ claim cited here was re-verified against the source. Single-pass
heuristic evaluation finds roughly a third of the problems present, so treat this
as a prioritised sample, not a census. Screenshots of the wizards were not
captured: `screencapture -R` succeeded once (launcher) then returned
"could not create image from rect" for every later call in this session.

**Verdict: incremental.** None of the five redesign triggers is evidenced. The
dark, flat register is coherent and the copy is already verb+object with zero
hits on the slop lexicon. The fixes are token-level (fonts, contrast, scale,
icons) plus flow-level (Escape, focus, progress labels, Shamir share step).

---

## 1. Executive summary

1. **Escape is a data-loss key.** In the decryptor, `WordEntry` binds Escape to
   close its autocomplete without returning `"break"`, so the event propagates to
   the Toplevel's Escape → `_close()` and the whole window (with up to k×50 typed
   words) disappears (`decryptor.py:150`, `:252`, `:583`). The encryptor and
   launcher also bind Escape to close/quit with no unsaved-input guard
   (`encryptor.py:265`, `launcher.py:61`); in standalone mode `_close` calls
   `master.destroy()` and quits the app.
2. **Every primary button fails contrast and has an invisible focus ring.**
   `#f5f5f7` on accent `#4a90d9` is 3.07:1 (needs 4.5 at 13 px); hover *lowers*
   it to 2.46:1. The focus ring is `highlightbackground=C["accent"]` on an
   accent-filled button — 1.03:1, i.e. not there (`shared.py:301-318`).
3. **Progress labels show the crypto layer's raw strings.** `_prog_cb` forwards
   messages like "Deriving 512-bit password key (Argon2id)..." and
   "Encapsulating + HKDF-SHA-512 expanding to 512 bits..." straight to the bar;
   the friendly `STAGES` names ("Securing password") are never displayed. Keyword
   order also means "Locking key" can never fire and two messages match nothing,
   so the bar freezes (`encryptor.py:95-114`, `:1206`; `decryptor.py:1150`).
4. **The Shamir share step is the riskiest flow and has four gaps.** "Decrypt
   now →" after a successful verify resets the form and asks for the credentials
   again (`decryptor.py:1386`); the decryptor has no way to load the
   `.share-N-of-M.txt` files the encryptor writes (`decryptor.py:896`); "Copy
   all" doesn't count as saved, so the leave-guard fires with no explanation
   (`encryptor.py:1388-1399`); the leave-guard itself is a generic Yes/No that
   never says the `.qcx` becomes unopenable (`encryptor.py:267-279`).
5. **The design system's fonts don't exist on macOS.** `UI="DejaVu Sans"` and
   `MONO="DejaVu Sans Mono"` both resolve to `.AppleSystemUIFont` (verified via
   `tkinter.font.families()`), so mnemonic grids, QCSHARE codes and paths are
   proportional on the primary platform and every `F` token is a silent
   fallback (`shared.py:34-35`).
6. **Volumes: the default mount point fails on macOS and the dangerous moments
   have no guard rails.** `/Volumes/<name>` cannot be created by a user process,
   and the failure surfaces as the generic "Access denied" text
   (`volume_manager.py:645`, `:742`). "Unmount" is one unconfirmed click on a live
   filesystem (`:935`), the `journal_suspicious` tamper warning is a one-button
   OK that tells the user to unmount but doesn't offer to (`:849-865`), and the
   create panel never says FUSE is missing until the volume already exists
   (`:399-419`). Nothing is focused on open and no `focus_set` exists in the
   file; the update banner's two controls are unfocusable Labels (`updater.py:115-126`).

---

## 2. Quick wins (high impact, S effort — ship first)

| # | Location | Finding | Sev | Fix |
|---|---|---|---|---|
| Q1 | `decryptor.py:150`, `:252` | Escape in `WordEntry`/listbox propagates to the window's Escape → closes the decryptor mid-entry | 4 | `return "break"` from both handlers |
| Q2 | `encryptor.py:1003`, `:1049` | Overwrite confirm has no `default="no"`; Return destroys an existing `.qcx`. Every other confirm on the screen gets it right | 3 | `default="no"` |
| Q3 | `encryptor.py:1206`, `decryptor.py:1150` | Raw crypto strings shown as stage label | 3 | Rebuild label as `STAGES[idx][0]` + captured `(\d+)%` |
| Q4 | `encryptor.py:95-114` | `_find_stage` matches "Kyber" before "private key"; "Encapsulating…" and "Generating … master key" match nothing | 2 | Order keywords most-specific first; add keywords for the two unmatched messages |
| Q5 | `shared.py:316-318` | Focus ring invisible on primary/danger buttons | 3 | Ring = `C["text"]` when bg is accent/error; thickness 2 |
| Q6 | `shared.py:20-24`, `:301-303` | Text-on-accent 3.07:1, hover 2.46:1; `text3` on `surface` 4.27:1 (card captions) | 3 | Accent → ~`#2f6fb8` (6.1:1 with `text`); hover darker not lighter (`accent_dim`); `text3` → `#9a9aa0` or use `text2` for captions |
| Q7 | `encryptor.py:1516`, `decryptor.py:1556` | Both `_fail`s hand-roll error mapping; neither imports `friendly_error` from `shared.py` and the vocabularies have diverged | 2 | Pass the exception object; render `friendly_error(exc)`; keep two mode-specific overrides |
| Q8 | `encryptor.py:951` | Empty Shamir spinbox → `IntVar.get()` raises `TclError` → Encrypt button becomes a silent no-op | 3 | try/except → "Enter a number between 2 and 20 for both fields" |
| Q9 | `launcher.py:50-56`, `:251` | App binds `<Command-v>` to open Volumes — ⌘V is Paste; hint also says "Ctrl+" on macOS | 2 | Use ⌘M (Mount) or ⌘⇧V; render ⌘ on darwin. Same for the wizards' Ctrl+O / Ctrl+↵ hints (`encryptor.py:470`, `decryptor.py:722`) |
| Q10 | `launcher.py:353-362` | Card hover recolours card + labels to `surface2`, which is the secondary button's bg → the button disappears into the hovered card | 2 | Include the button in `_bg_widgets` or hover to a distinct step |
| Q11 | `encryptor.py:1011`, `:1318` | `_freeze` sets `takefocus=0` on the just-pressed button and nothing focuses Cancel; `_done` rebuilds results and focuses nothing | 3 | `_cancel_btn.focus_set()` in `_start`; `after(50, save_btn.focus_set)` in `_done` |
| Q12 | `decryptor.py:1368` | Verify-only success marks the "Decrypt" step ✓ though nothing was written | 2 | `set_step(2)` |
| Q13 | `decryptor.py:1063`, `:1070` | Python list repr in copy: "Share(s) [1, 3] are empty" | 2 | `", ".join(...)` |
| Q14 | `encryptor.py:377` | Section heading stays "3 PASSWORD" in Shamir mode | 2 | Relabel to "3 SHARES" in `_on_mode` |
| Q15 | `encryptor.py:1504`, `decryptor.py:708` | Neutral status ("Cancelling…", "Busy…") rendered in error red | 2 | `fg` per message class |
| Q16 | `encryptor.py:1201`, `:1368`, `:1639` | "Open folder" vs "Show in folder" for the same `_reveal` action; decryptor uses "Show in folder" | 2 | One label |
| Q17 | `encryptor.py:359`, `decryptor.py:668` | FileCard always promises "or drag & drop" even when `tkinterdnd2` is absent | 2 | Append the phrase only when drop registration succeeded |
| Q18 | `launcher.py:279-317` | Recent-file rows are clickable but not focusable | 2 | `takefocus=1` + Return/space, mirror `_make_card` |
| Q19 | `launcher.py:405-475`, `decryptor.py:840-879` | Inspect dialogs `grab_set` with no Escape, no initial focus | 1 | Bind Escape, focus Close |
| Q20 | `launcher.py:243-247` | Two-line marketing sentence inside the launcher ("can only be opened with your password" — false for Shamir files) | 2 | Delete; merge version + shortcuts into one footer line |
| Q21 | `decryptor.py:1055`, `:1566` | Incomplete-share error points at a collapsed panel; Shamir failure never restores focus | 2 | Focus/expand the first bad input before showing the error |
| Q22 | `encryptor.py:306-319` | Drop in batch mode silently discards the batch and keeps only the first dropped path | 3 | Route through the same `askyesno` guard as the button; multi-drop → batch |
| Q23 | `encryptor.py:512-515` | Shamir "?" help is a Label with a click binding — not focusable | 2 | `FlatButton(..., small=True)` |
| Q24 | `encryptor.py:267-279` | Leave-guard copy: generic Yes/No, never says the file becomes unopenable | 3 | "Save the shares first — without them, `<file>.qcx` can never be opened again. Leave and discard the shares?" |
| Q25 | `volume_manager.py:645`, `:742-746` | Default mount point `/Volumes/<name>`; user processes can't create it on modern macOS; error is the generic "Access denied" | 4 | Default `~/QuantaCrypt Volumes/<name>` (already in TASKS); add a mount-point `PermissionError` branch naming the fix |
| Q26 | `volume_manager.py:935` | "Unmount" has no confirm; `danger=True` exists in `FlatButton` and is unused | 3 | `askyesno(... default="no")` naming the volume and "unsaved work in open files may be lost" |
| Q27 | `volume_manager.py:881`, `:879` | Unmount failure shows raw `fuse_ops` text with no next step; status caption not updated on failure, never expires | 3 | "Something is still using <name>. Close Finder windows or apps opened from it, then try again."; set status in both branches |
| Q28 | `volume_manager.py:36-40`, `:321` | `_find_stage` returns the raw core message, discarding the friendly `STAGES` names (same bug as Q3); Split-key mode matches nothing until "Kyber" | 3 | `return i, name`; own stage list for Shamir creation |
| Q29 | `volume_manager.py:399-419` | Create panel works with FUSE missing and never says the volume won't mount here | 3 | One warning strip in the create panel when `not all_ok` |
| Q30 | `volume_manager.py:903-906` | No empty state for Mounted Volumes; header + cards vanish after the last unmount | 2 | Keep header; "No volumes mounted." caption |
| Q31 | `volume_manager.py:334-339` | Success dialog says "use the Mount tab" (there is no tab; the segment says "Mount Existing") and makes the user re-pick the file just created | 3 | `askyesno("Mount it now?")` → set mode + prefill path |
| Q32 | `volume_manager.py:244-298` | Overwrite confirm fires before the password/match checks | 2 | Validate credentials first |
| Q33 | `volume_manager.py:68`, `:300-323` | Escape closes mid-create/mid-mount; create has no Cancel | 3 | `_busy` guard on close; reuse the encryptor's Cancel row |
| Q34 | `volume_manager.py:666-672`, `:163`, `:671` | Mount password field has no label; no Show toggle on any of the three password fields (both wizards have one) | 2 | Label + reuse the encryptor's `Show` |
| Q35 | `volume_manager.py` (no `focus_set` in file), `:68-73` | Nothing focused on open or after Ctrl+M panel switch; no Return-to-submit | 2 | Focus first entry in `_on_mode_change`; bind Return |
| Q36 | `volume_manager.py:91-100` | No `← Home` button although the launcher is hidden behind this window | 2 | Same header button as the wizards |
| Q37 | `volume_manager.py:473-478`, `:552-561` | "Install…" only shows brew commands; macOS path runs `brew` via osascript without checking brew exists, then shows "install in progress…" forever | 3 | Relabel "How to install…"; `shutil.which("brew")` first |
| Q38 | `volume_manager.py:424-444`, `:505` | Setup screen vocabulary: "FUSE backend", "fusepy (Python package)", "pip install fusepy", "Recheck dependencies" | 3 | "Disk mounting support (macFUSE or FUSE-T)", "Mounting helper", "Check again" |
| Q39 | `volume_manager.py:594-618` | "Recheck" with nothing changed produces zero visible change | 2 | "Checked just now — still missing: …" |
| Q40 | `updater.py:115-126` | "Download" and "✕" are plain Labels: unfocusable, no Return/space, ~10 px hit target | 3 | `FlatButton(..., small=True)` for both |
| Q41 | `updater.py:129-133` | Banner arrival re-centres the launcher window up to 5 s after launch | 3 | Delete the re-centre block |
| Q42 | `volume_manager.py:143` vs `:661`; `:196`, `:686` | "Split Key" (create) vs "Shares" (mount) for one concept; CTAs "Create Encrypted Volume"/"Mount Volume" vs the wizards' "Encrypt File →" | 2 | One term; "Create volume →" / "Mount volume →" |
| Q43 | `volume_manager.py:932`, `:895` | "Reveal" is a third label for show-in-folder and fails silently | 2 | "Show in Finder"; surface failure in status |

## 3. Major improvements (high impact, M effort)

| # | Location | Finding | Sev | Fix |
|---|---|---|---|---|
| M1 | `shared.py:34-35` | DejaVu Sans / Mono absent on macOS; MONO is proportional | 3 | Per-platform family map: darwin `.AppleSystemUIFont` + `Menlo`/`SF Mono`; linux DejaVu; win Segoe UI/Consolas. (Already queued as a Low in TASKS.) |
| M2 | `launcher.py:100-117`, `resizable(False, False)` | Window is ~860 pt tall before the Recent list; five recent rows push it past a 1080 pt display and it can't be resized or scrolled. On a 13" MacBook the Inspect button and hints are below the fold today | 3 | Cut the bottom copy (Q20), reduce card padding, cap Recent at 3 rows or scroll it, allow vertical resize |
| M3 | `launcher.py:190-224` | 2+1 card layout orphans Volumes at ~40% width under two full cards; reads as an afterthought and matches the icon-tile ×3 template | 2 | Three equal columns, or three full-width rows with the glyph left of the title |
| M4 | `decryptor.py:1386-1401` | "Decrypt now →" after verify calls `_reset()` and rebuilds empty credential fields | 4 | Don't reset; call `_start()` on the existing form |
| M5 | `decryptor.py:896-943` | No way to load `.share-N-of-M.txt` files; clipboard paste only | 3 | "Load from file…" using the parser already in `_paste_all_shares` |
| M6 | `decryptor.py:1249-1262` | Duplicate shares not detected → cryptic generic failure | 3 | Compare share indices; "Shares 1 and 2 are the same share" |
| M7 | `encryptor.py:1054`, `:1093-1100` | Batch encryption has no Cancel row and no `cancel_check`; progress bar saws 0→95% per file with a per-file ETA | 3 | Pack `_cancel_row`, pass `cancel_check`, report `(i-1+inner)/total` |
| M8 | `encryptor.py:872-875` | `_folder_stats` walks the tree on the main thread with no "Scanning…" state; the window freezes | 3 | Thread it; show "Scanning folder…" in the card |
| M9 | `encryptor.py:200` vs section labels; `decryptor.py:520` vs `:665-685` | Wizard step names and numbered section headers disagree on both wizards; encryptor lights only steps 0/1/4 of 5 | 2 | Rename `STEPS` to the section names; call `set_step` from mode/secret/output handlers |
| M10 | `encryptor.py:1388-1399` | Three save affordances, no stated consequence; "Copy all" doesn't clear `_shares_pending` | 3 | One caption: "Saving to files is what protects you — the clipboard clears in 60 s." |
| M11 | `shared.py:296-347` | `FlatButton` has no pressed state; disabled (`text3` on `surface2`) is near-identical to secondary enabled | 2 | Disabled = `surface` bg + `text3` + `takefocus=0`; pressed = `accent_dim` |
| M12 | `launcher.py` 🔒🔓💾🔍, `decryptor.py:764`, `updater.py` ✕, ✓/✗/⚠/📁 ×23 | Colour emoji as functional icons on a monochrome dark UI; tofu on Linux under DejaVu | 2 | Drop emoji from buttons; card glyphs as 2-tone Canvas marks or none; centralise `ICON = {"ok": "✓", "warn": "⚠", "err": "✗"}` in `shared.py` |
| M13 | `shared.py:38-46` + `launcher.py:171`, `:341`, `shared.py:722`, `decryptor.py:137` | Type scale 7/10/11/13/15/20/22/26/28 with no ratio; 7 pt is below any floor | 2 | Scale on 1.2 from 11: 11/13/16/19/23/28 as tokens; drop 7 pt |
| M14 | 98 uses of 1/2/3/5/7/9/14/18 px padding across `ui/`; nine `wraplength` values; each file re-declares `P` | No spacing scale | 1–2 | `SP = {xs:4, s:8, m:12, l:16, xl:24, xxl:32}` in `shared.py`; migrate opportunistically |
| M15 | `encryptor.py:95-102`, `:1080` | Fixed 6-dot stage list: "Compressing folder" shown as done for plain files; "Securing password" shown in Shamir mode | 2 | Build the stage list per run |
| M16 | `encryptor.py:881-889`, `:658`, `:696` | Encryptor writes `FileCard` privates (`_icon`, `_line1`, `_line2`) to fake a folder state | 1 | `FileCard.load_folder(path, count, size)` |
| M17 | `decryptor.py:1275`, `:1296-1361` | "Verify key only" runs Argon2id (0.55 of the bar) with no Cancel row and no `cancel_check` | 2 | Pack `_cancel_row`; check between stages |
| M18 | `encryptor.py:1430-1436` | Checklist step 4 "Test unlocking…" has no path to the decryptor from this screen | 2 | "Test decryption →" button, or drop the dependency from step 5 |
| M19 | `volume_manager.py:849-865` | `journal_suspicious` warning is a one-button OK that tells the user to unmount but doesn't offer to; `notify("Volume Mounted")` fires one line earlier; densest jargon in the app ("change journal", "truncated tail", "rollback") | 3 | `askyesno("Unmount now and keep this volume untouched?")` wired to `_do_unmount`; lead with "This volume's records don't match what QuantaCrypt last wrote — it may have been altered."; suppress the success notification |
| M20 | `volume_manager.py:874-883` | Unmount runs on the main thread (`save_all_dirty` + `diskutil` with no timeout); UI freezes with no "Unmounting…" state. Already queued in TASKS (F-035) | 3 | Worker thread + status + disabled row buttons |
| M21 | `volume_manager.py:373-389` | Recovery Shares dialog: no Copy, no Save, only right-click on a disabled Text; single exit "I've saved all shares"; `ClipboardTimer` imported, unused | 3 | Per-share Copy + "Save all shares…"; wire `ClipboardTimer` |
| M22 | `volume_manager.py:54`, `:898` | `resizable(False, False)` and cards appended per mounted volume with no ceiling; list never refreshes after an external eject | 3 / 2 | `resizable(False, True)`; `after(3000, _refresh_mounted_list)` while open |
| M23 | `volume_manager.py:222-297` | Six create-form validations are modal `showwarning`s; the wizards use an inline error label | 2 | One `_err` label under the Create button |
| M24 | `volume_manager.py:784-829` | Mount progress is a grey caption ("Deriving key (this takes a few seconds)…"); the same KDF gets a full `StagedProgressBar` on create | 2 | Reuse `StagedProgressBar` with Reading / Unlocking / Mounting |
| M25 | `volume_manager.py:620-697` | No recent-volumes prefill; `RecentFiles` unused here | 2 | `RecentFiles.add` on mount; prefill most recent |
| M26 | `updater.py:126`, `:53-91` | Dismissal not persisted (banner returns every launch); no manual "Check for updates" anywhere | 2 | Store dismissed tag; add a check item near the version label |
| M27 | 14 `messagebox` calls in `volume_manager.py` (41 app-wide) | Every high-stakes dialog is native light Tk chrome over a dark UI | 1 | A `confirm()`/`alert()` Toplevel in `shared.py`, adopted first by the three destructive dialogs. Effort L |

## 4. Strategic

No redesign trigger evidenced. Do not rebuild. One structural item worth a
design note before touching: unify the two wizards' section/step vocabulary and
the launcher's three entry points into one nav model (M3 + M9) — that is the only
change that touches more than one screen's IA.

## 5. Deprioritized (noted for completeness)

- `shared.py:58`, `:301-303` — three raw hex values outside `C` (`#fff`, `#5ba3e8`, `#ff6961`). Sev 1.
- `shared.py` border `#48484a` is 1.5:1 on `surface`; cards rely on it as the only separator. Sev 1.
- `PasswordStrengthBar` maps "Good" to the accent blue — the action colour used as a quality grade. Sev 1.
- Three copies of the label/value row builder (`launcher.py:451`, `decryptor.py:469`, `:857`) with different widths/wraps. Sev 1.
- `_Tooltip` lives in `decryptor.py`, used once; belongs in `shared.py`. Sev 1.
- `ShareCard` `tk.Text` fixed `height=5`, no scrollbar; a 6-line mnemonic is clipped and the outer canvas eats the wheel (`encryptor.py:142-169`). Sev 2, S.
- Two hand-rolled "saved" banners (`encryptor.py:1624`, `:1686`). Sev 1.
- `encryptor.py:1140` output-folder path packed into the wrong container (`ok_in` with a `side="left"` sibling). Sev 1.
- `_copy_all_shares` swallows clipboard failure; per-share copy shows "⚠ Failed" (`encryptor.py:1449`). Sev 2, S.
- `_reveal`/`open -R` is macOS-only and silent elsewhere (`encryptor.py:116`). Sev 2, S.
- Silent rename to `name_2.ext` on output collision (`decryptor.py:1222`). Sev 3 but S: one line on the success card.
- No failure/cancel `notify()` (`decryptor.py:1412`). Sev 2, S.
- `load_pkg` ValueErrors shown verbatim ("metadata envelope is not a valid dictionary") (`decryptor.py:742`). Sev 2, S.
- "File Information" dialog leads with algorithm names (`decryptor.py:867`). Sev 2, S.
- Presets 2-of-3 / 3-of-5 / 3-of-7 never show which is active (`encryptor.py:537`). Sev 1.
- Silent clamp of k/n to 20 (`encryptor.py:583-618`). Sev 1.
- Launcher header repeats the window title + three rules (`launcher.py:161-176`). Sev 1.
- `volume_manager.py:22` imports `WizardSteps` and `ClipboardTimer`, uses neither; `section_label` and a card helper exist in `shared.py` and the file hand-rolls both three times with three paddings. Sev 1.
- `volume_manager.py:924-928` volume name is `F["caption"]`, smaller than the setup screen's component names. Sev 2, S.
- `volume_manager.py:570-577` non-Darwin hint hardcodes `apt install libfuse-dev`; Windows gets the same text. Sev 2, S.
- `volume_manager.py:479-484` frozen bundle with fusepy missing shows no button at all. Sev 2, S.
- `volume_manager.py:954` "container 12.3 MB" — internal vocabulary. Sev 1.
- `updater.py:99-107` banner packs itself by child index with its own `padx=32`. Sev 2, S: give the launcher a named banner slot.
- `updater.py:119` inline font tuple built from `F["caption"]`. Sev 1.
- Dev only: this checkout's venv has stale editable metadata (installed 1.2.0 vs pyproject 1.3.0), so the launcher shows v1.2.0 and the updater will see GitHub's 1.3.0 as newer. `pip install -e .` fixes it.

## AI-tell scan

Hits in 4 categories: emoji-as-icons (#15), icon-tile ×3 cards (#5, partial 2+1),
flat type hierarchy (#13), Linux-default font (#11). No indigo, no beige, no
gradients, no slop copy, no generic CTAs. Borderline fingerprint; the register
itself is fine. De-slop is token-level: font map (M1), icon policy (M12), type
scale (M13). Not a restyle.

## Contrast table (computed)

| Pair | Ratio | Status |
|---|---|---|
| text on bg | 15.6 | OK |
| text2 on surface | 8.4 | OK |
| text3 on bg | 5.2 | OK |
| text3 on surface | 4.3 | fails 4.5 (captions in cards) |
| text3 on surface2 | 3.5 | disabled only |
| text on accent (primary button) | 3.1 | fails 4.5 |
| text on accent hover | 2.5 | fails |
| text on error (danger button) | 3.1 | fails 4.5 |
| accent on surface (links) | 4.2 | fails 4.5 |
| border on surface | 1.5 | fails 3:1 non-text |

---

## Implementation — 2026-09-02

Every quick win, major and deprioritised item above was implemented in one
pass (design system first, then the four screens in parallel). Summary of the
decisions that were not fully specified by the findings:

- **Tokens** (`shared.py`): `accent` is now a fill colour (`#2f6fb8`, 4.7:1
  with `text`) and `accent_text` (`#6aa6e8`) is for links and emphasis; hover
  and press go darker (`accent_hover`, `accent_press`); danger buttons use
  `error_fill`/`error_hover`; `text3` → `#9a9aa0`. Fonts are per platform
  (`.AppleSystemUIFont` + Menlo on macOS). Type scale 11/13/16/19/22/27 with
  `small` (10) as the one meta-text exception. `SP` spacing scale, `ICON`
  glyph map (no colour emoji anywhere), `MOD`/`accel()`/`bind_shortcut()`,
  `REVEAL_LABEL` + `reveal_path()`, `card()`, `kv_row()`, themed `confirm()`
  / `alert()`, `FileCard.load_folder/set_enabled/set_drop_supported`,
  `SegmentedControl.set_enabled`, `FlatButton` pressed/disabled states with a
  text-coloured focus ring on filled buttons, `RecentVolumes`, `AppPrefs`.
- **Launcher**: three full-width rows (no orphan card), the last-used mode
  carries the accent, one footer line, drop hint only when a drop target
  exists, Recent capped at 3 rows and focusable, vertical resize allowed,
  Escape no longer quits, ⌘M opens Volumes (⌘V was Paste). 484×640 with two
  recent rows, down from ~516×864.
- **Wizards**: `STEPS` match the section headings (encryptor: Source /
  Protection / Secret / Output / Encrypt; decryptor: File / Secret /
  Decrypt); progress labels come from `STAGES` names plus the percentage;
  `_fail` routes through `friendly_error`; status vs error colours split;
  Escape asks before discarding typed input and never closes from inside the
  autocomplete; Shamir: share files can be loaded, duplicates are detected,
  spare slots can be added, "Decrypt now" no longer resets, save-consequence
  caption added.
- **Volumes**: default mount point `~/QuantaCrypt Volumes/<name>`; unmount
  confirms, runs on a worker and reports into the row; tamper warning offers
  to unmount; create panel warns when FUSE is missing; setup screen written
  in plain language with the install command in the row; empty state, 3 s
  refresh, recent volumes, share dialog Copy/Save, inline validation.
- **Updater**: focusable buttons, no window re-centre, dismissal persisted,
  packs into the launcher's named banner slot.
- **Render check (2026-09-02, later)**: all seven screens captured and reviewed;
  three render-only fixes followed: WizardSteps canvas 44→56 (labels clipped under
  the system font), themed −/+ stepper replaces the native Spinbox (Aqua ignores
  its bg), "…" browse buttons relabelled "Browse…". Screenshots are in the
  published report.
- **Known dev-only flake**: `tests/test_crypto.py::TestEncryptShamir::test_bad_share_raises`
  failed once in a full run and passed on every rerun (a corrupted share
  value can, rarely, recover without raising). Pre-existing; not touched.
