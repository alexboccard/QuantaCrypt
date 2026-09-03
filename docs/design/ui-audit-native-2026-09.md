# UI audit — native macOS shell (2026-09-03)

Review-mode audit of `macos/QuantaCrypt/` (the SwiftUI shell that replaces
`src/quantacrypt/ui/`). Companion to `ui-audit-2026-09.md`, which covered the
Tk screens; nothing here applies to those.

**Scope.** All three sections (Encrypt, Decrypt, Volumes), the sidebar, the
toolbar, Settings, the shares sheet, and every alert/confirmation, in light and
dark. Out of scope: the `qc-core` protocol itself, crypto, FUSE internals.

**Method.** Phase order per the audit procedure: frame → inventory → flow
walkthrough → heuristics → token grep → accessibility → write-up. The app was
**built and run** (Debug, macOS 26.6) and driven through real journeys by
routing real `.qcx` / `.qcv` documents into it with `open`; screens were
screenshotted in light and dark and read back. Contrast numbers below are
measured off those screenshots, not estimated. A separate probe app was built
to settle how macOS 26 renders a `.borderedProminent` toolbar button in its
enabled and disabled states.

Coverage caveat: heuristic evaluation finds ~35% of problems per evaluator.
Four independent lens passes were run — structural, novice, error-recovery,
accessibility/platform — to widen that. It is still not a substitute for
watching a real person use it.

---

## Executive summary

The shell is **not** a styling problem. It is idiomatic macOS: system font,
semantic colours, SF Symbols only, no raw hex anywhere, no invented shadows or
radii, no animation theatre, and copy that passes the banned-lexicon and
generic-CTA greps cleanly. The AI-tell scan comes back at roughly one and a
half categories out of eighteen — far under the four-category fingerprint. The
error vocabulary in particular (cause + next step, the Caps Lock hint, "any k
of n, so swap a share", "nothing was written") is better than most shipping
apps.

The problems are **flow and architecture**, and they cluster on the three
things a security tool cannot afford to get wrong: knowing what the app will do
when you press the button, knowing why it won't, and not being able to destroy
your only key by accident.

The five highest-value findings:

1. **Two ways to permanently lose data, neither guarded.** ⌘Q while the shares
   sheet is open discards the only copy of the key material, bypassing the
   sheet's own leave-guard; and a created `.qcv` whose shares were discarded
   has no "show shares again" path, unlike `.qcx`. (N-01, N-02)
2. **The primary action is an unlabelled blue circle whose disabled state is
   invisible.** Measured: a disabled prominent toolbar button keeps the
   full-saturation fill and renders its glyph at **2.14:1**. Encrypt and
   Decrypt have no in-form button at all — the app's own generated share files
   instruct recipients to "Click Decrypt file", a control the UI never draws.
   (S-01, S-02)
3. **Opening a document spawns a duplicate window.** Verified live: one
   process, three identical windows after opening two documents, all bound to
   the same `AppState`. (S-03)
4. **Volumes leads with "Create a volume".** A user who double-clicks a `.qcv`
   lands on a creation form; their volume, its password field and the Mount
   button are below the fold, and "Mounted volumes" — the answer to *what is
   open right now* — is below that again. The one toolbar action silently
   swaps between Create and Mount depending on which field was last focused.
   (S-04, S-05)
5. **The password path never says the file is unrecoverable.** The string
   exists once, shown only after three wrong passwords on Decrypt. The
   split-key path warns properly; the password path does not warn at the moment
   the password is invented. (N-03)

Verdict: **incremental**. None of the five redesign triggers is present — the
IA is coherent, the technology supports what is needed, and the visual system
is sound. Every fix below is local.

---

## Quick wins — high impact, low effort. Ship these first.

| # | Fix | Location |
|---|---|---|
| Q-01 | Guard ⌘Q while a shares sheet is open (`.terminateCancel` + alert) | `App/AppDelegate.swift:21` |
| Q-02 | Add "Show shares again" to the created-volume row | `Features/Volumes/VolumesView.swift:188` |
| Q-03 | `WindowGroup` → `Window` (kills duplicate windows) | `App/QuantaCryptApp.swift:8` |
| Q-04 | `.labelStyle(.titleAndIcon)` on the three toolbar primaries | Encrypt/Decrypt/Volumes views |
| Q-05 | Add inline primary buttons to Encrypt and Decrypt, matching Volumes | `EncryptView.swift`, `DecryptView.swift` |
| Q-06 | Render `validationMessage` inline, not only in `.help()` | all three views |
| Q-07 | Say the file is unrecoverable next to the password fields and in the result card | `Shared/CredentialFields.swift:11` |
| Q-08 | Refuse `.qcx`/`.qcv` as an encrypt source; offer to open it in Decrypt | `EncryptView.swift:46` |
| Q-09 | Clear `shares` in `load(path:)` so one file's shares can't leak into another's | `Features/Decrypt/DecryptModel.swift:66` |
| Q-10 | Mount point → read-only tilde path + Change…, relabelled "Opens as a drive at" | `Features/Volumes/VolumesView.swift:244` |
| Q-11 | Label the inspect spinner and give it a timeout + retry | `DecryptView.swift:33`, `VolumesView.swift:254` |
| Q-12 | "Cancelling…" state so Cancel acknowledges itself | `Shared/StatusViews.swift:11` |
| Q-13 | Replace the `"Something went wrong."` fallback with cause + action | `Core/CoreProtocol.swift:219` |
| Q-14 | Empty state that teaches in Mounted volumes | `VolumesView.swift:303` |
| Q-15 | Drop the two raw `.font(.system(size:))` values | `ContentView.swift:124`, `DropZone.swift:19` |
| Q-16 | `.combine` → `.contain` on DropZone and ProgressPanel so the Choose and Cancel buttons exist for VoiceOver | `DropZone.swift:45`, `StatusViews.swift:24` |
| Q-17 | Move the section shortcuts to ⇧⌘E / ⇧⌘D / ⇧⌘M, giving ⌘M back to Minimize | `App/QuantaCryptApp.swift:19` |
| Q-18 | Name the mount-point field and the five "Change…" buttons for VoiceOver | `VolumesView.swift:147/228/246/250`, `EncryptView.swift:39/72` |
| Q-19 | Show `createValidationMessage` unconditionally (it is hidden in exactly the state that needs it) | `VolumesView.swift:179` |
| Q-20 | Status dot → shape + colour at a ≥3:1 tone, semantic size | `ContentView.swift:123` |
| Q-21 | Settings `.frame(width: 560)` → `minWidth` | `SettingsView.swift:71` |

## Major improvements — high impact, medium effort

| # | Fix | Location |
|---|---|---|
| M-01 | Reorder Volumes to Mounted → Mount → Create, and move Create into a sheet; the toolbar action becomes "Mount volume", always | `Features/Volumes/VolumesView.swift` |
| M-02 | Propagate helper death to `helperStatus`; make the status pill actionable when failed | `Core/CoreClient.swift:269`, `App/AppState.swift:61` |
| M-03 | Clear or fulfil `openNote` when the blocking job ends | `App/AppState.swift:110` |
| M-04 | Quit progress: show what is being unmounted/cancelled during the ≤40 s shutdown wait, and confirm before aborting a running job | `App/AppDelegate.swift:26` |
| M-05 | Tri-state the FUSE gate (`unknown`/`missing`/`ok`) so "not checked yet" stops reading as "not installed" | `VolumesModel.swift:311` |
| M-06 | Rewrite `.io` mount failures into cause + next step instead of passing raw Python text through | `VolumesModel.swift:365` |
| M-07 | Teach the concepts at the point of choice: one line under the protection picker in both states, one line saying what a volume is, Terminal/Homebrew context in the FUSE block | Encrypt + Volumes views |
| M-08 | "Check I can open it" on the encrypt result card, routing to Decrypt's existing `verify()` (writes nothing) | `EncryptView.swift:123` |
| M-09 | Say the plaintext original is untouched; offer "Move original to Trash" (never default) | `EncryptView.swift:100` |
| M-10 | Warn when the mounted list is stale after repeated poll failures, and disable its row buttons | `VolumesModel.swift:395` |
| M-11 | Make Recent rows real, keyboard-reachable list rows with hover/selected state | `App/ContentView.swift:69` |
| M-12 | Announce outcomes and move focus to the activity section for VoiceOver | all three views |

Strategic items: none. No redesign trigger fired.

Deferred, with reasons:

- **Create-a-volume as a sheet.** Cleaner than reordering, and it would remove
  the two-simultaneous-ProgressPanel problem outright, but it is a larger diff
  than the finding requires. Reordering plus a single stable toolbar action
  fixes S-04 and S-05 at a fraction of the risk. Revisit if the Volumes screen
  grows again.
- **A progress sheet during the ≤40 s quit.** Needs a scene that can outlive
  `applicationShouldTerminate`; the confirmation before aborting a running job
  is the load-bearing half and ships now.

---

## Findings

Severity is Nielsen 0–4 (0 not a problem · 1 cosmetic · 2 minor · 3 major ·
4 catastrophe), rated as frequency × impact × persistence.

### Data loss and irreversibility

**N-01 — ⌘Q discards unsaved shares.** `App/AppDelegate.swift:21`.
`applicationShouldTerminate` never checks whether a `SharesSheet` is open with
`saved == false`. The sheet guards Escape and its Close button
(`SharesSheet.swift:74`, `:121`), but ⌘Q bypasses both: the app runs
`core.shutdown()` and exits, and the only copy of the k-of-n key material is
gone. The `.qcx`/`.qcv` on disk is then permanently unopenable, with no warning
at any point. **Severity 4.** Fix: return `.terminateCancel` behind an alert
offering "Save shares…" / "Quit and discard".

**N-02 — a discarded `.qcv` share set cannot be recalled.**
`Features/Volumes/VolumesView.swift:188`. After a split-key volume is created
the result row offers only "Show in Finder" and "Mount volume now".
`EncryptView.swift:125` has exactly the second chance this row lacks ("Show
shares again"); `createResult.shares` is still held in the model, but nothing
re-presents it. One click on "Discard shares" makes the volume unopenable
forever. **Severity 4.** Fix: mirror `EncryptView.swift:125-132`.

**N-03 — the password path never says the file is unrecoverable.**
`Features/Decrypt/DecryptModel.swift:8`, `:215`. "There is no way to recover
this file without the password" exists once in the app and is shown only after
three wrong passwords on Decrypt. Nothing warns at the moment the password is
invented, at Encrypt, or in the success card. The split-key path does warn
("can never be opened again", `SharesSheet.swift:82`) — the asymmetry is the
tell. **Severity 4** (every encrypt · unrecoverable · never learned until too
late). Fix: state it beside the password fields and in the result card.

### Knowing what the button does

**S-01 — the primary action has no label.** `EncryptView.swift:15`,
`DecryptView.swift:17`, `VolumesView.swift:36`. macOS 26 renders
`Button(_:systemImage:)` in a toolbar as an icon-only circle; the words
"Encrypt file" are never drawn. The padlock glyph is the same symbol the
sidebar uses for the Encrypt section, so it reads as a section badge, not a
verb. Encrypt and Decrypt have **no in-form action at all** — the user reaches
the bottom of the form and there is nothing to press. The app's own generated
share files tell recipients to "Click Decrypt file" (`ShareFiles.swift:143`), a
control the UI does not draw. **Severity 4.** Fix: `.labelStyle(.titleAndIcon)`
plus an inline primary button on Encrypt and Decrypt, as Volumes already has.
*(Verified in an isolated probe: `.labelStyle(.titleAndIcon)` does draw the
title on macOS 26.)*

**S-02 — the disabled state of that button is invisible, and its reason is a
tooltip.** Same locations. Measured off the probe: a disabled
`.borderedProminent` toolbar button keeps the full-saturation fill and draws
its content at **2.14:1** against that fill (enabled: 3.23:1). In
`decrypt-new.png` the disabled toolbar circle is vivid blue while the equally
disabled "Verify only" beside it is plainly grey; same contradiction in
`volumes.png` against the dimmed "Create volume". So the button looks live,
does nothing when clicked, and the explanation — the app's well-written
`validationMessage` — is reachable only by hovering. **Severity 3.** Fix:
render `validationMessage` inline (Volumes already does at
`VolumesView.swift:179`).

**S-03 — opening a document spawns a duplicate window.**
`App/QuantaCryptApp.swift:8`. `WindowGroup` creates a new window for each
document open, but every window is bound to the one `AppState` the delegate
owns. Verified live: after `open`ing a `.qcx` and a `.qcv`, `pgrep` shows one
process and `CGWindowList` shows three windows, all titled the same and showing
identical content; typing in one appears in the others. **Severity 3.** Fix:
`Window("QuantaCrypt", id: "main")` — this app is a single-window utility, not
document-based, and the delegate's `application(_:open:)` routing is unaffected.

**S-04 — Volumes leads with the wrong task.** `VolumesView.swift:26-28`.
Section order is Create → Mount → Mounted. Opening `Vault.qcv` puts the user's
own volume at y≈900 of a 1240px window, its password field and Mount button
below the fold, and the mounted list below that. Creating a volume happens once
per volume; mounting happens every day, and "what is mounted right now" is the
question the screen should answer first. **Severity 3.** Fix: reorder to
Mounted → Mount → Create and move creation into a sheet (M-01).

**S-05 — the toolbar action silently changes identity.**
`VolumesView.swift:36-51`, `VolumesModel.swift:28`. The single toolbar button
is Create or Mount depending on `activeJob`, which flips whenever focus lands
in a field of the other section. It defaults to `.mount`, so on a first visit —
staring at an empty Create form — the top-right circle and ⌘↩ are the *Mount*
action. With no label drawn (S-01), nothing tells the user which. **Severity
3.** Fix: falls out of M-01 — one action, always Mount.

### Errors, interruption, recovery

**E-01 — helper death is never reported.** `Core/CoreClient.swift:269`,
`App/AppState.swift:61`. `transportEnded` increments `restartCount`, but grep
confirms nothing outside `CoreClient` reads it, and `refreshHelperStatus()` is
called only at launch and from Settings. After a helper crash the status pill
keeps showing a green dot and "Core 1.3.0" — the one always-visible health
indicator lies about the exact condition it exists to report. **Severity 3.**

**E-02 — Cancel gives no acknowledgement.** `Shared/StatusViews.swift:11`.
`cancel()` calls `task?.cancel()`; `isRunning` and `progress` are untouched
until the helper's `cancelled` event arrives, up to the 5 s `cancelGrace`. The
panel keeps reading "Encrypting… 62%" and the percentage can keep climbing.
**Severity 3.** Fix: an `isCancelling` flag, "Cancelling…", disabled Cancel.

**E-03 — the inspect spinner is unlabelled, untimed and inescapable.**
`DecryptView.swift:33`, `VolumesView.swift:254`. `DecryptModel.load` calls
`core.perform(.inspect(...))` with no timeout, and the Unlock and Save-to
sections are hidden behind `if model.info != nil`. A helper that starts but
never answers leaves the user on an otherwise empty screen with a bare spinner
and no exit. **Severity 3.** Fix: label it, wrap in `withTimeout`, offer retry.

**E-04 — mount failures pass raw Python text through.**
`VolumesModel.swift:365`. `friendlyMountError`'s `default:` returns the
helper's message verbatim, and the two most common real mount failures — mount
point busy or non-empty, and macFUSE/FUSE-T installed but not yet approved in
System Settings — arrive as `RuntimeError("FUSE mount failed: …")` classified
as `io`, which the switch does not rewrite. The user sees
`FUSE mount failed: [Errno 1] Operation not permitted`: no cause, no next step.
**Severity 3.**

**E-05 — "not checked yet" is indistinguishable from "FUSE missing".**
`VolumesModel.swift:311`, `:82`. `mountingAvailable` is `fuse?.ok ?? false`, so
a check still in flight, or one that threw, both read as "missing" and send the
user to `brew install`. The two explanatory warning strips are gated on
`fuse != nil`, so they stay hidden in exactly that case. **Severity 3.**

**E-06 — the mounted list goes stale silently.** `VolumesModel.swift:395`.
`refreshMounted`'s `catch { listLoaded = true }` discards every failure and
keeps the last list. If the helper becomes permanently unavailable the 3 s poll
fails forever while the section keeps listing volumes that no longer exist,
with working-looking Show in Finder and Unmount buttons. **Severity 3.**

**E-07 — the open-blocked banner never clears.** `App/AppState.swift:110`.
`openNote` is set when a document arrives during a running job and is cleared
only by a later successful `open()` or the Dismiss button; no completion path
touches it. After the job finishes the hourglass banner still says "Finish or
cancel the current job", and the deferred document is dropped — never retried,
never remembered. **Severity 3.**

**E-08 — quitting is a 40-second black box.** `App/AppDelegate.swift:26`.
`.terminateLater` awaits `core.shutdown()` (30 s) plus `terminate` (10 s) while
the helper cancels work and unmounts every volume. Nothing is shown during that
wait, and a running 20-minute encrypt is aborted by ⌘Q with no prompt.
**Severity 3.**

**E-09 — cancelling a mount reports the wrong thing.**
`VolumesModel.swift:384`. `mount_volume` has no cancel check inside the FUSE
startup wait, so the grace expiry fires and the UI shows "Cancelled — the
helper did not confirm, so check the destination before assuming nothing was
written" — copy written for a file write — while the mount usually goes on to
succeed and appears in the list 3 s later. **Severity 3.**

**E-10 — one file's shares leak into another's fields.**
`DecryptModel.swift:66`. `load(path:)` clears `password` but not `shares`, and
the inspect callback only pads when `shares.count < needed`. Open split-key
file B after typing shares for file A and A's shares sit there looking valid;
the failure then advises "try swapping in a different share", sending the user
hunting for a wrong share that does not exist. **Severity 2.** Fix: clear
`shares` alongside `password`, as `reset()` does.

### Teaching and comprehension

**N-04 — "Split key" is offered with no basis to choose.**
`EncryptView.swift:54`, `CredentialFields.swift:77`. The segmented control
presents Split key as an equal peer of Password with two words and no
explanation; the one sentence that would let someone decide appears only
*after* switching. Guessing wrong yields three `QCSHARE-` blobs and a modal
that will not close until files are saved. **Severity 3.**

**N-05 — the FUSE remedy assumes Terminal and Homebrew.**
`VolumesView.swift:85-121`. The Copy button hands over
`brew install --cask fuse-t` with no statement that this is a Terminal command,
that Homebrew is a separate program, or what a cask or a kernel extension is —
and then offers a second unexplained option. A user who cannot open Terminal
has no path forward and the whole Volumes feature is unreachable. **Severity
3.**

**N-06 — the volume concept is never explained.** `VolumesView.swift:137-167`.
The screen never says what a volume is or what happens after mounting. The
success note ("Mounted Vault at …") does not say to drag files in, or that
quitting the app unmounts the drive. **Severity 3.**

**N-07 — encrypting a `.qcx` silently double-encrypts it.**
`EncryptView.swift:46` (`accepts: { _ in true }`), `Panels.swift:33`.
`AppState.open` routes `.qcx` to Decrypt, but the Encrypt screen's drop zone
and unfiltered open panel accept it, yielding `notes.txt.qcx.qcx` and a green
success card. Encrypt is the default section, so this is the natural mistake
for someone who wants their file back. **Severity 3.**

**N-08 — the plaintext original is never mentioned.**
`EncryptView.swift:100-137`. Encryption leaves the original untouched; nothing
in the app says so. The user's model of "I encrypted my sensitive file" is that
it is now protected, while the readable copy sits beside the encrypted one.
**Severity 3.**

**N-09 — "Mount point" is a raw path text field.**
`VolumesView.swift:244`. A never-defined term, offered as an editable
filesystem path, whose main use is to produce the "choose a folder inside your
home folder" error that only exists because the field exists. The Location row
directly above it uses the right pattern: read-only text + Change…. **Severity
3.**

**N-10 — the status pill spends the toolbar's best real estate on a version
number.** `ContentView.swift:117-156`. "● Core 1.3.0" names a subsystem the
user has never heard of. Its failure state, "Helper unavailable", offers no
button; recovery requires knowing that ⌘, → Restart helper exists. In dark mode
the pill renders as a light chip with low-contrast text. **Severity 2–3.**

**N-11 — help is one menu item pointing at a GitHub README.**
`QuantaCryptApp.swift:27`. There is no help at any point of confusion: none at
Split key, Mount point, volume, or the FUSE block. **Severity 3.**

**E-11 — the generic fallback message is a forbidden string.**
`Core/CoreProtocol.swift:219`: `message ?? "Something went wrong."` — no cause,
no next step. **Severity 2.**

**S-06 — "No volumes mounted." teaches nothing.** `VolumesView.swift:303`.
The empty state of the screen's most valuable region is a bare sentence.
**Severity 2.**

**S-07 — "Choose a file first." is a dead section.** `EncryptView.swift:74`.
The Save-to section renders as an empty grey card before a source exists.
**Severity 1.** Fix: hide it until there is a source.

---

## Token, contrast and AI-tell scan

Clean, and worth recording so the next audit does not redo it.

| Check | Result |
|---|---|
| Raw hex / `Color(red:…)` in components | **0** |
| Colour literals | `.green` ×10, `.red` ×7, `.orange` ×5, `.accentColor` ×3 — all semantic, always paired with an SF Symbol, never colour-alone |
| Radius tokens | one (`cornerRadius: 10`, ×3) |
| Shadows invented | 0 |
| Font sizes off the semantic scale | 2 (`ContentView.swift:124` size 8, `DropZone.swift:19` size 28) |
| Spacing values | 0, 2, 4, 6, 8, 10, 12, 14 — all ÷2, all but 2/6/10/14 on the ÷4 grid; acceptable for SwiftUI metrics |
| Animation | none at all — a deliberate, correct choice for a utility |
| Icons | SF Symbols exclusively; zero emoji |
| Banned lexicon | **0 hits** |
| Generic CTAs ("Get Started", "Submit", …) | **0 hits** |
| Exclamation marks in UI copy | 0 |
| Dark mode | verified by screenshot; all semantic colours adapt. One defect: the toolbar status pill renders as a light chip with low-contrast text |
| Drop-zone dashed border | measured **3.08:1** — passes the 3:1 non-text minimum, with no margin |
| Disabled prominent toolbar button | measured **2.14:1** — fails (S-02) |

AI-tell categories hit: **1.5 of 18.** The drop zone is a bordered rounded rect
inside the grouped form's own rounded card (box-in-box, tell #8), and
user-facing copy leans on the em dash as a connector more than a human writer
would — "The volume grows as you add files — no fixed size to choose", "Longer
is stronger — a few unrelated words work well", "Saving to files is what
protects you — the clipboard clears in 60 s". Both are cosmetic. Nothing else
fires.

## Accessibility

Eight accessibility modifiers exist across 4,257 lines, and two of them do
active harm.

**A-01 — the button that starts every task is swallowed.**
`Shared/DropZone.swift:45-46`. `.accessibilityElement(children: .combine)`
followed by `.accessibilityLabel(title)` collapses the icon, subtitle and the
"Choose file or folder…" Button into one element whose label is overwritten
with the title alone. VoiceOver announces "Drop a file or folder here" and
nothing else — no button trait, no hint that anything is activatable. Same
component is the entry point on all three screens. **Severity 4.** Fix:
`.contain`, not `.combine`.

**A-02 — the Cancel button is swallowed the same way.**
`Shared/StatusViews.swift:20-24`. Cancel is the only way to abort a running
job; after `.combine` its sole route is the Escape shortcut, which is never
shown on screen. Worse, `VolumesView` can render two ProgressPanels at once
(`createRunning` and `mountRunning` are independent), registering two
`.cancelAction` shortcuts simultaneously. **Severity 3.**

**A-03 — ⌘M is taken from Minimize.** `App/QuantaCryptApp.swift:23`. "Mount
Volume…" claims ⌘M, which AppKit assigns to Window ▸ Minimize; the File menu
is scanned first, so a keyboard user loses minimize app-wide and gets a file
panel. ⌘D (Decrypt) and ⌘E (Encrypt) collide with the standard Duplicate /
"Don't Save" and Use-Selection-for-Find conventions. **Severity 3.**

**A-04 — Recent files are mouse-only.** `App/ContentView.swift:69-87`. The
rows are `Button`s with `.buttonStyle(.plain)` inside a `List(selection:)` and
carry no `.tag`, so arrow-key navigation skips the whole Recent section and the
rows get neither focus ring nor hover/selected background. Their two secondary
actions live in a `.contextMenu`, which has no keyboard equivalent. **Severity
3.**

**A-05 — outcomes are never announced.** `EncryptView.swift:82-98` and the
same shape on the other two screens. The activity section materialises
asynchronously far below the toolbar button that was pressed, with no
`AccessibilityNotification.Announcement` and no `@AccessibilityFocusState`
anywhere in the target. A VoiceOver user who presses ⌘↩ gets silence and must
hunt for the outcome. **Severity 3.**

**A-06 — the mount-point field has no accessible name.**
`VolumesView.swift:246`. `TextField("", …)` + `.labelsHidden()` and no
`.accessibilityLabel`; `LabeledContent`'s label is not attached to the inner
field. It is the only editable filesystem path in the app. **Severity 3.**

**A-07 — three identical "Change…" buttons on one screen.**
`VolumesView.swift:147, 228, 250` (and twice each on Encrypt/Decrypt). In the
rotor they are indistinguishable. **Severity 2.**

**A-08 — the status dot fails non-text contrast in both themes.**
`ContentView.swift:123-125`. Measured: `rgb(102,185,92)` on the dark-mode
chip's `rgb(206,206,206)` = **1.54:1**; light mode = **2.43:1**. Both under the
3:1 floor for a status indicator, at 8pt. The chip material inverts between
appearances; the hard-coded `.green/.orange/.red` does not. **Severity 2.**

**A-09 — the disabled Create button is both illegible and unexplained.**
`VolumesView.swift:177-183`. Measured **1.85:1** light, **2.17:1** dark. Line
179 gates the explanation on `!createName.isEmpty`, so in exactly the state the
screenshots show — empty Name — "Give the volume a name." is suppressed.
**Severity 2.**

**A-10 — fixed sizes don't scale.** `DropZone.swift:19` (28pt),
`ContentView.swift:124` (8pt), `SettingsView.swift:71` (`.frame(width: 560)` on
a window that therefore cannot widen), `CredentialFields.swift:23` /
`VolumesView.swift:208` (120pt strength meters). At accessibility text sizes
the labels grow around frozen glyphs. **Severity 2.**

## Implementation — 2026-09-03

All twenty-one quick wins, nine of the twelve majors in full and two in part,
implemented in the same session as the audit. 62 Swift tests pass (was 48;
`GuardrailTests.swift` adds 14 covering the guards whose absence lost data).
Verified by rebuilding and re-running the app, and re-screenshotting each
screen in both appearances.

The two partials: **M-04** ships the confirmation before a running job is
aborted, not the progress sheet during the quit wait. **M-09** names the
plaintext original and says where it still is, but does not offer "Move
original to Trash" — adding a one-click destructive action to a success card
is a decision about what this app does to the user's files, not a UI fix, so
it is yours to make.

What changed, by finding:

| Findings | Change |
|---|---|
| N-01 | `applicationShouldTerminate` asks `AppState.quitBlocker` first. Unsaved shares, or a running job, get a critical alert whose default is "Keep working". `SharesSheet` reports saves up via `onSaved` so the flag outlives the sheet, and a new share set re-arms the guard. |
| N-02 | "Show shares again" on the created-volume row, mirroring `.qcx`. |
| N-03 | A `WarningStrip` beside the password fields on both Encrypt and volume creation: "If you forget this password the file is gone — QuantaCrypt cannot recover it, and neither can anyone else." |
| S-01, S-02, A-09 | `.labelStyle(.titleAndIcon)` on all three toolbar primaries, and prominence **moved off** the toolbar: macOS 26 draws a disabled prominent toolbar button at full saturation (measured 2.14:1), so the prominent copy is now the new inline `PrimaryActionRow` at the end of each form, which dims correctly. `validationMessage` renders beside it as a `NextStepNote` instead of living only in `.help`. `createValidationMessage` is no longer gated on a non-empty Name. |
| S-03 | `WindowGroup` → `Window`. Verified: opening two documents now leaves one window, not three. |
| S-04, S-05 | Volumes reordered to Mounted → Mount → Create; the mode-switching `activeJob` is deleted and the toolbar action is always "Mount volume". |
| S-06, S-07 | Mounted-volumes empty state teaches; the "Choose a file first." placeholder section is gone. |
| E-01 | `CoreClient.onUnexpectedExit` propagates a helper crash to `helperStatus`. |
| E-02, A-02 | `isCancelling` on all four jobs: the panel says "Cancelling…", stops the percentage, and disables Cancel. Create and Mount now exclude each other, so two `.cancelAction` shortcuts can no longer be live at once. |
| E-03 | Inspect is bounded by `withTimeout(20s)`, the spinner is labelled, and failures get a "Try again". |
| E-04 | `.io` FUSE startup failures are rewritten to name the two real causes; the raw text moves to details. |
| E-05 | `MountSupport` is tri-state, so "not checked yet" no longer sends the user to Homebrew. |
| E-06, M-10 | Two consecutive poll failures mark the list stale, warn, and disable its row buttons. |
| E-07, M-03 | `OpenNote` carries the URL; the banner turns into "Open <file>" once the blocking job ends. |
| E-10 | `load(path:)` clears `shares` as well as `password`. |
| E-11 | The `"Something went wrong."` fallback names a cause and a next step. |
| N-04, N-06 | A one-line explanation under the protection picker **in both states**; a plain-language description of what a volume is; what to do after mounting. |
| N-05 | The FUSE block says it is a Terminal command, points at brew.sh, and offers "Open Terminal". |
| N-07 | `.qcx`/`.qcv` are refused as encryption sources, with an alert offering the section that can open them. |
| N-08 | The encrypt result card names the plaintext original and where it still is. |
| N-09 | "Mount point" → "Opens as a drive at", read-only tilde path plus Change…, matching the Location row. |
| N-10, A-08 | The status item is quiet when healthy ("Ready", no version number) and carries a "Try again" button when it fails. Dark-mode chip measured 6.18:1, was 1.54:1. |
| M-08 | "Check it opens" on the encrypt result routes to Decrypt's `verify()`, which writes nothing. |
| A-01, A-02 | `.combine` → `.contain` on DropZone and ProgressPanel, so the Choose and Cancel buttons exist for VoiceOver again. |
| A-03 | Section shortcuts moved to ⇧⌘E / ⇧⌘D / ⇧⌘M; ⌘M goes back to Minimize. |
| A-04, M-11 | Recent rows get a hover highlight, and File ▸ Open Recent carries the same list for keyboard users. |
| A-05, M-12 | Outcomes post an `AccessibilityNotification.Announcement`. |
| A-06, A-07 | The mount-point value and all five "Change…" buttons have distinct VoiceOver names. |
| A-10, Q-15 | The two raw `.font(.system(size:))` values are gone; Settings uses `minWidth`. |

Not done, and why:

- **M-01 (Create as a sheet), M-04 (a progress sheet during quit)** — see
  Deferred above. M-04's load-bearing half, confirming before a running job is
  aborted, did ship.
- **E-09 (cancelled mount reports the wrong thing)** — partly. `cancelMount`
  now refreshes the mounted list immediately, so a mount that succeeded anyway
  appears at once instead of three seconds later. Making the grace-expiry copy
  op-aware belongs in `CoreClient`, where the request kind is known; left for
  the next pass on the protocol layer.
- **N-11 (inline help popovers)** — the four jargon points now explain
  themselves in place, which was the goal; a popover system is a bigger
  decision about where help lives.

## Notes

- The working tree carries the uncommitted review-loop batch (42 files,
  +3415/−1096) on top of `e9bcba7`; this audit and its fixes stack on that.
- `macos/QuantaCrypt/Info.plist` is deleted from the index but present on disk
  (generated by xcodegen, now gitignored) — expected.
- `xcodegen generate` is required after adding a Swift file; the first run of
  `GuardrailTests` silently did not execute because the project had not been
  regenerated and the total stayed at 48.
- Swift tests: 48 before, 62 after, 0 failures. No Python was touched.
