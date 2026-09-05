# AI-tell audit (2026-09-04)

Review-mode pass over every surface a user or a reader of the repo sees, looking
only for signs that the work was machine-written. Companion to
`ui-audit-2026-09.md` (Tk screens) and `ui-audit-native-2026-09.md` (SwiftUI
shell), both of which covered usability and craft. This one covers provenance.

**Scope.** User-facing copy in `macos/QuantaCrypt/`, `src/quantacrypt/ui/` and
`src/quantacrypt/core/`, plus `README.md`. Out of scope: code comments and
docstrings (measured, reported below, deliberately left alone), and the
`docs/design/` notes, which are internal.

**Method.** Prior research was pulled from the KB before any new searching
(entries 30945, 30954, 26567 and the `ui-designer` reference set), then checked
against current sources. Every claim below is a count taken from the tree, not
an impression. Where a pattern looked like a tell, it was tested against the
repository's own history to see whether it predated the AI-assisted sessions.

---

## Executive summary

Fifteen of the eighteen tell categories in the reference set score zero. There
are no gradients, no glow, no glassmorphism, no purple or indigo, no warm-beige
surface, no raw hex outside the token tables, no bounce easing, no scattered
hover animation, no emoji standing in for icons, no invented testimonials or
statistics, no generic CTAs, and no hits on the slop lexicon. Both UIs use a
single icon system, a single radius, and a semantic palette that reads as
deliberate platform work rather than a template.

One tell was real, and it was everywhere: **a single punctuation template,
`fact — consequence`, doing the same job in roughly 230 user-facing strings.**
The em dash was not decoration. It had become the default connector for every
sentence in the product that needed to join a statement to its remedy, which is
exactly the shape reviewers and detection guides name first in prose.

Density before the fix:

| Surface | Copy words | Em dashes | Density | Against the 1-per-150 budget |
|---|---|---|---|---|
| `macos/` SwiftUI | 2,210 | 38 | 1 per 58 | 2.6x over |
| `src/quantacrypt/ui/` Tk | 3,891 | 108 | 1 per 36 | 4.2x over |
| `src/quantacrypt/core/` | n/a | ~50 | n/a | shared by both UIs |
| `README.md` | n/a | 37 | n/a | 12 were original |

The shape confirmed the template rather than ordinary punctuation. Sixteen of
the thirty-eight Swift dashes were followed by the word "the", and nearly every
instance separated a fact from the advice about it.

## Why this counted as a tell, with evidence

Heavy em-dash use is a style, and a person may simply write that way, so the
repository was asked directly. `core/crypto.py` carried **zero** em dashes at
the initial commit and eighteen today. Across every commit subject written by a
human author, one of thirty-seven uses one. The `README.md` did ship with
twelve, and all twelve are the same structural device (`**Term** — definition`)
in bullets and tables.

That gives a clean separation. The author's own use is structural, in lists,
tables and diagram labels. The imported use is prose, joining a claim to its
consequence. The first was preserved everywhere it appears. The second was
removed.

## What changed

Roughly 230 strings were rewritten, each taking the punctuation its own clause
wanted rather than one blanket substitution:

- a period where the two halves are independent statements
- a colon where the second half explains the first
- a semicolon where they are closely bound
- a comma, or `so` / `and` / `but`, where the clause is subordinate

Deliberately kept:

- `SettingsView.swift`, "Everything you type — passwords and shares — is sent
  to it." A genuine paired parenthetical, and correct.
- `README.md`'s `**Term** — definition` bullets, tables and ASCII diagram
  labels. The author's own convention, present from the first commit.
- Window titles and progress labels (`{file} — QuantaCrypt · Decrypt`,
  `File 2 of 5 — Deriving key`). A separator, not prose.
- Docstrings and code comments.

One README change was not punctuation. The tagline claimed the product is
"built on quantum-resistant cryptography so your data stays safe even as
computing advances", a benefit claim the project's own Security Overview
explicitly walks back: the KEM implementation is a pure-Python educational
library, not constant-time, and nothing here has been audited. An unverifiable
promise contradicted by the same document is the deepest form of the tell, so
the sentence was replaced with what the product actually does.

## A coupling this surfaced

Rewriting the share-file heading from `Share 1 — QCSHARE- code:` to
`QCSHARE- code for share 1:` broke two parser tests. `ShareFiles.parsed` treats
any line beginning with `QCSHARE-` as a share code, so the new heading was
counted as a damaged code. The heading is part of a file format the app reads
back, including files written by older versions, so the fix keeps the original
word and line structure and changes only the separator:
`Share 1, QCSHARE- code:`. Worth remembering that share-file headings are
parsed, not just displayed.

## Not changed, and why

Comments and docstrings across `src/quantacrypt/` run to 23,279 words with 262
em dashes, or one per 88 words. That is over the same budget, and it arrived
the same way. It was left alone for three reasons. The prose is good and
explains why rather than what, which is the thing that actually distinguishes
human comments from generated ones. The diff would be large, would touch every
core module, and would carry regression risk for no behaviour change. And a
codebase with literally zero em dashes anywhere reads as machine-processed in
its own right; the reference material is explicit that over-correction is a
tell too.

Recommendation: leave them. If they are ever revisited, do it as its own
commit.

## Scores by category

| # | Category | Result |
|---|---|---|
| 1 | Purple/indigo gradients | 0 |
| 2 | Gradient text, glow, glassmorphism | 0 |
| 3 | Claude beige (`#F4F1EA` family) | 0 |
| 4 | Meaningless status dots, accent stripes | 0 |
| 5 | Icon-tile three-card grid | 0, n/a |
| 6 | Centered hero, pill eyebrow | 0, n/a |
| 7 | Fixed marketing section recipe | 0 |
| 8 | Box-in-box nesting | 0 |
| 9 | Uniform symmetry, no rhythm | 0 |
| 10 | Over-rounding, soft shadows on gradient | 0; two radii (10, 6), no shadows |
| 11 | Default fonts as unexamined choice | 0; system font, a platform decision |
| 12 | Italic-serif accent word | 0 |
| 13 | Flat hierarchy | 0 |
| 14 | Bounce easing, motion theatre | 0; no animation at all |
| 15 | Emoji as functional icons | 0; SF Symbols and one glyph set |
| 16 | Fake content, invented stats | 0 |
| 17 | Slop lexicon, em-dash density | **the finding**; 1 unverifiable claim, ~230 dashes |
| 18 | Generic CTAs | 0 |

## Verification

- 92 Swift tests pass (`xcodebuild test`), including the two parser tests that
  caught the share-file coupling.
- Python suite re-run through `scripts/run_tests.sh`; 62 assertion fragments
  updated to match the new copy.
- Post-fix counts: Swift UI strings 38 → 1, Tk UI prose 107 → 0 (17 remain, all
  docstrings or title separators), core user strings ~50 → 2 (both docstrings),
  README 37 → 29 (all structural, author's own).

## Sources

Prior KB research (entries 30945, 30954, 26567) plus the `ui-designer`
reference set. Checked against three current sources:

- [vibecoded-design-tells](https://github.com/JCarterJohnson/vibecoded-design-tells),
  3.2M Reddit posts mined, tells ranked by how often people name them.
- [Impeccable / Slop](https://impeccable.style/slop/), Paul Bakaus's catalogue,
  the most complete current list at roughly sixty patterns across visual
  detail, type, colour, layout, motion, copy, imagery and design-system drift.
  It lists **"Em-dash overuse (multiple in body copy)"** as a named Copy tell,
  which corroborates this audit's finding independently of the prose checklist.
  Its Copy section also names aphoristic-cadence and theatre-framing copy;
  neither appears here.
- [Wikipedia: Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing),
  the canonical prose checklist, where em-dash overuse is pattern 13.

Cross-checking the Bakaus list turned up nothing further: zero side-tab accent
borders (which he calls the single most recognisable tell), zero pulsing status
dots, marquees, blinking cursors or repeating animations, no undersized
functional text (the Tk scale bottoms out at 10 pt), and no over-long measure
(the widest `wraplength` is 500 px, about 70 characters).

Current web sources on code-level tells add nothing this repo trips: no
per-function boilerplate docstrings, no banner-divider comments, no "in a real
implementation" placeholders, no explain-what comments.

One caveat from Bakaus worth recording, because it applies to this document:
today's antidote becomes tomorrow's tell once everyone reaches for it. Banning
purple moved models to beige. The durable defence is not this list, it is that
each choice has a stated reason.
