#!/usr/bin/env python3
"""Stamp a release version into every file that records one.

The release workflow used to do this with three `sed -i '' "s/^version = .*/…/"`
substitutions per build job.  `sed` exits 0 when its pattern matches nothing, so
a `version` line that grew leading whitespace, a reformatted `__version__`, or a
`CFBundleShortVersionString` switched to single quotes would have published a
release labelled with the *previous* version — and the in-app update checker
compares the running version against GitHub Releases, so every user would then
sit on a permanent "update available" banner that installing cannot clear.
A missed target has to be loud, which is the whole point of this script.

Usage:
    python3 scripts/stamp_version.py 1.4.0
    python3 scripts/stamp_version.py 1.4.0 --check   # verify only, write nothing
"""

from __future__ import annotations

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The version arrives straight from GITHUB_REF (`refs/tags/v…`), i.e. from
# whatever string someone managed to push as a tag.  A quote or a newline in it
# would corrupt the TOML/YAML it is written into, so reject it before any file
# is opened rather than repairing the damage afterwards.
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+-]*$")

#: (path, pattern, render).  Each pattern must match *exactly once*; `render`
#: rebuilds the matched span from the match so anything after it on the line
#: — `__init__.py`'s "keep in sync" comment, for one — survives.
TARGETS = (
    (
        "pyproject.toml",
        re.compile(r"""(?m)^(?P<pre>version[ \t]*=[ \t]*)(?P<val>"[^"]*"|'[^']*')[ \t]*$"""),
        lambda m, v: f'{m["pre"]}"{v}"',
    ),
    (
        "src/quantacrypt/__init__.py",
        re.compile(r"""(?m)^(?P<pre>[ \t]*__version__[ \t]*=[ \t]*)(?P<val>"[^"]*"|'[^']*')"""),
        lambda m, v: f'{m["pre"]}"{v}"',
    ),
    (
        # Stamped in every job, not just the native one: the Tk jobs ignore
        # this file, but keeping one code path means the native build cannot
        # be the only place a stamping bug shows up.
        "macos/project.yml",
        re.compile(
            r"""(?m)^(?P<pre>[ \t]*CFBundleShortVersionString:[ \t]*)"""
            r"""(?P<val>"[^"]*"|'[^']*'|[^\s#]+)[ \t]*$"""
        ),
        lambda m, v: f'{m["pre"]}"{v}"',
    ),
)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def plan(root: str, version: str) -> tuple[list[tuple[str, str, str, str]], list[str]]:
    """Resolve every target without writing anything.

    Returns (edits, problems) where an edit is (path, relative path, old
    version, new file text).  Planning before writing keeps a miss on the
    third target from leaving the first two rewritten.
    """
    edits: list[tuple[str, str, str, str]] = []
    problems: list[str] = []

    for rel, pattern, render in TARGETS:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            problems.append(f"{rel}: file not found")
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        found = list(pattern.finditer(text))
        if not found:
            problems.append(
                f"{rel}: no line matching {pattern.pattern} — the format "
                f"changed and this stamp would have been a silent no-op"
            )
            continue
        if len(found) > 1:
            problems.append(
                f"{rel}: {len(found)} lines match {pattern.pattern} — "
                f"ambiguous, refusing to guess"
            )
            continue
        m = found[0]
        new_text = text[: m.start()] + render(m, version) + text[m.end():]
        edits.append((path, rel, _unquote(m["val"]), new_text))

    return edits, problems


def stamp(root: str, version: str, *, check: bool = False) -> int:
    """Rewrite (or, with ``check``, verify) every version-bearing file."""
    edits, problems = plan(root, version)

    if check:
        for _, rel, old, _ in edits:
            if old == version:
                print(f"  {rel}: {old}")
            else:
                problems.append(f"{rel}: is {old}, expected {version}")
    elif not problems:
        for path, rel, old, new_text in edits:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_text)
            print(f"  {rel}: {old} -> {version}")

    if problems:
        print("stamp_version: FAILED", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    if not check:
        # Read the files back rather than trusting the substitution: a render
        # bug that produced `version = ""1.4.0""` would still have written.
        written, verify_problems = plan(root, version)
        stale = [rel for _, rel, old, _ in written if old != version]
        if verify_problems or stale:
            print("stamp_version: post-write verification FAILED", file=sys.stderr)
            for p in verify_problems + [f"{r}: still not {version}" for r in stale]:
                print(f"  {p}", file=sys.stderr)
            return 1

    print(f"stamp_version: all {len(TARGETS)} file(s) at {version}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="release version, without the leading 'v'")
    ap.add_argument("--check", action="store_true",
                    help="verify every file already carries it; write nothing")
    ap.add_argument("--root", default=ROOT, help="repository root (default: this checkout)")
    args = ap.parse_args(argv)

    if not VERSION_RE.match(args.version):
        print(f"stamp_version: {args.version!r} is not a version", file=sys.stderr)
        return 2

    return stamp(args.root, args.version, check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
