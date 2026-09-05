#!/usr/bin/env python3
"""Print the hash-pinned requirement blocks for named packages from the lock.

    python scripts/lock_subset.py setuptools > build-requirements.txt
    pip install --require-hashes -r build-requirements.txt

Why this exists: ``pip install --require-hashes -r requirements-lock.txt``
pins what is *installed*, but pip's PEP 517 build isolation fetches the
build backend (setuptools) unpinned to build any sdist in the lock — fusepy
is one — and to build this project.  Installing the backend from the lock
first and then passing ``--no-build-isolation`` closes that gap without a
second lock file to keep in sync.
"""

from __future__ import annotations

import argparse
import re
import sys

_NAME_RE = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _blocks(text: str):
    """Yield each requirement with its backslash-continued hash lines."""
    block: list[str] = []
    for line in text.splitlines():
        if not block and (not line.strip() or line.lstrip().startswith("#")):
            continue
        block.append(line)
        if not line.rstrip().endswith("\\"):
            yield block
            block = []
    if block:
        yield block


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--lock", default="requirements-lock.txt")
    ap.add_argument("names", nargs="+", help="package names to extract")
    args = ap.parse_args(argv)

    wanted = {_canonical(n) for n in args.names}
    found: set[str] = set()
    with open(args.lock, encoding="utf-8") as f:
        text = f.read()
    for block in _blocks(text):
        m = _NAME_RE.match(block[0])
        if not m:
            continue
        name = _canonical(m.group(1))
        if name in wanted:
            found.add(name)
            print("\n".join(block))
    missing = sorted(wanted - found)
    if missing:
        print(f"lock_subset: not in {args.lock}: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
