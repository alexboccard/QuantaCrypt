#!/usr/bin/env python3
"""Per-file coverage gate.

coverage.py's ``fail_under`` is a single number over the whole project, so one
well-tested module can hide a barely-tested one — which is exactly what
happened here: the aggregate read 95% while ``ui/volume_manager.py`` sat at
11% and ``__main__.py`` at 0%, because the measured scope was ``core/`` alone.

This checks every file independently.

Usage:
    python scripts/check_coverage.py [--min 95] [--json coverage.json]

Expects a coverage JSON report to already exist (``coverage json``), or
generates one from the current ``.coverage`` data file.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Files allowed below the floor, each with the reason it cannot reach it.
#: Keep this list short and justified — it is the escape hatch, not the norm.
EXEMPT: dict[str, str] = {}


def _load(json_path: str) -> dict:
    if not os.path.exists(json_path):
        # --fail-under=0: the project's global fail_under would make this
        # generation step exit non-zero before we ever get to look per file,
        # which is the whole point of this script.
        subprocess.run(
            [sys.executable, "-m", "coverage", "json", "-o", json_path,
             "--fail-under=0"],
            cwd=ROOT, check=True,
        )
    with open(json_path) as f:
        return json.load(f)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min", type=float, default=95.0,
                    help="minimum percent per file (default: 95)")
    ap.add_argument("--json", default=os.path.join(ROOT, "coverage.json"))
    args = ap.parse_args()

    report = _load(args.json)
    files = report.get("files", {})
    if not files:
        print("check_coverage: no files in the coverage report — "
              "was the run scoped to nothing?", file=sys.stderr)
        return 2

    failures: list[tuple[str, float, int]] = []
    exempted: list[tuple[str, float]] = []
    rows: list[tuple[str, float, int]] = []

    for path, data in sorted(files.items()):
        summary = data["summary"]
        if summary["num_statements"] == 0:
            continue                      # nothing executable to cover
        pct = summary["percent_covered"]
        missing = summary["missing_lines"]
        rows.append((path, pct, missing))
        if pct + 1e-9 < args.min:
            (exempted if path in EXEMPT else failures).append(
                (path, pct, missing) if path not in EXEMPT else (path, pct)
            )

    width = max(len(p) for p, _, _ in rows)
    print(f"{'File'.ljust(width)}  {'Cover':>7}  {'Missing':>7}")
    for path, pct, missing in rows:
        flag = "" if pct + 1e-9 >= args.min else ("  (exempt)" if path in EXEMPT else "  <-- BELOW")
        print(f"{path.ljust(width)}  {pct:6.2f}%  {missing:7d}{flag}")

    for path, pct in exempted:
        print(f"\nexempt: {path} at {pct:.2f}% — {EXEMPT[path]}")

    sys.stdout.flush()      # keep the table above the verdict in CI logs
    if failures:
        print(f"\nFAIL: {len(failures)} file(s) below {args.min:g}% coverage:",
              file=sys.stderr)
        for path, pct, missing in failures:
            print(f"  {path}: {pct:.2f}% ({missing} statements uncovered)",
                  file=sys.stderr)
        return 1

    print(f"\nOK: every file is at or above {args.min:g}%.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
