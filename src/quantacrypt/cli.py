"""``qc-core`` — the QuantaCrypt core as a JSON-lines helper process.

    qc-core            serve requests on stdin/stdout until EOF or shutdown
    qc-core --version  print the version and exit

Protocol: docs/design/core-service-protocol.md.
"""

from __future__ import annotations

import argparse
import signal
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qc-core", description=__doc__.split("\n")[0])
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args(argv)

    from quantacrypt import __version__
    if args.version:
        print(__version__)
        return 0

    from quantacrypt.core.service import Service

    # Line-buffered, UTF-8 stdio regardless of locale; nothing but protocol
    # lines may reach stdout, so logging goes to stderr.
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)  # type: ignore[union-attr]
    svc = Service(sys.stdin, sys.stdout)

    def _term(_signum, _frame):
        svc.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _term)
    svc.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
