"""``qc-core`` — the QuantaCrypt core as a JSON-lines helper process.

    qc-core            serve requests on stdin/stdout until EOF or shutdown
    qc-core --version  print the version and exit

Protocol: docs/design/core-service-protocol.md.
"""

from __future__ import annotations

import argparse
import signal
import sys


def _reconfigure(stream, **kwargs) -> None:
    """``TextIOWrapper.reconfigure`` where the stream has one; a pipe stood
    in by something else (tests, an embedding host) is left as it is."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(**kwargs)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qc-core", description=__doc__.split("\n")[0])
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args(argv)

    from quantacrypt import __version__
    if args.version:
        print(__version__)
        return 0

    from quantacrypt.core.service import Service, ServiceStop

    # Line-buffered, UTF-8 stdio regardless of locale; nothing but protocol
    # lines may reach stdout, so logging goes to stderr.  stdin too: the
    # PyInstaller bootloader starts the interpreter in isolated mode and
    # never reads PYTHONIOENCODING, so the frozen helper's stdin followed
    # the C locale and a non-ASCII password arrived surrogate-escaped and
    # failed as "damaged file" (review F-041).
    _reconfigure(sys.stdin, encoding="utf-8", errors="strict")
    _reconfigure(sys.stdout, encoding="utf-8", line_buffering=True)
    import logging
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="qc-core %(levelname)s %(name)s: %(message)s")
    svc = Service(sys.stdin, sys.stdout)

    # The only SIGTERM path in the helper (fuse_ops' handlers are not
    # installed here: mounts run on worker threads).  The handler must not
    # do the teardown itself — it runs on the main thread, which may be
    # blocked inside unmount_volume() holding _mount_lock; it only asks the
    # loop to stop, and run()'s finally does the work.
    stopping = {"raised": False}

    def _term(_signum, _frame):
        svc.request_stop()
        # Raise once, to unwind the blocked stdin read.  A second signal
        # (the client's escalation) must not interrupt the teardown that
        # is already running in run()'s finally.
        if not stopping["raised"]:
            stopping["raised"] = True
            raise ServiceStop()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    try:
        svc.run()
    except ServiceStop:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
