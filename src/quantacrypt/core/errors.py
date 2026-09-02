"""User-facing error text and machine-readable error codes.

Lives in core (not ui) so the service and every front end share one
vocabulary.  ``friendly_error`` returns the sentence a person should read;
``classify_error`` adds the code a program should branch on.
"""

from __future__ import annotations

import errno as _errno


def friendly_error(exc: BaseException) -> str:
    """Translate a raw exception into a user-facing, actionable message.

    Known shapes are mapped to plain English with a next step; anything else
    falls back to ``str(exc)`` (or the type name when the message is empty —
    cryptography's ``InvalidTag`` stringifies to "").
    """
    if isinstance(exc, FileNotFoundError):
        return "File not found — it may have been moved or deleted."
    if isinstance(exc, PermissionError):
        return ("Access denied — check you have permission to read / write "
                "this file, and that it isn't open in another app.")
    if isinstance(exc, IsADirectoryError):
        return "That path is a folder, not a file."
    if isinstance(exc, OSError):
        if exc.errno == _errno.ENOSPC:
            return "Disk is full — free up space and try again."
        if exc.errno == _errno.EIO:
            return "Disk read / write error — the drive may be failing."
        if exc.errno == _errno.EROFS:
            return "Destination is read-only."

    msg = str(exc)
    lower = (msg or type(exc).__name__).lower()
    if "invalidtag" in lower or "authentication" in lower:
        return ("The password or shares are incorrect, or the file has been "
                "modified since it was encrypted.")
    if "unsupported" in lower and "version" in lower:
        return ("This file was created with a newer version of QuantaCrypt. "
                "Please update the app.")
    if "older" in lower and "version" in lower:
        return ("This file uses an older format. Decrypt it with the "
                "original app version, then re-encrypt with this one.")
    if "truncat" in lower or "appears truncated" in lower:
        return ("The file appears to be truncated or incomplete — "
                "re-download or restore from backup.")
    if "hmac" in lower:
        return ("The file's integrity check failed — the file may be "
                "corrupt or tampered with.")
    if not msg:
        return f"{type(exc).__name__} (no additional detail)"
    return msg


def classify_error(exc: BaseException) -> tuple[str, str, str]:
    """Return ``(code, message, detail)`` for an exception.

    Codes: wrong_credentials, cancelled, not_found, permission_denied, io,
    format, unsupported, busy, internal.
    """
    from quantacrypt.core.crypto import CancelledOperation

    detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    message = friendly_error(exc)
    if isinstance(exc, CancelledOperation):
        return "cancelled", "Cancelled — nothing was written.", detail
    if isinstance(exc, FileNotFoundError):
        return "not_found", message, detail
    if isinstance(exc, PermissionError):
        return "permission_denied", message, detail
    if isinstance(exc, OSError):
        return "io", message, detail
    lower = (str(exc) or type(exc).__name__).lower()
    if "invalidtag" in lower or "authentication" in lower or "incorrect" in lower:
        return "wrong_credentials", message, detail
    if "already mounted" in lower or "in use" in lower or "busy" in lower:
        return "busy", message, detail
    if "version" in lower and ("newer" in lower or "older" in lower or "unsupported" in lower):
        return "unsupported", message, detail
    if isinstance(exc, ValueError):
        return "format", message, detail
    if isinstance(exc, (NotImplementedError, RuntimeError)) and "fuse" in lower:
        return "unsupported", message, detail
    return "internal", message, detail
