"""QuantaCrypt — Post-quantum file encryption."""

from importlib.metadata import version as _v, PackageNotFoundError as _E

try:
    __version__ = _v("quantacrypt")
except _E:               # running from source or PyInstaller bundle
    __version__ = "1.2.0"  # keep in sync with pyproject.toml


def main():  # pragma: no cover
    """Entry point — lazy import to avoid pulling in tkinter at package load."""
    from quantacrypt.__main__ import main as _main
    return _main()


__all__ = ["main", "__version__"]
