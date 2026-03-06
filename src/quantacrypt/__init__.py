"""QuantaCrypt — Post-quantum file encryption."""

__version__ = "4.0.0"


def main():
    """Entry point — lazy import to avoid pulling in tkinter at package load."""
    from quantacrypt.__main__ import main as _main
    return _main()


__all__ = ["main", "__version__"]
