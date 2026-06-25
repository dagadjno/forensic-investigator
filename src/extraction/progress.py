"""Shared progress helpers for the deterministic parsers.

`status()` writes a transient line that overwrites itself (carriage return) on a TTY, so a
long parse shows a live counter on ONE line instead of scrolling thousands. When stdout is
redirected (e.g. a backgrounded run logging to a file) it is a no-op, so the log keeps only
the permanent lines written by `status_done()` / `print()`.
"""
from __future__ import annotations

import shutil
import sys


def _width() -> int:
    return shutil.get_terminal_size(fallback=(100, 24)).columns - 1


def status(msg: str) -> None:
    """Transient in-place progress line (TTY only; no-op when redirected)."""
    if not sys.stdout.isatty():
        return
    w = _width()
    sys.stdout.write("\r" + msg[:w].ljust(w))
    sys.stdout.flush()


def status_done(msg: str) -> None:
    """Clear the transient line (TTY only), then write `msg` as a permanent line."""
    if sys.stdout.isatty():
        w = _width()
        sys.stdout.write("\r" + " " * w + "\r")
    print(msg, flush=True)
