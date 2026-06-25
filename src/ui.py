"""Tiny, safe CLI color + emoji helpers.

Safety (the important part):
- **Color** (ANSI escapes) is emitted ONLY when stdout is an interactive TTY, NO_COLOR is
  unset, and (on Windows) VT processing could be enabled. When output is redirected to a
  file / piped / backgrounded, `c()` returns the text unchanged — so logs never get escape-
  code junk.
- **Emojis** are plain UTF-8 text. main.py forces stdout to UTF-8 with errors="replace", so
  emitting them can never raise UnicodeEncodeError (a terminal that can't render one shows a
  box, it does not crash). If you ever want them gone, set NO_EMOJI=1.

Usage:
    from .ui import c, EMOJI
    print(f"{EMOJI['search']} {c('Ingesting', 'bold', 'cyan')} {host} ...")
"""
from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m", "gray": "\033[90m",
}

EMOJI = {
    "search": "🔍", "brain": "🧠", "report": "📝", "ok": "✅", "warn": "⚠️",
    "error": "❌", "lead": "🔎", "folder": "📂", "chart": "📊", "broom": "🧹",
    "memory": "🧬", "clock": "⏱️", "resume": "🔄", "tool": "🔧",
}


def _enable_windows_vt() -> bool:
    """Turn on ANSI handling in the Windows console. No-op/True elsewhere."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except Exception:
        return False


# Force UTF-8 stdout/stderr so emojis can never raise UnicodeEncodeError. Done HERE (not
# only in main.py) so ANY entry point that imports a parser/ui — e.g. reusing a parser
# standalone — is protected too. errors="replace" means a stray char degrades to '?', never
# a crash.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def _can_emoji() -> bool:
    """True only if stdout can actually encode non-ASCII (UTF-8). Belt-and-suspenders: if the
    reconfigure above failed and we're still on a legacy codepage, blank the emojis."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in enc


_USE_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and _enable_windows_vt()
)
_USE_EMOJI = os.environ.get("NO_EMOJI") is None and _can_emoji()

if not _USE_EMOJI:
    EMOJI = {k: "" for k in EMOJI}


def c(text: str, *styles: str) -> str:
    """Wrap `text` in ANSI styles when color is active; otherwise return it unchanged."""
    if not _USE_COLOR or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}" if prefix else text


def color_enabled() -> bool:
    return _USE_COLOR
