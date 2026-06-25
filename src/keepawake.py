"""Keep the machine awake during a long run.

A long investigation left unattended can be interrupted if the OS idle-sleeps (the process
gets suspended; network/API calls can break on resume). This asks the OS not to idle-sleep
while the run is in progress. The request is released automatically when the process exits.

IMPORTANT caveat: this prevents *idle/timeout* sleep only. It does NOT override **closing a
laptop lid** — that's governed by the power plan's lid-close action, not this flag. For an
unattended run on a laptop, keep the lid open (or set lid-close to "do nothing").

Windows-only; a no-op (returns False) on other platforms. On macOS the equivalent is running
under `caffeinate`; on Linux, `systemd-inhibit`.
"""
from __future__ import annotations

import os


def prevent_idle_sleep() -> bool:
    """Request that the system not idle-sleep. Returns True if the request was applied."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        ES_CONTINUOUS = 0x80000000        # keep the setting until the next call / process exit
        ES_SYSTEM_REQUIRED = 0x00000001   # the system is in use; don't idle-sleep
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        return True
    except Exception:
        return False
