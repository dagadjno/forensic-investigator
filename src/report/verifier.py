"""Citation-verification pass.

The tools already reject uncited locators at write time, but LLMs can still
fabricate plausible-looking strings, so we independently confirm every cited locator
resolves to real parsed data. Anything that doesn't is flagged in the report.
"""
from __future__ import annotations

from ..store.case_db import CaseDB


def resolves(case: CaseDB, locator: str) -> bool:
    """True if the locator points at something that actually exists in the case data."""
    if locator.startswith("file:"):
        rest = locator[len("file:"):]
        # file:<path> or file:<path>:<line>
        path = rest
        if ":" in rest:
            head, tail = rest.rsplit(":", 1)
            if tail.isdigit():
                path = head
        return case.conn.execute("SELECT 1 FROM files WHERE path=?", (path,)).fetchone() is not None
    # otherwise treat as an event locator
    return case.conn.execute("SELECT 1 FROM events WHERE locator=?", (locator,)).fetchone() is not None


def verify_locators(case: CaseDB, locators: list[str]) -> list[str]:
    """Return the subset that fail to resolve."""
    return [loc for loc in locators if not resolves(case, loc)]
