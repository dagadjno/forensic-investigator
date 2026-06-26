"""Shared text detection + BOM-aware decoding.

Triage collections carry plain-text dumps with non-text extensions: Autorunsc writes
UTF-16 `.dat`, while `schtasks` / `tasklist` / `ipconfig` write ASCII `.dat`. The file
cataloger uses `looks_text()` so those are flagged readable (is_text=1), and the read
tools use `read_text_auto()` so a UTF-16/BOM file decodes correctly instead of coming
back as mojibake. Binary blobs (registry hives, SRUDB.dat ESE, OBJECTS.DATA, PE files)
are still correctly classified as non-text.
"""
from __future__ import annotations

from pathlib import Path

# Extensions trusted as text without sniffing.
TEXT_EXTS = {".txt", ".csv", ".log", ".ini", ".htm", ".html", ".json", ".xml",
             ".ps1", ".bat", ".md"}
_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")


def looks_text(fp: Path, size: int, suffix: str | None = None) -> bool:
    """True if fp can be read as text. A known text extension passes immediately; otherwise
    sniff the first 4 KB: a UTF-16/UTF-8 BOM => text; a NUL byte (without such a BOM) =>
    binary (registry hives, ESE DBs, OBJECTS.DATA, PE files); else require mostly-printable.
    Conservative: a stray control byte in the first block reads as binary."""
    suf = (suffix if suffix is not None else fp.suffix).lower()
    if suf in TEXT_EXTS:
        return True
    if size == 0:
        return False
    try:
        with fp.open("rb") as f:
            chunk = f.read(4096)
    except OSError:
        return False
    if chunk.startswith(_BOMS):
        return True
    if b"\x00" in chunk:
        return False
    nontext = sum(1 for b in chunk if b < 0x09 or 0x0e <= b < 0x20 or b == 0x7f)
    return nontext / len(chunk) < 0.05


def read_text_auto(fp: Path) -> str:
    """Read a text file honoring a UTF-16/UTF-8 BOM; fall back to UTF-8 with replacement."""
    data = fp.read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data.decode("utf-8-sig", errors="replace")
    return data.decode("utf-8", errors="replace")
