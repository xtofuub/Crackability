"""Extract printable strings from a binary — the equivalent of the `strings`
CLI, covering both ASCII and UTF-16LE, with de-duplication and a hard cap so a
very large app binary can't exhaust memory."""
from __future__ import annotations

import re

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


def extract_strings(data: bytes, min_len: int = 4, max_strings: int = 400_000) -> list[str]:
    """Return de-duplicated printable strings (ASCII + UTF-16LE) from *data*."""
    seen: dict[str, None] = {}

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in ascii_re.finditer(data):
        try:
            s = m.group().decode("ascii", "ignore")
        except Exception:
            continue
        if s not in seen:
            seen[s] = None
            if len(seen) >= max_strings:
                return list(seen.keys())

    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in utf16_re.finditer(data):
        try:
            s = m.group().decode("utf-16le", "ignore")
        except Exception:
            continue
        if s not in seen:
            seen[s] = None
            if len(seen) >= max_strings:
                break

    return list(seen.keys())


def extract_from_file(path: str, min_len: int = 4, max_bytes: int = 400 * 1024 * 1024,
                      max_strings: int = 400_000) -> list[str]:
    with open(path, "rb") as fh:
        data = fh.read(max_bytes)
    return extract_strings(data, min_len=min_len, max_strings=max_strings)
