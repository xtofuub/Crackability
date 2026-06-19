"""Best-effort Swift symbol de-mangling.

Modern apps are largely Swift, and Swift symbols are mangled (for example
`$s10RevenueCat15EntitlementInfoV8isActiveSbvg`). Plain substring checks miss the
human identifiers buried inside. This recovers them two ways:

1. If a `swift-demangle` binary is on PATH (Xcode / a Swift toolchain), use it for
   full, accurate names.
2. Always also extract the length-prefixed identifier runs straight out of the
   mangled symbol. This needs no toolchain (so it works on Windows) and surfaces
   the module / type / member names like RevenueCat, EntitlementInfo, isActive.
"""
from __future__ import annotations

import re
import shutil
import subprocess

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_SYMBOLS = 200_000


def _looks_mangled(sym: str) -> bool:
    return sym.startswith(("$s", "$S", "_$s", "_$S", "_T")) or "$s" in sym[:6]


def swift_identifiers(sym: str) -> list[str]:
    """Pull length-prefixed identifier runs from a mangled Swift symbol.

    Swift encodes identifiers as ``<decimal length><that many chars>``, so a run
    like ``10RevenueCat`` yields ``RevenueCat``.
    """
    out: list[str] = []
    i, n = 0, len(sym)
    while i < n:
        if sym[i].isdigit():
            j = i
            while j < n and sym[j].isdigit():
                j += 1
            try:
                length = int(sym[i:j])
            except ValueError:
                i = j
                continue
            if 0 < length <= 100 and j + length <= n:
                ident = sym[j:j + length]
                if _IDENT.fullmatch(ident):
                    out.append(ident)
                i = j + length
                continue
            i = j
        else:
            i += 1
    return out


def _tool_demangle(mangled: list[str]) -> list[str]:
    exe = shutil.which("swift-demangle")
    if not exe or not mangled:
        return []
    try:
        proc = subprocess.run(
            [exe], input="\n".join(mangled[:20000]),
            capture_output=True, text=True, timeout=30,
        )
        return [ln for ln in proc.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def enrich(symbols) -> set[str]:
    """Return extra searchable tokens recovered from mangled Swift symbols."""
    extra: set[str] = set()
    mangled: list[str] = []
    for i, s in enumerate(symbols):
        if i >= _MAX_SYMBOLS:
            break
        if _looks_mangled(s):
            mangled.append(s)
            extra.update(swift_identifiers(s))
    for line in _tool_demangle(mangled):
        extra.update(_IDENT.findall(line))
    return {t for t in extra if len(t) >= 3}
