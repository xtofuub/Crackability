"""Parse a Mach-O executable with LIEF and distil the facts the checks need.

Everything is defensively wrapped: LIEF's API has shifted across versions and
some fields are absent on unusual binaries, so any single failure degrades to a
sensible default rather than crashing the whole analysis.
"""
from __future__ import annotations

import plistlib
import re

from .models import MachOInfo

try:
    import lief  # type: ignore
    _HAS_LIEF = True
except Exception:                      # pragma: no cover - import guard
    lief = None                        # type: ignore
    _HAS_LIEF = False

# arm64e subtype (low byte) — indicates pointer authentication support.
_CPU_SUBTYPE_ARM64E = 2

_ENTITLEMENT_RE = re.compile(
    rb"<\?xml[^>]*\?>\s*<!DOCTYPE plist.*?</plist>|<plist[^>]*>.*?</plist>",
    re.DOTALL,
)


def lief_available() -> bool:
    return _HAS_LIEF


def _names(seq) -> list[str]:
    out: list[str] = []
    for x in seq or []:
        n = getattr(x, "name", None)
        if n is None:
            n = str(x)
        if n:
            out.append(str(n))
    return out


def _arch_name(binary) -> str:
    try:
        ct = binary.header.cpu_type
        return getattr(ct, "name", str(ct)).replace("CPU_TYPE.", "")
    except Exception:
        return "unknown"


def _extract_entitlements(raw: bytes) -> dict:
    """Pull the entitlements plist out of the embedded code signature (or an
    embedded mobileprovision) by locating a plist blob with entitlement keys."""
    markers = (b"application-identifier", b"get-task-allow", b"com.apple.developer")
    for m in _ENTITLEMENT_RE.finditer(raw):
        blob = m.group()
        if not any(mk in blob for mk in markers):
            continue
        try:
            data = plistlib.loads(blob)
            if isinstance(data, dict) and any(
                k in data for k in ("application-identifier", "get-task-allow")
            ):
                # mobileprovision wraps entitlements one level down.
                if "Entitlements" in data and isinstance(data["Entitlements"], dict):
                    return data["Entitlements"]
                return data
        except Exception:
            continue
    return {}


def _select_slice(binaries: list):
    """Prefer a plain arm64 slice (what sideloaders run), then arm64e, then any."""
    arm64 = None
    arm64e = None
    for b in binaries:
        arch = _arch_name(b)
        if arch == "ARM64":
            sub = 0
            try:
                sub = int(b.header.cpu_subtype) & 0xFF
            except Exception:
                pass
            if sub == _CPU_SUBTYPE_ARM64E:
                arm64e = arm64e or b
            else:
                arm64 = arm64 or b
    return arm64 or arm64e or (binaries[0] if binaries else None)


def parse_macho(path: str) -> MachOInfo:
    info = MachOInfo(path=path)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        info.size = len(raw)
    except Exception as exc:
        info.error = f"could not read executable: {exc}"
        return info

    if not _HAS_LIEF:
        info.error = "LIEF not available"
        return info

    try:
        fat = lief.MachO.parse(path)
    except Exception as exc:
        info.error = f"LIEF parse error: {exc}"
        return info

    if fat is None:
        info.error = "not a Mach-O binary"
        return info

    try:
        binaries = list(fat)
    except Exception:
        binaries = [fat]

    info.available_archs = [_arch_name(b) for b in binaries]
    info.is_arm64e = any(
        _arch_name(b) == "ARM64" and (int(getattr(b.header, "cpu_subtype", 0)) & 0xFF) == _CPU_SUBTYPE_ARM64E
        for b in binaries
    )

    b = _select_slice(binaries)
    if b is None:
        info.error = "no Mach-O slices found"
        return info

    info.parsed = True
    info.arch = _arch_name(b)

    # Header facts -------------------------------------------------------- #
    try:
        info.cpu_subtype = int(b.header.cpu_subtype)
        info.file_type = getattr(b.header.file_type, "name", str(b.header.file_type))
        info.n_load_commands = int(getattr(b.header, "nb_cmds", 0))
        info.flags = [getattr(f, "name", str(f)) for f in getattr(b.header, "flags_list", [])]
    except Exception:
        pass

    for attr, name in (("is_pie", "is_pie"), ("has_nx", "has_nx")):
        try:
            setattr(info, attr, bool(getattr(b, name)))
        except Exception:
            pass

    # Encryption ---------------------------------------------------------- #
    try:
        if getattr(b, "has_encryption_info", False):
            enc = b.encryption_info
            cid = getattr(enc, "crypt_id", None)
            if cid is None:
                cid = getattr(enc, "cryptid", None)
            info.cryptid = int(cid) if cid is not None else None
            info.is_encrypted = bool(info.cryptid)
    except Exception:
        pass

    # Code signature ------------------------------------------------------ #
    try:
        info.has_code_signature = bool(getattr(b, "has_code_signature", False))
    except Exception:
        pass

    # Libraries / symbols / segments ------------------------------------- #
    try:
        info.libraries = _names(getattr(b, "libraries", []))
    except Exception:
        pass

    imported, exported, allsyms = [], [], []
    try:
        imported = _names(getattr(b, "imported_functions", []))
    except Exception:
        pass
    try:
        exported = _names(getattr(b, "exported_functions", []))
    except Exception:
        pass
    try:
        allsyms = _names(getattr(b, "symbols", []))
    except Exception:
        pass
    info.imported_symbols = imported
    info.exported_symbols = exported

    combined = set(imported) | set(allsyms)
    info.has_stack_canary = any("stack_chk" in s for s in combined)
    info.uses_arc = any(
        tok in s
        for s in combined
        for tok in ("objc_release", "objc_storeStrong", "objc_retainAutoreleased")
    )

    try:
        info.segments = _names(getattr(b, "segments", []))
    except Exception:
        pass
    try:
        sects = []
        for s in getattr(b, "sections", []):
            seg = getattr(s, "segment_name", None)
            if not seg:
                seg = getattr(getattr(s, "segment", None), "name", "")
            sects.append(f"{seg},{getattr(s, 'name', '')}".strip(","))
        info.sections = sects
    except Exception:
        pass

    info.is_restricted = any("RESTRICT" in (seg or "").upper() for seg in info.segments) or any(
        "restrict" in sec.lower() for sec in info.sections
    )

    try:
        info.rpaths = [getattr(r, "path", str(r)) for r in getattr(b, "rpaths", [])]
    except Exception:
        pass

    # UUID ---------------------------------------------------------------- #
    try:
        uid = getattr(b, "uuid", None)
        if uid:
            info.uuid = "".join(f"{x:02X}" for x in uid)
    except Exception:
        pass

    # Entitlements -------------------------------------------------------- #
    try:
        info.entitlements = _extract_entitlements(raw)
    except Exception:
        info.entitlements = {}

    return info
