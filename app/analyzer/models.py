"""Core data model: bundle metadata, Mach-O facts, check results and the shared
analysis context with fast search helpers used by every check."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterable, Iterator, Optional


# --------------------------------------------------------------------------- #
#  Enums
# --------------------------------------------------------------------------- #
class Status(str, Enum):
    PASS = "PASS"    # protection present / good posture
    WARN = "WARN"    # weakness / protection missing
    FAIL = "FAIL"    # serious weakness, clearly exploitable
    INFO = "INFO"    # informational, no judgement
    ERROR = "ERROR"  # the check could not run

    @property
    def rank(self) -> int:
        return {"PASS": 0, "INFO": 1, "WARN": 2, "FAIL": 3, "ERROR": 1}[self.value]


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Category display names (also drives section ordering in the UI)
CATEGORY_BINARY = "Binary Protection"
CATEGORY_TAMPER = "Anti-Tampering"
CATEGORY_MONEY = "Monetization & Receipts"
CATEGORY_SECRETS = "Secrets & Cryptography"
CATEGORY_FRAMEWORKS = "Frameworks & SDKs"
CATEGORY_CONFIG = "App Configuration"

CATEGORY_ORDER = [
    CATEGORY_BINARY,
    CATEGORY_TAMPER,
    CATEGORY_MONEY,
    CATEGORY_SECRETS,
    CATEGORY_FRAMEWORKS,
    CATEGORY_CONFIG,
]


# --------------------------------------------------------------------------- #
#  Findings & results
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A single piece of evidence inside a check."""
    label: str
    detail: str = ""
    location: str = ""

    def to_dict(self) -> dict:
        return {"label": self.label, "detail": self.detail, "location": self.location}


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    status: Status
    summary: str = ""
    risk: float = 0.0          # 0..1 contribution to crackability on this axis
    weight: float = 1.0        # importance multiplier in the overall score
    severity: Severity = Severity.NONE
    explanation: str = ""      # "why this matters"
    remediation: str = ""      # how to harden
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "status": self.status.value,
            "summary": self.summary,
            "risk": round(self.risk, 3),
            "weight": self.weight,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
#  Bundle + Mach-O facts
# --------------------------------------------------------------------------- #
@dataclass
class AppBundle:
    ipa_path: str
    app_path: str
    executable_path: str
    executable_name: str = ""
    bundle_id: str = ""
    display_name: str = ""
    version: str = ""
    build: str = ""
    min_os: str = ""
    platforms: list[str] = field(default_factory=list)
    sdk_name: str = ""
    info_plist: dict = field(default_factory=dict)
    icon_data: Optional[bytes] = None
    frameworks: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    file_size: int = 0

    def to_dict(self) -> dict:
        keys = ("ipa_path", "app_path", "executable_name", "bundle_id",
                "display_name", "version", "build", "min_os", "platforms",
                "sdk_name", "frameworks", "plugins", "file_size")
        return {k: getattr(self, k) for k in keys}


@dataclass
class MachOInfo:
    path: str
    parsed: bool = False
    error: Optional[str] = None
    arch: str = ""
    available_archs: list[str] = field(default_factory=list)
    cpu_subtype: int = 0
    file_type: str = ""
    flags: list[str] = field(default_factory=list)
    is_pie: bool = False
    has_nx: bool = False
    cryptid: Optional[int] = None
    is_encrypted: bool = False
    has_stack_canary: bool = False
    uses_arc: bool = False
    is_arm64e: bool = False
    has_code_signature: bool = False
    is_restricted: bool = False
    n_load_commands: int = 0
    libraries: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    exported_symbols: list[str] = field(default_factory=list)
    segments: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    entitlements: dict = field(default_factory=dict)
    uuid: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        keys = ("path", "parsed", "error", "arch", "available_archs",
                "file_type", "flags", "is_pie", "has_nx", "cryptid",
                "is_encrypted", "has_stack_canary", "uses_arc", "is_arm64e",
                "has_code_signature", "is_restricted", "n_load_commands",
                "libraries", "segments", "sections", "rpaths", "entitlements",
                "uuid", "size")
        return {k: getattr(self, k) for k in keys}


# --------------------------------------------------------------------------- #
#  Analysis context — shared input handed to every check
# --------------------------------------------------------------------------- #
@dataclass
class AnalysisContext:
    bundle: AppBundle
    macho: MachOInfo
    strings: list[str] = field(default_factory=list)
    symbols: set[str] = field(default_factory=set)
    libraries: list[str] = field(default_factory=list)
    framework_names: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._blob = "\n".join(self.strings)
        self._sym_blob = "\n".join(self.symbols)
        self._all_blob = self._blob + "\n" + self._sym_blob + "\n" + "\n".join(self.framework_names)
        self._all_blob_lower = self._all_blob.lower()

    # -- presence ---------------------------------------------------------- #
    def contains(self, needle: str, case_sensitive: bool = False) -> bool:
        if case_sensitive:
            return needle in self._all_blob
        return needle.lower() in self._all_blob_lower

    def contains_any(self, needles: Iterable[str], case_sensitive: bool = False) -> bool:
        return any(self.contains(n, case_sensitive) for n in needles)

    # -- evidence ---------------------------------------------------------- #
    def _iter_all(self) -> Iterator[str]:
        yield from self.strings
        yield from self.symbols
        yield from self.framework_names

    def find(self, needle: str, case_sensitive: bool = False, limit: int = 8) -> list[str]:
        out: list[str] = []
        nl = needle if case_sensitive else needle.lower()
        seen: set[str] = set()
        for s in self._iter_all():
            hay = s if case_sensitive else s.lower()
            if nl in hay and s not in seen:
                seen.add(s)
                out.append(s)
                if len(out) >= limit:
                    break
        return out

    def find_any(self, needles: Iterable[str], case_sensitive: bool = False,
                 per: int = 1, total: int = 24) -> list[tuple[str, str]]:
        """Return (needle, matched_string) pairs across all needles."""
        out: list[tuple[str, str]] = []
        for n in needles:
            for hit in self.find(n, case_sensitive, limit=per):
                out.append((n, hit))
                if len(out) >= total:
                    return out
        return out

    def regex(self, pattern: str, flags: int = re.IGNORECASE, limit: int = 24,
              strings_only: bool = True) -> list[tuple[str, str]]:
        rx = re.compile(pattern, flags)
        src = self.strings if strings_only else list(self._iter_all())
        out: list[tuple[str, str]] = []
        for s in src:
            m = rx.search(s)
            if m:
                out.append((s, m.group(0)))
                if len(out) >= limit:
                    break
        return out

    def has_symbol(self, name: str) -> bool:
        return name in self.symbols

    def find_symbols(self, substr: str, limit: int = 10) -> list[str]:
        sl = substr.lower()
        out = []
        for s in self.symbols:
            if sl in s.lower():
                out.append(s)
                if len(out) >= limit:
                    break
        return out


# --------------------------------------------------------------------------- #
#  Final report
# --------------------------------------------------------------------------- #
@dataclass
class AnalysisReport:
    bundle: AppBundle
    macho: MachOInfo
    results: list[CheckResult]
    score: int
    verdict: str
    verdict_subtitle: str
    verdict_key: str
    tool_version: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Status}
        for r in self.results:
            c[r.status.value] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "score": self.score,
            "verdict": self.verdict,
            "verdict_subtitle": self.verdict_subtitle,
            "verdict_key": self.verdict_key,
            "counts": self.counts,
            "bundle": self.bundle.to_dict(),
            "macho": self.macho.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }
