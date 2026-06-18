"""Integrity / tamper / injection (Frida, MobileSubstrate) detection."""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_TAMPER, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class AntiTamperCheck(Check):
    id = "anti_tamper"
    title = "Integrity & Injection Detection"
    category = CATEGORY_TAMPER
    weight = 1.3
    explanation = (
        "Cracks work by patching the binary or injecting a dylib (MobileSubstrate "
        "tweaks, Frida gadget, fishhook). Self-integrity checks (verifying the "
        "code signature / a checksum) and injection detection (walking the dyld "
        "image list for unexpected libraries) let an app notice it has been "
        "modified and react."
    )
    remediation = (
        "Verify the embedded code signature / a hash of __TEXT at runtime, walk "
        "the loaded-image list for MobileSubstrate/Frida, check DYLD_INSERT_"
        "LIBRARIES, and enforce the outcome server-side. A commercial RASP SDK "
        "(GuardSquare, Appdome, Promon, Talsec) automates this."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        sym_hits = [s for s in sig.ANTITAMPER_SYMBOLS if ctx.find_symbols(s) or ctx.contains(s)]
        kw_hits = ctx.find_any(sig.ANTITAMPER_KEYWORDS, per=1, total=16)
        hardening = [t for t in sig.HARDENING_SDK_TOKENS if ctx.contains(t)]

        findings: list[Finding] = []
        for t in hardening:
            findings.append(Finding(t, "commercial app-hardening / RASP SDK"))
        for s in sym_hits:
            findings.append(Finding(s, "integrity / image-inspection API"))
        for needle, sample in kw_hits:
            findings.append(Finding(needle, "integrity / injection indicator", _trim(sample)))

        injection_aware = ctx.contains("_dyld_image_count") or ctx.contains("frida") or \
            ctx.contains("MSHookFunction") or ctx.contains("fishhook")
        integrity_aware = ctx.contains("SignerIdentity") or ctx.contains("_CodeSignature") or \
            ctx.contains_any(("integrityCheck", "verifyIntegrity", "checksumValidation"))

        if hardening:
            return self.result(
                Status.PASS,
                f"Commercial app-hardening present ({', '.join(hardening)}).",
                0.05, findings=findings,
            )
        if integrity_aware and injection_aware:
            return self.result(
                Status.PASS,
                "Both integrity verification and injection detection present.",
                0.2, findings=findings,
            )
        if integrity_aware or injection_aware:
            return self.result(
                Status.WARN,
                "Partial tamper protection — only one of integrity / injection "
                "detection was found.",
                0.55, severity=Severity.LOW, findings=findings,
            )
        return self.result(
            Status.WARN,
            "No integrity or injection detection — the binary can be patched or "
            "have a tweak injected without the app noticing.",
            0.88, severity=Severity.HIGH,
        )


def _trim(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
