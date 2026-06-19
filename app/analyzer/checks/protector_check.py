"""Commercial protector / packer / obfuscator fingerprinting.

A recognized protector (iXGuard, Arxan, Promon, Appdome, Talsec, and similar)
encrypts strings, mangles control flow, and adds runtime integrity plus
anti-hook layers. Its presence is a strong defensive signal and materially
raises the effort and skill needed to crack the app, so this check rewards it
and names the product. Absence is reported as informational; the tamper verdict
itself lives in Integrity & Injection Detection.
"""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_TAMPER, AnalysisContext, CheckResult, Finding, Status
from .base import Check


class ProtectorCheck(Check):
    id = "protector"
    title = "Commercial Protector / Obfuscation"
    category = CATEGORY_TAMPER
    weight = 0.9
    explanation = (
        "Commercial protectors and obfuscators (iXGuard, Arxan, Promon SHIELD, "
        "Appdome, Talsec freeRASP, and similar) encrypt strings, mangle control "
        "flow, and add runtime integrity and anti-hook layers. Their presence is "
        "a strong defensive signal and raises the skill and time needed to crack "
        "the app well beyond what hand-rolled checks achieve."
    )
    remediation = (
        "For a high-value app, a commercial RASP or obfuscation layer raises the "
        "bar significantly. If one is expected here but not detected, confirm it "
        "is actually linked into the release build and not just the debug config."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        vendors: dict[str, str] = {}
        for label, tokens in sig.PROTECTORS.items():
            for t in tokens:
                if ctx.contains(t):
                    vendors[label] = t
                    break

        section_names = list(ctx.macho.sections) + list(ctx.macho.segments)
        sects = [
            s for s in section_names
            if any(p in s.lower() for p in sig.PROTECTOR_SECTIONS)
        ]

        if vendors or sects:
            findings = [
                Finding(label, "commercial protector / obfuscator", tok)
                for label, tok in vendors.items()
            ]
            findings += [Finding(s, "protector-specific Mach-O section") for s in sects[:6]]
            names = ", ".join(vendors) if vendors else "custom packer sections"
            return self.result(
                Status.PASS,
                f"Commercial protection detected ({names}). Static analysis and "
                "patching are significantly harder.",
                0.08, findings=findings,
            )

        return self.result(
            Status.INFO,
            "No recognized commercial protector or obfuscator. Any tamper "
            "resistance is bespoke; see Integrity & Injection Detection for the "
            "verdict.",
            0.0, weight=0.0,
        )
