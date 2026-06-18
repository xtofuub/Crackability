"""Does the app try to detect a jailbroken device?"""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_TAMPER, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class JailbreakDetectionCheck(Check):
    id = "jailbreak_detection"
    title = "Jailbreak Detection"
    category = CATEGORY_TAMPER
    weight = 1.3
    explanation = (
        "Cracked apps and tweaks run on jailbroken devices. An app that probes "
        "for jailbreak artefacts (Cydia/Sileo paths, MobileSubstrate, suspicious "
        "URL schemes) can refuse to run or disable premium features in that "
        "environment, which is the single most common anti-piracy control."
    )
    remediation = (
        "Add layered jailbreak detection (file/URL probes, fork()/sandbox tests, "
        "dyld image inspection) and — critically — verify the result server-side "
        "so a single client patch can't disable it. Consider IOSSecuritySuite or "
        "a commercial RASP SDK."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        path_hits = ctx.find_any(sig.JAILBREAK_PATHS, per=1, total=20)
        kw_hits = ctx.find_any(sig.JAILBREAK_KEYWORDS, per=1, total=12)
        sdk_hits = [name for name in sig.JAILBREAK_SDKS if ctx.contains(name)]

        findings: list[Finding] = []
        for needle, sample in path_hits:
            findings.append(Finding(needle, "jailbreak path probe", _trim(sample)))
        for needle, sample in kw_hits:
            if needle.lower() not in {f.label.lower() for f in findings}:
                findings.append(Finding(needle, "jailbreak indicator", _trim(sample)))
        for name in sdk_hits:
            findings.append(Finding(name, "jailbreak-detection library"))

        strong = bool(sdk_hits) or len(path_hits) >= 3
        weak = bool(path_hits) or bool(kw_hits)

        if strong:
            return self.result(
                Status.PASS,
                f"Jailbreak detection present ({len(findings)} indicators).",
                0.1, severity=Severity.NONE, findings=findings,
            )
        if weak:
            return self.result(
                Status.WARN,
                "Only minimal jailbreak indicators found — detection may be weak "
                "or easily bypassed.",
                0.5, severity=Severity.MEDIUM, findings=findings,
            )
        return self.result(
            Status.WARN,
            "No jailbreak detection found — the app will run unmodified on a "
            "jailbroken device, ready for tweaks and patches.",
            0.92, severity=Severity.MEDIUM,
        )


def _trim(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
