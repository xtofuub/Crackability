"""Inventory embedded frameworks and fingerprint known third-party SDKs."""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_FRAMEWORKS, AnalysisContext, CheckResult, Finding, Status
from .base import Check


class FrameworksCheck(Check):
    id = "frameworks"
    title = "Embedded Frameworks & SDKs"
    category = CATEGORY_FRAMEWORKS
    weight = 0.0  # informational — does not move the score
    explanation = (
        "The third-party SDKs an app bundles shape its attack surface and its "
        "defences. Commercial hardening / RASP SDKs make cracking much harder; "
        "server-validating monetization SDKs protect subscriptions; cross-"
        "platform runtimes (Flutter, React Native, Unity) change where the "
        "interesting logic actually lives."
    )
    remediation = ""

    def run(self, ctx: AnalysisContext) -> CheckResult:
        detected: dict[str, str] = {}  # display -> category
        for token, (display, category) in sig.KNOWN_SDKS.items():
            if ctx.contains(token):
                detected[display] = category

        findings: list[Finding] = []

        # Group SDKs by category for a tidy listing.
        by_cat: dict[str, list[str]] = {}
        for display, category in detected.items():
            by_cat.setdefault(category, []).append(display)
        for category in sorted(by_cat):
            names = sorted(set(by_cat[category]))
            findings.append(Finding(category, ", ".join(names)))

        # Raw embedded framework / plugin bundles from disk.
        for fw in ctx.bundle.frameworks:
            findings.append(Finding(fw, "embedded framework", "Frameworks/"))
        for pg in ctx.bundle.plugins:
            findings.append(Finding(pg, "app extension", "PlugIns/"))

        n_sdks = len(detected)
        n_fw = len(ctx.bundle.frameworks)
        hardening = [d for d, c in detected.items() if c == "App hardening"]
        summary = f"{n_sdks} known SDK(s) fingerprinted across {n_fw} embedded framework(s)."
        if hardening:
            summary += f" Commercial hardening detected: {', '.join(hardening)}."

        return self.result(Status.INFO, summary, 0.0, weight=0.0, findings=findings)
