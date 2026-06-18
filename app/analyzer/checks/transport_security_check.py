"""App Transport Security posture from Info.plist."""
from __future__ import annotations

from ..models import CATEGORY_CONFIG, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class TransportSecurityCheck(Check):
    id = "transport_security"
    title = "App Transport Security (ATS)"
    category = CATEGORY_CONFIG
    weight = 0.4
    explanation = (
        "ATS forces TLS for network traffic. Disabling it "
        "(NSAllowsArbitraryLoads) lets the app talk over plain HTTP, which makes "
        "it trivial to intercept and tamper with API traffic — including licence "
        "and entitlement calls — using a proxy."
    )
    remediation = (
        "Remove NSAllowsArbitraryLoads, scope any exceptions to specific domains, "
        "and pin certificates for entitlement / purchase endpoints."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        ats = ctx.bundle.info_plist.get("NSAppTransportSecurity")
        if not isinstance(ats, dict):
            return self.result(
                Status.PASS,
                "No ATS exceptions — default TLS enforcement applies.",
                0.1,
            )

        findings: list[Finding] = []
        arbitrary = bool(ats.get("NSAllowsArbitraryLoads"))
        media = bool(ats.get("NSAllowsArbitraryLoadsForMedia"))
        web = bool(ats.get("NSAllowsArbitraryLoadsInWebContent"))
        if arbitrary:
            findings.append(Finding("NSAllowsArbitraryLoads", "ATS disabled globally — HTTP allowed"))
        if media:
            findings.append(Finding("NSAllowsArbitraryLoadsForMedia", "cleartext media allowed"))
        if web:
            findings.append(Finding("NSAllowsArbitraryLoadsInWebContent", "cleartext web content allowed"))

        domains = ats.get("NSExceptionDomains")
        insecure_domains = []
        if isinstance(domains, dict):
            for dom, cfg in domains.items():
                if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
                    insecure_domains.append(dom)
                    findings.append(Finding(dom, "per-domain insecure HTTP exception"))

        if arbitrary:
            return self.result(
                Status.WARN,
                "ATS is disabled globally — all traffic may use cleartext HTTP.",
                0.7, severity=Severity.MEDIUM, findings=findings,
            )
        if insecure_domains or media or web:
            return self.result(
                Status.WARN,
                "ATS exceptions allow some cleartext traffic.",
                0.45, severity=Severity.LOW, findings=findings,
            )
        return self.result(
            Status.PASS,
            "ATS configured with TLS-only exceptions.",
            0.15, findings=findings,
        )
