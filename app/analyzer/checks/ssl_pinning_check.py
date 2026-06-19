"""TLS certificate / public-key pinning.

Without pinning, a proxy with a trusted root on the device can read and modify
API traffic, including subscription and entitlement responses. That is exactly
how a server response gets forged to grant premium. Pinning makes the app reject
connections that do not present the expected certificate or public key.
"""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_CONFIG, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class SslPinningCheck(Check):
    id = "ssl_pinning"
    title = "TLS Certificate Pinning"
    category = CATEGORY_CONFIG
    weight = 0.7
    explanation = (
        "Certificate pinning makes the app reject TLS connections that do not "
        "present an expected certificate or public key. Without it, a proxy with "
        "a trusted root installed on the device can read and modify API traffic, "
        "including subscription and entitlement responses, which is how an "
        "entitlement or receipt response gets forged."
    )
    remediation = (
        "Pin the certificate or public key for entitlement and purchase "
        "endpoints (TrustKit, native NSPinnedDomains, or your network layer's "
        "pinning), and fail closed on a mismatch."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        ats = ctx.bundle.info_plist.get("NSAppTransportSecurity")
        plist_pin = isinstance(ats, dict) and bool(ats.get("NSPinnedDomains"))
        tokens = [t for t in sig.PINNING_TOKENS if ctx.contains(t)]

        if plist_pin or tokens:
            findings: list[Finding] = []
            if plist_pin:
                findings.append(Finding("NSPinnedDomains", "native ATS pinning in Info.plist"))
            for t in tokens:
                findings.append(Finding(t, "certificate / public-key pinning"))
            names = ", ".join(tokens[:4]) if tokens else "NSPinnedDomains"
            return self.result(
                Status.PASS,
                f"Certificate pinning present ({names}). API and receipt traffic "
                "resists proxy interception.",
                0.2, findings=findings,
            )

        has_network = ctx.contains_any(sig.NETWORK_SURFACE) or \
            ctx.contains_any(sig.RECEIPT_LOCAL) or ctx.contains_any(sig.APPLE_VERIFY_HOSTS)
        if not has_network:
            return self.result(
                Status.INFO,
                "No network or purchase surface detected, so pinning is not "
                "applicable.",
                0.0, weight=0.0,
            )

        return self.result(
            Status.WARN,
            "No certificate pinning detected. API and receipt traffic can be "
            "intercepted and modified with a proxy, which is how entitlement and "
            "receipt responses get forged.",
            0.55, severity=Severity.MEDIUM,
        )
