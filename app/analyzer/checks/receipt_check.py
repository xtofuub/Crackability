"""How are purchases / subscriptions validated? Local validation is spoofable."""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_MONEY, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class ReceiptValidationCheck(Check):
    id = "receipt_validation"
    title = "Purchase / Subscription Validation"
    category = CATEGORY_MONEY
    weight = 1.6
    explanation = (
        "Subscription cracks work by faking a valid purchase. If receipt "
        "validation happens on-device (parsing appStoreReceiptURL / a PKCS7 "
        "receipt locally), a jailbroken user can swap in a forged receipt or "
        "hook the validation method to always return success. Server-side "
        "validation — or an SDK that performs it (RevenueCat, Adapty, "
        "Qonversion, Superwall) — and StoreKit 2's signed transactions are far "
        "harder to fake."
    )
    remediation = (
        "Validate receipts / StoreKit 2 transactions on your own backend (or via "
        "a server-validating SDK), gate entitlements on that server response, and "
        "never trust a boolean computed purely on the device."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        sdk_hits: dict[str, str] = {}
        for token, label in sig.IAP_SDKS.items():
            if ctx.contains(token):
                sdk_hits[label] = token
        local = ctx.find_any(sig.RECEIPT_LOCAL, per=1, total=12)
        sk1 = ctx.contains_any(sig.STOREKIT1)
        sk2 = ctx.contains_any(sig.STOREKIT2)
        apple_hosts = ctx.find_any(sig.APPLE_VERIFY_HOSTS, per=1, total=6)

        has_iap = bool(sdk_hits or local or sk1 or sk2 or apple_hosts)
        if not has_iap:
            return self.result(
                Status.INFO,
                "No in-app purchase or subscription code detected — nothing to "
                "validate (the app may be free or ad-supported).",
                0.0, weight=0.0,
            )

        findings: list[Finding] = []
        for label, token in sdk_hits.items():
            findings.append(Finding(label, "server-validating purchase SDK", token))
        if sk2:
            findings.append(Finding("StoreKit 2", "signed, server-verifiable transactions"))
        if sk1:
            findings.append(Finding("StoreKit 1", "classic SKPaymentQueue API"))
        for needle, sample in local:
            findings.append(Finding(needle, "on-device receipt handling", _trim(sample)))
        for needle, sample in apple_hosts:
            findings.append(Finding(needle, "Apple verifyReceipt endpoint", _trim(sample)))

        # A server-validating SDK is the strongest signal.
        if sdk_hits:
            return self.result(
                Status.PASS,
                f"Server-validating subscription SDK in use ({', '.join(sdk_hits)}) "
                "— purchases are checked off-device.",
                0.2, findings=findings,
            )
        # StoreKit 2 signed transactions, no obvious local-only parsing.
        if sk2 and not local:
            return self.result(
                Status.PASS,
                "Uses StoreKit 2 signed transactions — verifiable server-side.",
                0.35, severity=Severity.LOW, findings=findings,
            )
        # Local receipt parsing with no server SDK == classic crackable setup.
        if local:
            return self.result(
                Status.FAIL,
                "On-device receipt validation detected with no server-validating "
                "SDK — a forged receipt or a hooked validation method can unlock "
                "paid features.",
                0.9, severity=Severity.HIGH, findings=findings,
            )
        return self.result(
            Status.WARN,
            "In-app purchases present but the validation path is unclear — "
            "confirm entitlements are gated on a server response.",
            0.6, severity=Severity.MEDIUM, findings=findings,
        )


def _trim(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
