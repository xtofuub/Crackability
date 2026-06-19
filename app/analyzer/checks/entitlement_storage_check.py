"""On-device entitlement storage: a flag a cracker can edit without hooking.

Even apps that validate purchases server-side often cache the result on the
device so the UI unlocks instantly. If that cache is a plain NSUserDefaults
value, a Preferences plist, or a Keychain item with a weak accessibility class,
a jailbroken user can edit it directly (no Frida, no binary patch) to flip
themselves to premium. This check looks for those persistence indicators next to
premium / license naming.
"""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_MONEY, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class EntitlementStorageCheck(Check):
    id = "entitlement_storage"
    title = "On-Device Entitlement Storage"
    category = CATEGORY_MONEY
    weight = 1.1
    explanation = (
        "Even with server validation, apps often cache the entitlement result "
        "on-device so paid UI unlocks instantly. If that cache is a plain "
        "NSUserDefaults value, a Preferences plist, or a Keychain item with a "
        "weak accessibility class, a jailbroken user can edit it directly, with "
        "no hooking, to flip themselves to premium."
    )
    remediation = (
        "Treat any on-device entitlement cache as untrusted. Re-verify against "
        "the server on launch and when entering paid flows, store sensitive "
        "items with kSecAttrAccessibleWhenUnlockedThisDeviceOnly plus an access "
        "control flag, and never let a persisted boolean alone unlock content."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        weak_kc = [t for t in sig.WEAK_KEYCHAIN_ACCESS if ctx.contains(t)]
        caches = [t for t in sig.ENTITLEMENT_CACHE_KEYS if ctx.contains(t)]
        uses_defaults = ctx.contains_any(sig.USERDEFAULTS_TOKENS)
        has_premium_naming = ctx.contains_any(sig.PREMIUM_FLAGS)
        defaults_premium = uses_defaults and has_premium_naming

        if not (weak_kc or caches or defaults_premium):
            return self.result(
                Status.PASS,
                "No obvious on-device entitlement persistence (NSUserDefaults, "
                "Keychain or plist) tied to premium state.",
                0.2,
            )

        findings: list[Finding] = []
        for t in weak_kc:
            findings.append(Finding(t, "weak Keychain accessibility (readable while unlocked)"))
        for t in caches:
            findings.append(Finding(t, "on-device entitlement / purchase cache"))
        if defaults_premium:
            findings.append(
                Finding("NSUserDefaults + premium naming",
                        "premium state likely cached in an editable plist"))

        surfaces = []
        if weak_kc:
            surfaces.append("weak Keychain item")
        if caches:
            surfaces.append("local entitlement cache")
        if defaults_premium:
            surfaces.append("NSUserDefaults flag")

        risk = min(0.75, 0.4 + 0.12 * len(weak_kc) + 0.1 * len(caches) + (0.15 if defaults_premium else 0.0))
        severity = Severity.HIGH if weak_kc else Severity.MEDIUM
        return self.result(
            Status.WARN,
            f"On-device entitlement storage indicators found ({', '.join(surfaces)}). "
            "A jailbroken user can edit these directly to unlock paid features "
            "without hooking.",
            risk, severity=severity, findings=findings,
        )
