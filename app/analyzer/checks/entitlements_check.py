"""Code-signing entitlements (debuggability, capabilities)."""
from __future__ import annotations

from ..models import CATEGORY_CONFIG, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check

_NOTABLE = {
    "application-identifier": "App ID",
    "com.apple.developer.team-identifier": "Team ID",
    "aps-environment": "Push environment",
    "com.apple.security.application-groups": "App groups",
    "keychain-access-groups": "Keychain groups",
    "com.apple.developer.associated-domains": "Associated domains",
    "com.apple.developer.in-app-payments": "Apple Pay merchants",
    "com.apple.developer.networking.networkextension": "Network extension",
}


class EntitlementsCheck(Check):
    id = "entitlements"
    title = "Code-Signing Entitlements"
    category = CATEGORY_CONFIG
    weight = 0.5
    explanation = (
        "Entitlements embedded in the code signature describe the app's "
        "capabilities. get-task-allow = true means the process is debuggable — "
        "appropriate for development builds, but on a shipped app it lets anyone "
        "attach a debugger and inspect/patch it at will."
    )
    remediation = (
        "Ship App Store / distribution builds (get-task-allow = false). Scope "
        "keychain and app-group entitlements as tightly as possible."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        ents = ctx.macho.entitlements or {}
        if not ents:
            return self.result(
                Status.INFO,
                "No entitlements recovered (typical for a re-signed / dumped IPA).",
                0.0, weight=0.0,
            )

        findings: list[Finding] = []
        debuggable = bool(ents.get("get-task-allow"))
        findings.append(Finding(
            "get-task-allow", "TRUE — process is debuggable" if debuggable else "false",
        ))
        for key, label in _NOTABLE.items():
            if key in ents:
                val = ents[key]
                if isinstance(val, (list, tuple)):
                    val = ", ".join(str(v) for v in val)
                findings.append(Finding(label, str(val)[:120]))

        if debuggable:
            return self.result(
                Status.WARN,
                "get-task-allow is TRUE — a debugger can attach to this build.",
                0.6, weight=0.5, severity=Severity.MEDIUM, findings=findings,
            )
        return self.result(
            Status.INFO,
            f"{len(findings)} entitlement(s) recovered; not debuggable.",
            0.0, weight=0.0, findings=findings,
        )
