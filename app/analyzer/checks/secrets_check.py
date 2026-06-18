"""Hardcoded credentials / API keys embedded in the binary."""
from __future__ import annotations

import re

from .. import signatures as sig
from ..models import CATEGORY_SECRETS, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_ENUM = {
    "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


class SecretsCheck(Check):
    id = "hardcoded_secrets"
    title = "Hardcoded Secrets & API Keys"
    category = CATEGORY_SECRETS
    weight = 1.0
    explanation = (
        "Because a decrypted binary is fully readable, any credential compiled "
        "into it is effectively public. Hardcoded cloud keys, payment-provider "
        "secrets, tokens or private keys can be lifted directly from the app and "
        "abused — and they make a cracker's job trivial."
    )
    remediation = (
        "Never ship long-lived secrets in the client. Move privileged calls "
        "behind your backend, use short-lived tokens minted server-side, and "
        "rotate anything that has already shipped."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        findings: list[Finding] = []
        worst = "low"
        seen: set[str] = set()

        for name, pattern, severity in sig.SECRET_PATTERNS:
            rx = re.compile(pattern)
            count = 0
            for s in ctx.strings:
                m = rx.search(s)
                if not m:
                    continue
                token = m.group(0)
                key = f"{name}:{token}"
                if key in seen:
                    continue
                seen.add(key)
                # Show the actual matched secret — the point of the report is to
                # surface it so it can be verified and rotated. Value is the
                # mono evidence; the key type and severity sit beside it.
                findings.append(Finding(token.strip(), name, severity))
                if _SEV_ORDER[severity] > _SEV_ORDER[worst]:
                    worst = severity
                count += 1
                if count >= 5:
                    break

        if not findings:
            return self.result(
                Status.PASS,
                "No high-confidence hardcoded secrets detected.",
                0.0,
            )

        risk = {"low": 0.4, "medium": 0.6, "high": 0.8, "critical": 0.95}[worst]
        status = Status.FAIL if _SEV_ORDER[worst] >= 3 else Status.WARN
        plural = "secret" if len(findings) == 1 else "secrets"
        return self.result(
            status,
            f"{len(findings)} potential hardcoded {plural} found (worst: {worst}).",
            risk, severity=_SEV_ENUM[worst], findings=findings,
        )
