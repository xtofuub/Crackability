"""Weak cryptography and insecure C APIs."""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_SECRETS, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class WeakCryptoCheck(Check):
    id = "weak_crypto"
    title = "Weak Cryptography & Unsafe APIs"
    category = CATEGORY_SECRETS
    weight = 0.6
    explanation = (
        "Broken hashes (MD5/SHA-1), legacy ciphers (DES/RC4), ECB mode and "
        "unbounded C string functions weaken whatever protection they back. A "
        "licence check guarded by an MD5 of a device id, for example, is easy to "
        "forge."
    )
    remediation = (
        "Use SHA-256+ and AES-GCM via CryptoKit / CommonCrypto with random IVs, "
        "and replace strcpy/sprintf/system() with bounded, safe equivalents."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        findings: list[Finding] = []
        for token, desc in sig.WEAK_CRYPTO.items():
            if ctx.find_symbols(token) or ctx.contains(token):
                findings.append(Finding(token, desc))
        insecure: list[Finding] = []
        for token, desc in sig.INSECURE_FUNCS.items():
            sym = token.rstrip("(")
            if ctx.find_symbols(sym) or ctx.contains(token):
                insecure.append(Finding(sym, desc))

        all_findings = findings + insecure
        if not all_findings:
            return self.result(Status.PASS, "No weak crypto or unsafe APIs spotted.", 0.0)

        # Weight: weak crypto matters a bit more than a stray strcpy.
        risk = min(0.8, 0.18 * len(findings) + 0.07 * len(insecure))
        status = Status.WARN
        sev = Severity.MEDIUM if findings else Severity.LOW
        bits = []
        if findings:
            bits.append(f"{len(findings)} weak-crypto primitive(s)")
        if insecure:
            bits.append(f"{len(insecure)} unsafe API(s)")
        return self.result(status, "Found " + " and ".join(bits) + ".",
                           risk, severity=sev, findings=all_findings)
