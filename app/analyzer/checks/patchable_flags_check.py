"""Patchable premium / license flags — the simplest and most common crack.

A boolean gate like ``-isPremium`` / ``hasValidLicense`` / ``unlockAll`` is
trivially patched to always-true (or hooked at runtime) on a jailbroken device,
unless the entitlement is verified off-device. These method/property names are
visible in a decrypted binary's selectors and symbols.
"""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_MONEY, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class PatchableFlagsCheck(Check):
    id = "patchable_flags"
    title = "Patchable Premium / License Flags"
    category = CATEGORY_MONEY
    weight = 1.2
    explanation = (
        "The most common crack is the simplest: find a boolean gate — isPremium, "
        "hasValidLicense, unlockAll, removeAds — and patch it to always return "
        "true, or hook it at runtime. Any entitlement decided by an on-device "
        "boolean can be flipped on a jailbroken device. These names are readable "
        "in the decrypted binary's Objective-C selectors and Swift symbols."
    )
    remediation = (
        "Don't gate paid features on a local boolean. Derive entitlements from a "
        "server response (or a server-validating SDK / StoreKit 2 verification), "
        "and fetch the actual premium content from the backend so a flipped flag "
        "yields nothing usable. Avoid a single chokepoint method that returns the "
        "BOOL — that's the one line a cracker patches."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        hits = ctx.find_any(sig.PREMIUM_FLAGS, per=1, total=40)
        if not hits:
            return self.result(
                Status.PASS,
                "No obvious on-device premium / license boolean gates found in the "
                "binary's symbols.",
                0.15,
            )

        findings: list[Finding] = []
        seen: set[str] = set()
        for needle, matched in hits:
            key = needle.lower()
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(needle, "boolean gate — patchable to always-unlocked", _trim(matched)))

        n = len(findings)
        # Presence is a real patch surface; more distinct gates == more places to
        # flip one. Bounded so this never alone dominates the score.
        risk = min(0.72, 0.45 + 0.045 * n)
        summary = (
            f"{n} on-device premium / license flag{'s' if n != 1 else ''} found — "
            "each is a boolean a jailbroken user can patch or hook to unlock paid "
            "features unless the entitlement is verified server-side."
        )
        return self.result(Status.WARN, summary, risk,
                           severity=Severity.MEDIUM, findings=findings)


def _trim(s: str, n: int = 90) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 1] + "…"
