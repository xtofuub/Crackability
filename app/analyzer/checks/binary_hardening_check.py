"""Compiler / linker hardening: PIE, stack canary, ARC, arm64e PAC."""
from __future__ import annotations

from ..models import CATEGORY_BINARY, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class BinaryHardeningCheck(Check):
    id = "binary_hardening"
    title = "Binary Hardening (PIE · Canary · ARC · PAC)"
    category = CATEGORY_BINARY
    weight = 0.7
    explanation = (
        "Compiler and linker hardening raises the cost of reverse engineering "
        "and memory-corruption exploitation: PIE enables ASLR, a stack canary "
        "detects stack smashing, ARC removes whole classes of use-after-free "
        "bugs, and an arm64e slice adds pointer authentication (PAC)."
    )
    remediation = (
        "Build with PIE (the default), -fstack-protector-strong, ARC, and ship "
        "an arm64e slice where the deployment target allows it."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        m = ctx.macho
        if not m.parsed:
            return self.result(Status.ERROR, "Mach-O could not be parsed.", 0.4,
                               weight=0.3, error=m.error)

        findings: list[Finding] = []
        missing = 0.0
        total = 0.0

        def axis(name: str, ok: bool, w: float, good: str, bad: str) -> None:
            nonlocal missing, total
            total += w
            findings.append(Finding(f"{name}: {'yes' if ok else 'no'}", good if ok else bad))
            if not ok:
                missing += w

        axis("PIE / ASLR", m.is_pie, 0.40,
             "Position-independent — ASLR is active.",
             "No PIE — fixed load address makes static patching easy.")
        axis("Stack canary", m.has_stack_canary, 0.30,
             "__stack_chk_* present.",
             "No stack-protector symbols found.")
        axis("ARC", m.uses_arc, 0.15,
             "Automatic Reference Counting in use.",
             "No ARC symbols — manual memory management.")
        axis("arm64e (PAC)", m.is_arm64e, 0.15,
             "arm64e slice present — pointer authentication available.",
             "No arm64e slice — no PAC hardening.")

        risk = (missing / total) if total else 0.0
        if risk < 0.2:
            status, sev, summary = Status.PASS, Severity.NONE, "Binary is well hardened."
        elif risk < 0.55:
            status, sev, summary = Status.WARN, Severity.LOW, "Some hardening features are missing."
        else:
            status, sev, summary = Status.FAIL, Severity.MEDIUM, "Key hardening features are absent."

        return self.result(status, summary, risk, severity=sev, findings=findings)
