"""Anti-debugging / anti-tracing techniques."""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_TAMPER, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class AntiDebugCheck(Check):
    id = "anti_debug"
    title = "Anti-Debugging"
    category = CATEGORY_TAMPER
    weight = 1.0
    explanation = (
        "Crackers attach a debugger (lldb) or a dynamic-instrumentation tool "
        "(Frida) to trace logic and flip license checks at runtime. ptrace("
        "PT_DENY_ATTACH), sysctl P_TRACED probes and csops checks make live "
        "debugging noticeably harder."
    )
    remediation = (
        "Combine ptrace(PT_DENY_ATTACH), a sysctl KERN_PROC P_TRACED check and "
        "syscall-level variants, and re-check periodically rather than once at "
        "launch. Anti-debug alone is weak — pair it with integrity checks."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        sym_hits = [s for s in sig.ANTIDEBUG_SYMBOLS if ctx.find_symbols(s) or ctx.contains(s)]
        kw_hits = ctx.find_any(sig.ANTIDEBUG_KEYWORDS, per=1, total=12)

        findings: list[Finding] = []
        for s in sym_hits:
            findings.append(Finding(s, "anti-debug syscall / symbol"))
        for needle, sample in kw_hits:
            findings.append(Finding(needle, "anti-debug indicator", _trim(sample)))

        # PT_DENY_ATTACH or an explicit P_TRACED check is the strong signal.
        strong = ctx.contains("PT_DENY_ATTACH") or ctx.contains("P_TRACED") or (
            "ptrace" in sym_hits and "sysctl" in sym_hits
        )

        if strong:
            return self.result(
                Status.PASS,
                "Anti-debugging present (ptrace / sysctl based).",
                0.15, findings=findings,
            )
        if findings:
            return self.result(
                Status.WARN,
                "Partial anti-debug signals — may be incidental rather than a "
                "deliberate control.",
                0.55, severity=Severity.LOW, findings=findings,
            )
        return self.result(
            Status.WARN,
            "No anti-debugging found — a debugger or Frida can attach freely to "
            "trace and patch licence logic.",
            0.9, severity=Severity.MEDIUM,
        )


def _trim(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
