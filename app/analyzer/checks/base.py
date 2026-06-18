"""Base class shared by every check."""
from __future__ import annotations

from ..models import AnalysisContext, CheckResult, Finding, Severity, Status


class Check:
    """A single static analysis check.

    Subclasses set the class attributes and implement ``run``. ``risk`` is the
    0..1 contribution to the overall crackability score (1 == no protection on
    this axis); ``weight`` is how much this axis matters relative to others.
    """

    id: str = ""
    title: str = ""
    category: str = ""
    weight: float = 1.0
    explanation: str = ""
    remediation: str = ""

    def run(self, ctx: AnalysisContext) -> CheckResult:  # pragma: no cover
        raise NotImplementedError

    # Convenience constructor so subclasses stay terse.
    def result(
        self,
        status: Status,
        summary: str,
        risk: float,
        *,
        weight: float | None = None,
        severity: Severity = Severity.NONE,
        findings: list[Finding] | None = None,
        error: str | None = None,
    ) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            title=self.title,
            category=self.category,
            status=status,
            summary=summary,
            risk=max(0.0, min(1.0, risk)),
            weight=self.weight if weight is None else weight,
            severity=severity,
            explanation=self.explanation,
            remediation=self.remediation,
            findings=findings or [],
            error=error,
        )
