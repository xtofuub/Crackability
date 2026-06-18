"""Leftover debug / non-production artefacts."""
from __future__ import annotations

from .. import signatures as sig
from ..models import CATEGORY_CONFIG, AnalysisContext, CheckResult, Finding, Severity, Status
from .base import Check


class DebugArtifactsCheck(Check):
    id = "debug_artifacts"
    title = "Debug & Non-Production Artefacts"
    category = CATEGORY_CONFIG
    weight = 0.4
    explanation = (
        "Strings pointing at localhost, staging/dev endpoints, verbose logging "
        "or TODO/FIXME markers suggest debug code shipped to production. These "
        "often expose internal endpoints or feature flags that simplify "
        "tampering."
    )
    remediation = (
        "Strip debug endpoints and verbose logging from release builds with "
        "compile-time flags, and keep staging configuration out of the bundle."
    )

    def run(self, ctx: AnalysisContext) -> CheckResult:
        hits = ctx.find_any(sig.DEBUG_ARTIFACTS, per=1, total=20)
        if not hits:
            return self.result(Status.PASS, "No obvious debug artefacts found.", 0.0)

        findings = [Finding(needle, "debug / non-prod indicator", _trim(sample))
                    for needle, sample in hits]
        # localhost / staging endpoints are the meaningful ones.
        notable = any(n in {"http://localhost", "https://localhost", "127.0.0.1",
                            "10.0.2.2", "staging.", "-staging", "dev-api.",
                            ".ngrok.io"} for n, _ in hits)
        risk = 0.45 if notable else 0.2
        sev = Severity.LOW
        return self.result(
            Status.WARN,
            f"{len(findings)} debug / non-production artefact(s) present.",
            risk, severity=sev, findings=findings,
        )


def _trim(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
