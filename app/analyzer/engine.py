"""Top-level orchestration: IPA -> AnalysisReport."""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
from typing import Callable, Optional

from .. import __version__
from . import scoring

log = logging.getLogger(__name__)
from .checks import all_checks
from .ipa_loader import load_ipa
from .macho_binary import parse_macho
from .models import AnalysisContext, AnalysisReport, MachOInfo
from .strings_extractor import extract_from_file

ProgressFn = Optional[Callable[[int, str], None]]


def _emit(progress: ProgressFn, pct: int, msg: str) -> None:
    if progress:
        try:
            progress(pct, msg)
        except Exception:
            pass


def _framework_search_tokens(bundle) -> list[str]:
    """Names worth making searchable so SDK fingerprints match on bundle layout."""
    tokens: list[str] = []
    for fw in bundle.frameworks:
        tokens.append(fw)
        tokens.append(fw.replace(".framework", "").replace(".dylib", ""))
    for pg in bundle.plugins:
        tokens.append(pg)
        tokens.append(pg.replace(".appex", ""))
    return tokens


def analyze(ipa_path: str, progress: ProgressFn = None) -> AnalysisReport:
    """Run the full static analysis pipeline on *ipa_path*."""
    workdir = tempfile.mkdtemp(prefix="ios_crack_")
    log.info("analysis started: %s", ipa_path)
    try:
        _emit(progress, 5, "Extracting IPA…")
        bundle = load_ipa(ipa_path, workdir)

        _emit(progress, 22, "Parsing Mach-O executable…")
        macho: MachOInfo = parse_macho(bundle.executable_path)

        _emit(progress, 42, "Extracting strings…")
        strings = extract_from_file(bundle.executable_path)

        _emit(progress, 58, "Building analysis context…")
        symbols = set(macho.imported_symbols) | set(macho.exported_symbols)
        framework_tokens = _framework_search_tokens(bundle)
        ctx = AnalysisContext(
            bundle=bundle,
            macho=macho,
            strings=strings,
            symbols=symbols,
            libraries=macho.libraries,
            framework_names=macho.libraries + framework_tokens,
        )

        checks = all_checks()
        results = []
        span = 36
        for i, check in enumerate(checks):
            _emit(progress, 60 + int(span * i / len(checks)), f"Running: {check.title}")
            try:
                results.append(check.run(ctx))
            except Exception as exc:  # a single check must never sink the run
                log.exception("check %s failed", check.id)
                from .models import CheckResult, Status
                results.append(CheckResult(
                    check_id=check.id, title=check.title, category=check.category,
                    status=Status.ERROR, summary=f"Check failed: {exc}",
                    risk=0.0, weight=0.0, error=str(exc),
                ))

        _emit(progress, 97, "Scoring…")
        score = scoring.compute_score(results)
        label, subtitle, key = scoring.verdict_for(score)

        report = AnalysisReport(
            bundle=bundle,
            macho=macho,
            results=results,
            score=score,
            verdict=label,
            verdict_subtitle=subtitle,
            verdict_key=key,
            tool_version=__version__,
        )
        _emit(progress, 100, "Done.")
        log.info("analysis complete: %s score=%d verdict=%s",
                 bundle.bundle_id or bundle.display_name, score, label)
        return report
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
