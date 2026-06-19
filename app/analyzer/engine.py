"""Top-level orchestration: IPA -> AnalysisReport."""
from __future__ import annotations

import logging
import os
import plistlib
import shutil
import tempfile
from typing import Callable, Optional

from .. import __version__
from . import demangle, scoring

log = logging.getLogger(__name__)
from .checks import all_checks
from .ipa_loader import load_ipa
from .macho_binary import collect_symbols, parse_macho
from .models import AnalysisContext, AnalysisReport, MachOInfo
from .strings_extractor import extract_from_file

ProgressFn = Optional[Callable[[int, str], None]]

# Bounds so a huge app with many large frameworks can't blow up analysis.
_MAX_EMBEDDED = 60
_EMB_MAX_BYTES = 80 * 1024 * 1024
_EMB_STRING_BUDGET = 120_000


def _bundle_exe(bundle_dir: str, fallback_name: str) -> Optional[str]:
    """Resolve a sub-bundle's executable (Info.plist CFBundleExecutable, else the
    same-named file)."""
    try:
        with open(os.path.join(bundle_dir, "Info.plist"), "rb") as fh:
            exe = (plistlib.load(fh) or {}).get("CFBundleExecutable")
        if exe:
            p = os.path.join(bundle_dir, exe)
            if os.path.isfile(p):
                return p
    except Exception:
        pass
    p = os.path.join(bundle_dir, fallback_name)
    return p if os.path.isfile(p) else None


def _embedded_binaries(bundle) -> list[str]:
    """Main-binary-adjacent Mach-Os worth scanning: embedded frameworks, app
    extensions and their nested frameworks, and dylibs."""
    out: list[str] = []
    app = bundle.app_path
    for sub in ("Frameworks", "PlugIns"):
        d = os.path.join(app, sub)
        if not os.path.isdir(d):
            continue
        for entry in sorted(os.listdir(d)):
            p = os.path.join(d, entry)
            if entry.endswith(".framework") and os.path.isdir(p):
                exe = _bundle_exe(p, entry[: -len(".framework")])
                if exe:
                    out.append(exe)
            elif entry.endswith((".appex", ".app")) and os.path.isdir(p):
                exe = _bundle_exe(p, entry.split(".")[0])
                if exe:
                    out.append(exe)
                nested = os.path.join(p, "Frameworks")
                if os.path.isdir(nested):
                    for fw in sorted(os.listdir(nested)):
                        if fw.endswith(".framework"):
                            fp = _bundle_exe(os.path.join(nested, fw), fw[: -len(".framework")])
                            if fp:
                                out.append(fp)
            elif entry.endswith(".dylib") and os.path.isfile(p):
                out.append(p)
    return out[:_MAX_EMBEDDED]


def _is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
        return magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                         b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                         b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")
    except Exception:
        return False


def _scan_embedded(bundle) -> tuple[list[str], set[str], list[str]]:
    """Fold embedded frameworks / extensions into the analysis: their strings and
    symbols (where RevenueCat, protectors, pinning libraries actually live)."""
    extra_strings: list[str] = []
    extra_symbols: set[str] = set()
    scanned: list[str] = []
    for p in _embedded_binaries(bundle):
        if not _is_macho(p):
            continue
        try:
            extra_symbols |= collect_symbols(p)
            if len(extra_strings) < _EMB_STRING_BUDGET:
                extra_strings.extend(
                    extract_from_file(p, max_bytes=_EMB_MAX_BYTES, max_strings=80_000))
            scanned.append(os.path.basename(p))
        except Exception:
            log.debug("embedded scan failed: %s", p, exc_info=True)
    return extra_strings[:_EMB_STRING_BUDGET], extra_symbols, scanned


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

        _emit(progress, 40, "Extracting strings…")
        strings = extract_from_file(bundle.executable_path)
        symbols = set(macho.imported_symbols) | set(macho.exported_symbols)

        _emit(progress, 50, "Scanning embedded frameworks & extensions…")
        emb_strings, emb_symbols, scanned = _scan_embedded(bundle)
        if scanned:
            log.info("scanned %d embedded binaries: %s", len(scanned), ", ".join(scanned[:12]))
        strings = strings + emb_strings
        symbols |= emb_symbols

        _emit(progress, 56, "De-mangling Swift symbols…")
        symbols |= demangle.enrich(symbols)

        _emit(progress, 58, "Building analysis context…")
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
