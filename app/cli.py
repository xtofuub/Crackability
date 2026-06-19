"""Headless command-line runner: analyse an IPA and print / export the report."""
from __future__ import annotations

import argparse
import os
import sys

from .analyzer.engine import analyze
from .analyzer.models import Status
from .report import exporter

_C = {
    "PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m",
    "INFO": "\033[94m", "ERROR": "\033[90m", "R": "\033[0m", "B": "\033[1m",
}


def _color(txt: str, key: str, enabled: bool) -> str:
    if not enabled:
        return txt
    return f"{_C.get(key, '')}{txt}{_C['R']}"


def _ensure_streams() -> None:
    """A windowed PyInstaller build has no console: sys.stdout/stderr are None.
    Point them at a sink so --cli still runs (and can write report files)."""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")


def run(argv: list[str] | None = None) -> int:
    _ensure_streams()
    p = argparse.ArgumentParser(
        prog="ios-crack-analyzer",
        description="Static crackability / anti-piracy posture analysis for a decrypted iOS .ipa",
    )
    p.add_argument("ipa", help="path to a decrypted .ipa file")
    p.add_argument("--json", metavar="PATH", help="write a JSON report to PATH")
    p.add_argument("--html", metavar="PATH", help="write an HTML report to PATH")
    p.add_argument("--sarif", metavar="PATH", help="write a SARIF 2.1.0 report to PATH")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    args = p.parse_args(argv)

    color = not args.no_color and bool(getattr(sys.stdout, "isatty", lambda: False)())

    if not os.path.isfile(args.ipa):
        print(f"error: file not found: {args.ipa}", file=sys.stderr)
        return 2

    try:
        report = analyze(args.ipa, progress=lambda pct, msg: print(
            f"\r[{pct:3d}%] {msg:<40}", end="", file=sys.stderr, flush=True))
    except Exception as exc:
        print(f"\nerror: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("", file=sys.stderr)

    b = report.bundle
    print(_color(f"\n{b.display_name}", "B", color)
          + f"  {b.bundle_id}  v{b.version} ({b.build})")
    print(f"Architectures: {', '.join(report.macho.available_archs) or '—'}"
          f"   PIE={report.macho.is_pie} Canary={report.macho.has_stack_canary}"
          f" ARC={report.macho.uses_arc} cryptid={report.macho.cryptid}")
    print("-" * 72)

    for r in report.results:
        tag = _color(f"{r.status.value:5}", r.status.value, color)
        print(f"{tag} {r.title}")
        print(f"      {r.summary}")
        for f in r.findings[:6]:
            extra = f" — {f.detail}" if f.detail else ""
            print(f"        • {f.label}{extra}")
        if len(r.findings) > 6:
            print(f"        … +{len(r.findings) - 6} more")

    print("-" * 72)
    verdict_key = report.verdict_key.upper()
    band = {"low": "PASS", "moderate": "WARN", "high": "FAIL", "critical": "FAIL"}.get(
        report.verdict_key, "INFO")
    print(_color(f"CRACKABILITY SCORE: {report.score}/100  —  {report.verdict} "
                 f"({report.verdict_subtitle})", band, color))

    if args.json:
        exporter.export_json(report, args.json)
        print(f"JSON report  -> {args.json}")
    if args.html:
        exporter.export_html(report, args.html)
        print(f"HTML report  -> {args.html}")
    if args.sarif:
        exporter.export_sarif(report, args.sarif)
        print(f"SARIF report -> {args.sarif}")

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
