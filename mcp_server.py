"""Read-only MCP server for the iOS Crackability Analyzer.

Exposes the *static assessment* over the Model Context Protocol so other tools /
agents can request an analysis and receive structured findings + a crackability
score. This is an ASSESSOR, not an exploit driver: it only reads and reports.
There are deliberately no tools here that unlock, flip flags, forge receipts, or
otherwise modify an app. Those are out of scope for this server.

Run:  python mcp_server.py        (stdio transport)
Deps: pip install mcp
"""
from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from app.analyzer.checks import all_checks
from app.analyzer.correlate import correlate
from app.analyzer.engine import analyze
from app.report import exporter

mcp = FastMCP("ios-crackability-analyzer")


@mcp.tool()
def analyze_ipa(ipa_path: str) -> dict:
    """Statically analyze a decrypted .ipa and return crackability findings + score.

    Read-only: extracts the bundle, parses the Mach-O, runs every static check
    (encryption, hardening, jailbreak/anti-debug/anti-tamper detection, receipt
    validation, patchable premium-flag *detection*, hardcoded secrets, weak
    crypto, ATS, entitlements) and returns the full report as JSON.

    Args:
        ipa_path: absolute path to a decrypted .ipa on this machine.
    """
    if not ipa_path or not os.path.isfile(ipa_path):
        return {"ok": False, "error": f"file not found: {ipa_path}"}
    try:
        report = analyze(ipa_path)
        return {"ok": True, "report": report.to_dict()}
    except Exception as exc:  # noqa: BLE001 - report failures as data
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
def analyze_ipa_sarif(ipa_path: str) -> dict:
    """Analyze a decrypted .ipa and return the findings as SARIF 2.1.0 (for code
    scanning / CI ingestion). Read-only."""
    if not ipa_path or not os.path.isfile(ipa_path):
        return {"ok": False, "error": f"file not found: {ipa_path}"}
    try:
        return {"ok": True, "sarif": exporter.build_sarif(analyze(ipa_path))}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
def correlate_reports(static_report_path: str, dynamic_report_path: str) -> dict:
    """Fuse a static report JSON with an on-device dynamic result JSON, marking
    each shared weakness as suspected / confirmed / refuted. Read-only."""
    try:
        with open(static_report_path, encoding="utf-8") as f:
            static = json.load(f)
        with open(dynamic_report_path, encoding="utf-8") as f:
            dynamic = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "correlation": correlate(static, dynamic)}


@mcp.tool()
def list_checks() -> list[dict]:
    """List the static checks the analyzer runs, with id, title and category."""
    out: list[dict] = []
    for c in all_checks():
        cat = getattr(c, "category", "")
        out.append({
            "id": getattr(c, "id", ""),
            "title": getattr(c, "title", ""),
            "category": getattr(cat, "value", str(cat)),
        })
    return out


@mcp.tool()
def scoring_guide() -> dict:
    """Explain how the 0-100 crackability score maps to a verdict band."""
    return {
        "scale": "0 (well-protected) … 100 (trivially crackable)",
        "bands": {
            "low": "0-39: strong protections; hard to crack",
            "moderate": "40-59: some gaps worth hardening",
            "high": "60-84: few effective protections; likely crackable",
            "critical": "85-100: wide open / already crack-ready",
        },
        "note": "cryptid==0 (FairPlay-decrypted) dominates, since a decrypted "
                "binary is open to static analysis and patching.",
    }


if __name__ == "__main__":
    mcp.run()
