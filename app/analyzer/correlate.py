"""Correlate a static report with an on-device dynamic result.

Static analysis says what looks weak; the dynamic run says what was actually
exploitable. Fusing them turns "suspected" findings into "confirmed" (or
"refuted") ones, which is the signal a real assessment wants.

Inputs are plain dicts:
  - static_report:  the output of AnalysisReport.to_dict()
  - dynamic_report: a hook-test result (hooked / verdict / sdks) and/or a
                    dynamic-analysis result (probes: jailbreak/antidebug/receipt)
"""
from __future__ import annotations

from typing import Optional


def _check(static: dict, cid: str) -> Optional[dict]:
    for r in static.get("results", []):
        if r.get("check_id") == cid:
            return r
    return None


def _c(axis: str, static: str, dynamic: str, status: str, note: str) -> dict:
    return {"axis": axis, "static": static, "dynamic": dynamic,
            "status": status, "note": note}


def correlate(static_report: dict, dynamic_report: dict) -> dict:
    static_report = static_report or {}
    dynamic_report = dynamic_report or {}
    probes = dynamic_report.get("probes") or {}
    verdict = dynamic_report.get("verdict") or {}
    hooked = dynamic_report.get("hooked") or []
    cors: list[dict] = []

    # --- premium / license gates --------------------------------------- #
    pf = _check(static_report, "patchable_flags")
    if pf and pf.get("status") in ("WARN", "FAIL"):
        if hooked:
            cors.append(_c(
                "Premium / license gates",
                "boolean gate names found in the binary",
                f"{len(hooked)} gate(s) flipped to unlocked at runtime",
                "confirmed",
                "Client-side gating is bypassable; the named gates were forced true live.",
            ))
        elif dynamic_report.get("identifier"):
            cors.append(_c(
                "Premium / license gates",
                "boolean gate names found in the binary",
                "no ObjC gate flipped at runtime",
                "suspected",
                "The real gate may be Swift/JS, which the ObjC flip cannot reach.",
            ))

    # --- entitlement storage ------------------------------------------- #
    es = _check(static_report, "entitlement_storage")
    if es and es.get("status") == "WARN":
        cors.append(_c(
            "On-device entitlement storage",
            "editable Keychain / NSUserDefaults / plist indicators",
            verdict.get("label", "not exercised") if verdict else "not exercised",
            "confirmed" if hooked else "suspected",
            "Persisted entitlement state is editable without hooking.",
        ))

    # --- receipt / subscription validation ----------------------------- #
    rc = _check(static_report, "receipt_validation")
    rprobe = probes.get("receipt") or {}
    if rc and rprobe:
        if rc.get("status") == "FAIL" and rprobe.get("status") == "fail":
            cors.append(_c(
                "Receipt validation",
                "on-device validation, no server SDK",
                "receipt read with no validation round-trip",
                "confirmed",
                "Local-only validation is forgeable; confirmed at runtime.",
            ))
        elif rc.get("status") == "FAIL" and rprobe.get("status") == "pass":
            cors.append(_c(
                "Receipt validation",
                "looked local in the binary",
                "server round-trip observed at runtime",
                "refuted",
                "Runtime hit a validation server, so it is sturdier than it looked.",
            ))

    # --- jailbreak / anti-debug ---------------------------------------- #
    jb = _check(static_report, "jailbreak_detection")
    jprobe = probes.get("jailbreak") or {}
    if jb and jprobe:
        fired = bool(jprobe.get("detections") or jprobe.get("apis"))
        cors.append(_c(
            "Jailbreak detection",
            "detection strings present" if jb.get("status") == "PASS" else "no detection strings",
            "checks fired at launch but were interceptable" if fired else "no checks observed",
            "confirmed" if fired else "suspected",
            "Detection exists but is bypassable with a runtime hook." if fired
            else "No runtime jailbreak checks seen in the window.",
        ))

    confirmed = sum(1 for c in cors if c["status"] == "confirmed")
    summary = (
        f"{confirmed} of {len(cors)} cross-checked weakness(es) confirmed at runtime."
        if cors else "No overlapping axes to correlate."
    )

    return {
        "identifier": dynamic_report.get("identifier")
        or static_report.get("bundle", {}).get("bundle_id", ""),
        "static_score": static_report.get("score"),
        "static_verdict": static_report.get("verdict"),
        "dynamic_verdict": verdict.get("label"),
        "confirmed_count": confirmed,
        "correlations": cors,
        "summary": summary,
    }
