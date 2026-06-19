"""A well-protected app should score far lower than the crackable sample. This
exercises the PASS branches that the crackable fixture never reaches."""
from __future__ import annotations

from app.analyzer.models import Status


def _by_id(report, cid):
    for r in report.results:
        if r.check_id == cid:
            return r
    raise AssertionError(f"no check with id {cid!r}")


def test_hardened_scores_lower(report, hardened_report):
    assert hardened_report.score < report.score
    assert hardened_report.score < 40
    assert hardened_report.verdict_key in {"low", "moderate"}


def test_hardened_pass_paths(hardened_report):
    expected_pass = [
        "encryption",
        "protector",
        "ssl_pinning",
        "receipt_validation",
        "patchable_flags",
        "entitlement_storage",
        "jailbreak_detection",
        "anti_debug",
        "anti_tamper",
    ]
    for cid in expected_pass:
        r = _by_id(hardened_report, cid)
        assert r.status is Status.PASS, f"{cid} expected PASS, got {r.status.value}"
