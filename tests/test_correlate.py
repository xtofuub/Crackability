"""Static-to-dynamic correlation: suspected vs confirmed."""
from __future__ import annotations

from app.analyzer.correlate import correlate


def test_confirmed_premium_and_receipt():
    static = {
        "score": 70, "verdict": "High",
        "bundle": {"bundle_id": "com.x.y"},
        "results": [
            {"check_id": "patchable_flags", "status": "WARN"},
            {"check_id": "receipt_validation", "status": "FAIL"},
            {"check_id": "entitlement_storage", "status": "WARN"},
        ],
    }
    dynamic = {
        "identifier": "com.x.y",
        "hooked": [{"cls": "App.Sub", "sel": "- isInSubscription"}],
        "verdict": {"label": "BYPASSABLE"},
        "probes": {"receipt": {"status": "fail"}},
    }
    out = correlate(static, dynamic)
    axes = {c["axis"]: c["status"] for c in out["correlations"]}
    assert axes["Premium / license gates"] == "confirmed"
    assert axes["Receipt validation"] == "confirmed"
    assert out["confirmed_count"] >= 2


def test_refuted_receipt_when_server_observed():
    static = {"results": [{"check_id": "receipt_validation", "status": "FAIL"}]}
    dynamic = {"probes": {"receipt": {"status": "pass"}}}
    out = correlate(static, dynamic)
    axes = {c["axis"]: c["status"] for c in out["correlations"]}
    assert axes["Receipt validation"] == "refuted"


def test_empty_inputs_are_safe():
    out = correlate({}, {})
    assert out["correlations"] == []
    assert out["confirmed_count"] == 0
