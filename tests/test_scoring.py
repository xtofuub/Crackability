"""Scoring aggregation and verdict bands."""
from __future__ import annotations

from app.analyzer.models import CheckResult, Status
from app.analyzer.scoring import compute_score, verdict_for


def _r(risk: float, weight: float, status: Status = Status.WARN) -> CheckResult:
    return CheckResult("id", "title", "cat", status, risk=risk, weight=weight)


def test_weighted_average():
    assert compute_score([_r(1.0, 1.0), _r(0.0, 1.0)]) == 50


def test_uneven_weights():
    # (0.9*2 + 0.1*1) / 3 = 0.6333 -> 63
    assert compute_score([_r(0.9, 2.0), _r(0.1, 1.0)]) == 63


def test_zero_weight_is_ignored():
    assert compute_score([_r(1.0, 0.0, Status.INFO), _r(0.2, 1.0)]) == 20


def test_error_results_ignored():
    assert compute_score([_r(1.0, 1.0, Status.ERROR), _r(0.4, 1.0)]) == 40


def test_no_weighted_checks_scores_zero():
    assert compute_score([_r(1.0, 0.0, Status.INFO)]) == 0


def test_verdict_bands():
    assert verdict_for(0)[0] == "Low"
    assert verdict_for(24)[0] == "Low"
    assert verdict_for(25)[0] == "Moderate"
    assert verdict_for(49)[0] == "Moderate"
    assert verdict_for(50)[0] == "High"
    assert verdict_for(74)[0] == "High"
    assert verdict_for(75)[0] == "Very High"
    assert verdict_for(100)[0] == "Very High"
