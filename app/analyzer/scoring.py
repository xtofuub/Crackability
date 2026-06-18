"""Aggregate per-check risk into an overall crackability score and verdict."""
from __future__ import annotations

from .models import CheckResult, Status

# verdict thresholds on a 0..100 "crackability" scale (higher == easier to crack)
_BANDS = [
    (25, "Low", "Well protected against casual cracking", "low"),
    (50, "Moderate", "Some meaningful protections in place", "moderate"),
    (75, "High", "Few effective protections — likely crackable", "high"),
    (101, "Very High", "Minimal protection — trivially crackable", "critical"),
]


def compute_score(results: list[CheckResult]) -> int:
    """Weighted average of per-axis risk, 0..100. Higher == more crackable."""
    num = 0.0
    den = 0.0
    for r in results:
        if r.status is Status.ERROR:
            continue
        if r.weight <= 0:
            continue
        num += r.risk * r.weight
        den += r.weight
    if den == 0:
        return 0
    return int(round(num / den * 100))


def verdict_for(score: int) -> tuple[str, str, str]:
    """Return (label, subtitle, key) for a score."""
    for threshold, label, subtitle, key in _BANDS:
        if score < threshold:
            return label, subtitle, key
    return _BANDS[-1][1], _BANDS[-1][2], _BANDS[-1][3]
