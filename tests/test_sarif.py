"""SARIF export shape, so findings can flow into code scanning / CI."""
from __future__ import annotations

from app.report import exporter


def test_sarif_shape(report):
    s = exporter.build_sarif(report)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "encryption" in rule_ids
    # one result per check
    assert len(run["results"]) == len(report.results)
    # a decrypted binary fails the encryption check -> SARIF error level
    enc = next(r for r in run["results"] if r["ruleId"] == "encryption")
    assert enc["level"] == "error"
    assert run["properties"]["crackabilityScore"] == report.score
