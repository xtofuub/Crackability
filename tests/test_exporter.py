"""JSON / HTML report exporters."""
from __future__ import annotations

import json

from app.report import exporter


def test_json_roundtrip(report, tmp_path):
    p = tmp_path / "r.json"
    exporter.export_json(report, str(p))
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["score"] == report.score
    assert data["verdict"] == report.verdict
    assert len(data["results"]) == len(report.results)
    assert data["bundle"]["bundle_id"] == report.bundle.bundle_id


def test_html_is_self_contained(report, tmp_path):
    p = tmp_path / "r.html"
    exporter.export_html(report, str(p))
    html = p.read_text(encoding="utf-8")
    assert html.strip().startswith("<!doctype html>")
    assert "</html>" in html
    assert report.bundle.display_name in html
    # score gauge is inlined as SVG, no external assets
    assert "<svg" in html
    assert "http-equiv" not in html.lower() or "external" not in html.lower()
