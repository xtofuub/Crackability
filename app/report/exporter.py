"""Serialise an AnalysisReport to JSON or a standalone, styled HTML document."""
from __future__ import annotations

import base64
import html
import json
import math
from datetime import datetime

from ..analyzer.models import AnalysisReport, Status

# Shared palette (kept in sync with the GUI theme).
_VERDICT_COLORS = {
    "low": "#4cc38a",
    "moderate": "#e3b341",
    "high": "#df8b59",
    "critical": "#e5675f",
}
_STATUS_COLORS = {
    "PASS": "#4cc38a",
    "WARN": "#e3b341",
    "FAIL": "#e5675f",
    "INFO": "#5b8cff",
    "ERROR": "#8a97a6",
}
_SEV_COLORS = {
    "critical": "#e5675f",
    "high": "#df8b59",
    "medium": "#e3b341",
    "low": "#7d8896",
    "none": "#4cc38a",
}


def export_json(report: AnalysisReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)


def _gauge_svg(score: int, color: str, size: int = 160) -> str:
    r = size / 2 - 14
    cx = cy = size / 2
    circ = 2 * math.pi * r
    frac = max(0.0, min(1.0, score / 100.0))
    dash = circ * frac
    start = -90
    return f"""
<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#212a37" stroke-width="12"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="12"
          stroke-linecap="round" stroke-dasharray="{dash:.2f} {circ:.2f}"
          transform="rotate({start} {cx} {cy})"/>
  <text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="40"
        fill="#e9eef5" font-family="Segoe UI, Arial" font-weight="700">{score}</text>
  <text x="{cx}" y="{cy + 20}" text-anchor="middle" font-size="13"
        fill="#97a3b4" font-family="Segoe UI, Arial">/ 100</text>
</svg>"""


def _esc(s) -> str:
    return html.escape(str(s))


def export_html(report: AnalysisReport, path: str) -> None:
    d = report.to_dict()
    b = report.bundle
    m = report.macho
    color = _VERDICT_COLORS.get(report.verdict_key, "#d6a531")

    icon_html = ""
    if b.icon_data:
        try:
            b64 = base64.b64encode(b.icon_data).decode("ascii")
            icon_html = f'<img class="appicon" src="data:image/png;base64,{b64}" alt="icon"/>'
        except Exception:
            icon_html = ""
    if not icon_html:
        letter = (b.display_name or "?")[:1].upper()
        icon_html = f'<div class="appicon placeholder">{_esc(letter)}</div>'

    counts = d["counts"]
    chips = "".join(
        f'<span class="chip" style="--c:{_STATUS_COLORS[k]}">{counts[k]} {k}</span>'
        for k in ("PASS", "WARN", "FAIL", "INFO") if counts.get(k)
    )

    # Group results by category, preserving the engine's order.
    cats: list[tuple[str, list[dict]]] = []
    for r in d["results"]:
        if not cats or cats[-1][0] != r["category"]:
            cats.append((r["category"], []))
        cats[-1][1].append(r)

    sections = []
    for category, items in cats:
        rows = []
        for r in items:
            sc = _STATUS_COLORS.get(r["status"], "#97a3b4")
            sev = r["severity"]
            sev_badge = (
                f'<span class="sev" style="--c:{_SEV_COLORS.get(sev, "#6e7d90")}">{_esc(sev)}</span>'
                if sev not in ("none",) else ""
            )
            findings = ""
            if r["findings"]:
                lis = "".join(
                    f'<li><code>{_esc(f["label"])}</code>'
                    + (f' — {_esc(f["detail"])}' if f["detail"] else "")
                    + (f' <span class="loc">{_esc(f["location"])}</span>' if f["location"] else "")
                    + "</li>"
                    for f in r["findings"]
                )
                findings = f'<ul class="findings">{lis}</ul>'
            remediation = (
                f'<div class="remediation"><b>Remediation.</b> {_esc(r["remediation"])}</div>'
                if r["remediation"] else ""
            )
            rows.append(f"""
    <div class="card" style="--c:{sc}">
      <div class="card-head">
        <span class="dot" style="background:{sc}"></span>
        <span class="ctitle">{_esc(r["title"])}</span>
        <span class="status" style="--c:{sc}">{_esc(r["status"])}</span>
        {sev_badge}
      </div>
      <div class="summary">{_esc(r["summary"])}</div>
      <div class="explain">{_esc(r["explanation"])}</div>
      {findings}
      {remediation}
    </div>""")
        sections.append(
            f'<h2 class="cat">{_esc(category)}</h2>' + "".join(rows)
        )

    meta_rows = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
        for k, v in [
            ("Bundle ID", b.bundle_id or "—"),
            ("Version", f"{b.version or '—'} ({b.build or '—'})"),
            ("Min iOS", b.min_os or "—"),
            ("Architectures", ", ".join(m.available_archs) or m.arch or "—"),
            ("Executable", b.executable_name or "—"),
            ("Encrypted (cryptid)", m.cryptid if m.cryptid is not None else "—"),
            ("PIE / Canary / ARC", f"{m.is_pie} / {m.has_stack_canary} / {m.uses_arc}"),
            ("Embedded frameworks", len(b.frameworks)),
            ("IPA size", f"{b.file_size / 1_048_576:.1f} MB"),
        ]
    )

    generated = datetime.fromisoformat(d["generated_at"]).strftime("%Y-%m-%d %H:%M")
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Crackability Report — {_esc(b.display_name)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0b0e13; color:#e9eef5;
         font-family:'Segoe UI',system-ui,Arial,sans-serif; line-height:1.5; }}
  .wrap {{ max-width:1000px; margin:0 auto; padding:32px 24px 64px; }}
  .top {{ display:flex; gap:24px; align-items:center; flex-wrap:wrap;
          border-bottom:1px solid #212a37; padding-bottom:24px; }}
  .appicon {{ width:84px; height:84px; border-radius:19px; object-fit:cover;
              border:1px solid #2a3441; }}
  .placeholder {{ display:flex; align-items:center; justify-content:center;
                  font-size:38px; font-weight:700; background:#1c2330; color:#7c93b5; }}
  .titleblock h1 {{ margin:0 0 4px; font-size:26px; }}
  .titleblock .sub {{ color:#97a3b4; font-size:14px; }}
  .gaugewrap {{ margin-left:auto; text-align:center; }}
  .verdict {{ font-size:17px; font-weight:700; margin-top:6px; }}
  .verdict small {{ display:block; font-weight:400; color:#97a3b4; font-size:12px; max-width:180px; }}
  .chips {{ margin:18px 0 0; display:flex; gap:8px; flex-wrap:wrap; }}
  .chip {{ font-size:12px; padding:4px 10px; border-radius:20px;
           border:1px solid var(--c); color:var(--c); }}
  table.meta {{ width:100%; border-collapse:collapse; margin:24px 0; font-size:14px; }}
  table.meta th {{ text-align:left; color:#97a3b4; font-weight:500; width:200px;
                   padding:7px 12px; border-bottom:1px solid #19202b; }}
  table.meta td {{ padding:7px 12px; border-bottom:1px solid #19202b; }}
  h2.cat {{ font-size:15px; text-transform:uppercase; letter-spacing:.08em;
            color:#7c93b5; margin:30px 0 12px; }}
  .card {{ background:#11161e; border:1px solid #212a37; border-left:3px solid var(--c);
           border-radius:10px; padding:16px 18px; margin:12px 0; }}
  .card-head {{ display:flex; align-items:center; gap:10px; }}
  .dot {{ width:9px; height:9px; border-radius:50%; }}
  .ctitle {{ font-weight:600; font-size:15px; }}
  .status {{ margin-left:auto; font-size:11px; font-weight:700; color:var(--c);
             border:1px solid var(--c); border-radius:6px; padding:2px 8px; }}
  .sev {{ font-size:10px; text-transform:uppercase; color:var(--c);
          border:1px solid var(--c); border-radius:6px; padding:2px 7px; }}
  .summary {{ margin:10px 0 6px; font-size:14px; }}
  .explain {{ color:#97a3b4; font-size:13px; }}
  ul.findings {{ margin:10px 0 0; padding-left:18px; font-size:13px; }}
  ul.findings code {{ background:#0b0e13; padding:1px 6px; border-radius:5px; color:#cfe0ff; }}
  .loc {{ color:#6e7d90; font-size:12px; }}
  .remediation {{ margin-top:10px; font-size:13px; color:#b9c6d6;
                  background:#0e1219; border-radius:8px; padding:8px 12px; }}
  footer {{ margin-top:40px; color:#5b6776; font-size:12px; text-align:center; }}
</style></head><body><div class="wrap">
  <div class="top">
    {icon_html}
    <div class="titleblock">
      <h1>{_esc(b.display_name or 'Unknown app')}</h1>
      <div class="sub">{_esc(b.bundle_id)} · v{_esc(b.version)} ({_esc(b.build)})</div>
    </div>
    <div class="gaugewrap">
      {_gauge_svg(report.score, color)}
      <div class="verdict" style="color:{color}">{_esc(report.verdict)} crackability
        <small>{_esc(report.verdict_subtitle)}</small>
      </div>
    </div>
  </div>
  <div class="chips">{chips}</div>
  <table class="meta">{meta_rows}</table>
  {''.join(sections)}
  <footer>Generated by iOS Crackability Analyzer v{_esc(d['tool_version'])} · {generated}
    · For authorised security assessment and developer hardening only.</footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
