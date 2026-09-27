from __future__ import annotations

import html
from pathlib import Path
from typing import Any

def render_html(case: dict[str, Any]) -> str:
    def esc(v: Any) -> str: return html.escape(str(v))
    primary = case["primary_match"]
    bullets = "".join(f"<li>{esc(x)}</li>" for x in case.get("explanation", []))
    evidence = "".join(f"<li>{esc(x['text'])} — {esc(x['source'])}</li>" for x in case.get("evidence", []))
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>RA-XSOC-X Investigation Report</title>
<style>body{{font-family:system-ui;max-width:900px;margin:40px auto;line-height:1.5}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;text-align:left}}h1,h2{{margin-top:28px}}</style>
</head><body>
<h1>RA-XSOC-X Investigation Report</h1>
<table>
<tr><th>Analysis</th><td>{esc(case["analysis_id"])}</td></tr>
<tr><th>Incident</th><td>{esc(case["incident_id"])}</td></tr>
<tr><th>Primary classification</th><td>{esc(primary["name"])}</td></tr>
<tr><th>Confidence</th><td>{esc(case["confidence"])}</td></tr>
<tr><th>Review status</th><td>{esc(case["review_status"])}</td></tr>
</table>
<h2>Explanation</h2><ul>{bullets}</ul>
<h2>Evidence</h2><ul>{evidence}</ul>
<h2>Response guidance</h2><ul>{"".join(f"<li>{esc(x)}</li>" for x in case["playbook"]["investigation"])}</ul>
<p><strong>Human review:</strong> AI output is decision support, not autonomous containment.</p>
</body></html>"""

def save_html(case: dict[str, Any], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(case), encoding="utf-8")
    return output


def render_pdf(case: dict[str, Any], output: Path) -> Path:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    output.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output), pagesize=A4)
    primary = case["primary_match"]
    story = [
        Paragraph("RA-XSOC-X Investigation Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Analysis: {html.escape(str(case['analysis_id']))}", styles["BodyText"]),
        Paragraph(f"Incident: {html.escape(str(case['incident_id']))}", styles["BodyText"]),
        Paragraph(f"Primary classification: {html.escape(str(primary['name']))}", styles["BodyText"]),
        Paragraph(f"Confidence: {html.escape(str(case['confidence']))}", styles["BodyText"]),
        Paragraph(f"Review status: {html.escape(str(case['review_status']))}", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Explanation", styles["Heading2"]),
    ]
    for item in case.get("explanation", []):
        story.append(Paragraph("• " + html.escape(str(item)), styles["BodyText"]))
    story.extend([Spacer(1, 12), Paragraph("Evidence", styles["Heading2"])])
    for item in case.get("evidence", []):
        story.append(Paragraph("• " + html.escape(str(item["text"])), styles["BodyText"]))
    story.extend([
        Spacer(1, 12),
        Paragraph("Human review is required before operational response.", styles["BodyText"]),
    ])
    doc.build(story)
    return output
