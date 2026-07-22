"""Report rendering - JSON / CSV / HTML / DOCX, pure standard library.

Turns the exercise report dict (service.build_report) and the cohort gradebook
into downloadable deliverables. DOCX is generated as minimal, valid OOXML
(a zip of document.xml) with no third-party dependency.
"""

from __future__ import annotations

import csv
import html
import io
import json
import zipfile

# ------------------------------------------------------------------ JSON ----
def report_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, default=str).encode("utf-8")


# ------------------------------------------------------------------- CSV ----
def report_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    s = report.get("scenario", {})
    cov = report.get("coverage", {})
    score = report.get("score") or {}
    w.writerow(["CyberRange after-action report"])
    w.writerow(["exercise_id", report.get("exercise_id")])
    w.writerow(["scenario", s.get("name"), s.get("id")])
    w.writerow(["status", report.get("status")])
    w.writerow(["started_at", report.get("started_at")])
    w.writerow(["ended_at", report.get("ended_at")])
    w.writerow(["total_score", score.get("total")])
    w.writerow([])
    w.writerow(["coverage", "techniques"])
    w.writerow(["expected", " ".join(cov.get("expected", []))])
    w.writerow(["observed", " ".join(cov.get("observed", []))])
    w.writerow(["detected", " ".join(cov.get("detected", []))])
    w.writerow(["gaps", " ".join(cov.get("gaps", [])) or "none"])
    fw = report.get("framework_coverage", {})
    w.writerow([])
    w.writerow(["framework crosswalk (curated, indicative)"])
    w.writerow(["NIST CSF functions", " ".join(fw.get("nist_csf", [])) or "-"])
    w.writerow(["NICE work roles", " | ".join(fw.get("nice", [])) or "-"])
    w.writerow(["CIS Controls", " | ".join(fw.get("cis", [])) or "-"])
    w.writerow(["NSA CAE Knowledge Units", " | ".join(fw.get("cae", [])) or "-"])
    w.writerow([])
    w.writerow(["detections:", "technique", "rule", "verdict", "basis", "severity", "latency_s", "detail"])
    for d in report.get("detections", []):
        w.writerow(["", d.get("technique_id"), d.get("rule_id") or d.get("rule_version"),
                    d.get("verdict"), d.get("basis"), d.get("severity"),
                    d.get("latency_s"), (d.get("detail") or "")[:120]])
    w.writerow([])
    w.writerow(["evidence:", "ts_utc", "role", "by", "description"])
    for e in report.get("evidence", []):
        w.writerow(["", e.get("ts_utc"), e.get("role"), e.get("submitted_by"),
                    (e.get("description") or "")[:200]])
    return buf.getvalue()


def gradebook_csv(gb: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    assignments = gb.get("assignments", [])
    w.writerow(["Class", gb.get("cohort", {}).get("name")])
    w.writerow([])
    header = ["Student"] + [a.get("title", a.get("id")) for a in assignments] + ["Completed", "Avg %"]
    w.writerow(header)
    for row in gb.get("rows", []):
        cells = row.get("cells", {})
        out = [row.get("display_name") or row.get("username")]
        for a in assignments:
            c = cells.get(a["id"], {})
            out.append(c.get("score") if c.get("status") == "completed"
                       else (c.get("status") or "not_started"))
        out += [row.get("completed"), row.get("avg_score")]
        w.writerow(out)
    return buf.getvalue()


# ------------------------------------------------------------------ HTML ----
def report_html(report: dict) -> str:
    s = report.get("scenario", {})
    cov = report.get("coverage", {})
    fw = report.get("framework_coverage", {})
    score = report.get("score") or {}
    e = html.escape

    def chips(items, cls=""):
        return " ".join(f'<span class="tag {cls}">{e(str(t))}</span>' for t in items) or "-"

    dims = ""
    for d in (score.get("dimensions") or []):
        dims += (f'<tr><td>{e(d["dimension"])}</td><td>{d["raw"]}</td>'
                 f'<td>{d["weight"]}</td><td>{d["contribution"]}</td></tr>')
    dets = ""
    for d in report.get("detections", []):
        dets += (f'<tr><td>{e(str(d.get("technique_id")))}</td>'
                 f'<td>{e(str(d.get("rule_id") or d.get("rule_version")))}</td>'
                 f'<td>{e(str(d.get("verdict")))}</td><td>{e(str(d.get("basis")))}</td>'
                 f'<td>{e(str(d.get("severity")))}</td><td>{e(str(d.get("latency_s")))}</td></tr>')
    recs = "".join(f"<li>{e(r)}</li>" for r in report.get("recommendations", []))

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>CyberRange report {e(report.get('exercise_id',''))}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a2233;max-width:820px;margin:32px auto;padding:0 20px}}
 h1{{font-size:22px;margin:0}} h2{{font-size:14px;text-transform:uppercase;letter-spacing:.5px;color:#5a6a85;margin-top:28px}}
 .sub{{color:#5a6a85}} table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}}
 th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #e5e9f0}} th{{color:#5a6a85;font-size:11px;text-transform:uppercase}}
 .tag{{display:inline-block;font-family:monospace;font-size:11px;padding:2px 7px;border-radius:4px;background:#eef2f8;border:1px solid #d7deea;margin:1px}}
 .tag.gap{{background:#fdecec;border-color:#f5c2c2;color:#b23}} .total{{font-size:28px;font-weight:700}}
 @media print{{body{{margin:0}}}}
</style></head><body>
<h1>CyberRange - After-Action Report</h1>
<p class="sub">{e(s.get('name',''))} · {e(s.get('mode',''))} · {e(report.get('exercise_id',''))}</p>
<p class="sub">Status: {e(str(report.get('status')))} · {e(str(report.get('started_at')))} → {e(str(report.get('ended_at')))}</p>
<h2>Score</h2>
<p class="total">{e(str(score.get('total','-')))}</p>
<table><tr><th>Dimension</th><th>Raw</th><th>Weight</th><th>Contribution</th></tr>{dims}</table>
<h2>ATT&amp;CK coverage</h2>
<p>Expected: {chips(cov.get('expected',[]))}<br>Observed: {chips(cov.get('observed',[]))}<br>
Detected: {chips(cov.get('detected',[]))}<br>Gaps: {chips(cov.get('gaps',[]),'gap')}</p>
<h2>Framework crosswalk <span class="sub" style="text-transform:none;font-size:11px">(curated, indicative)</span></h2>
<p>NIST CSF: {chips(fw.get('nist_csf', []))}<br>
NICE roles: {chips(fw.get('nice', []))}<br>
CIS Controls: {chips(fw.get('cis', []))}<br>
NSA CAE KUs: {chips(fw.get('cae', []))}</p>
<h2>Detections</h2>
<table><tr><th>Technique</th><th>Rule</th><th>Verdict</th><th>Basis</th><th>Severity</th><th>MTTD (s)</th></tr>{dets or '<tr><td colspan=6>none</td></tr>'}</table>
<h2>Evidence &amp; recommendations</h2>
<p class="sub">{report.get('evidence_count',0)} evidence item(s), {report.get('timeline_events',0)} timeline events.</p>
<ul>{recs}</ul>
<p class="sub" style="margin-top:30px">Generated by CyberRange · print to PDF to save.</p>
</body></html>"""


# ------------------------------------------------------------------ DOCX ----
_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>')
_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '</Relationships>')


def _para(text: str, *, bold=False, size=22, color=None) -> str:
    rpr = ""
    if bold:
        rpr += "<w:b/>"
    rpr += f'<w:sz w:val="{size}"/>'
    if color:
        rpr += f'<w:color w:val="{color}"/>'
    return (f'<w:p><w:r><w:rPr>{rpr}</w:rPr>'
            f'<w:t xml:space="preserve">{html.escape(text)}</w:t></w:r></w:p>')


def report_docx(report: dict) -> bytes:
    s = report.get("scenario", {})
    cov = report.get("coverage", {})
    score = report.get("score") or {}
    P = [
        _para("CyberRange - After-Action Report", bold=True, size=36, color="1F4E79"),
        _para(f"{s.get('name','')}  ·  {s.get('mode','')}", size=24, color="2E75B6"),
        _para(f"Exercise: {report.get('exercise_id','')}", size=18, color="808080"),
        _para(f"Status: {report.get('status')}   Started: {report.get('started_at')}   Ended: {report.get('ended_at')}", size=18, color="808080"),
        _para("Score", bold=True, size=26, color="1F4E79"),
        _para(f"Total: {score.get('total','-')}", size=24),
    ]
    for d in (score.get("dimensions") or []):
        P.append(_para(f"  • {d['dimension']}: raw {d['raw']} × {d['weight']} = {d['contribution']}", size=20))
    P.append(_para("ATT&CK coverage", bold=True, size=26, color="1F4E79"))
    P.append(_para(f"Expected:  {', '.join(cov.get('expected', [])) or '-'}", size=20))
    P.append(_para(f"Detected:  {', '.join(cov.get('detected', [])) or '-'}", size=20))
    P.append(_para(f"Gaps:      {', '.join(cov.get('gaps', [])) or 'none'}", size=20, color="B22222"))
    fw = report.get("framework_coverage", {})
    P.append(_para("Framework crosswalk (curated, indicative)", bold=True, size=26, color="1F4E79"))
    P.append(_para(f"NIST CSF:  {', '.join(fw.get('nist_csf', [])) or '-'}", size=20))
    P.append(_para(f"NICE roles:  {', '.join(fw.get('nice', [])) or '-'}", size=20))
    P.append(_para(f"CIS Controls:  {', '.join(fw.get('cis', [])) or '-'}", size=20))
    P.append(_para(f"NSA CAE KUs:  {', '.join(fw.get('cae', [])) or '-'}", size=20))
    P.append(_para("Detections", bold=True, size=26, color="1F4E79"))
    for d in report.get("detections", []):
        P.append(_para(f"  • [{d.get('severity')}] {d.get('technique_id')} {d.get('rule_id') or ''} "
                       f"({d.get('basis')}, MTTD {d.get('latency_s')}s) - {(d.get('detail') or '')[:80]}", size=19))
    if not report.get("detections"):
        P.append(_para("  (none)", size=19))
    P.append(_para("Recommendations", bold=True, size=26, color="1F4E79"))
    for r in report.get("recommendations", []):
        P.append(_para(f"  • {r}", size=20))

    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f'<w:body>{"".join(P)}<w:sectPr/></w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", document)
    return buf.getvalue()
