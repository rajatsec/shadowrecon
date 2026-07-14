"""Enterprise report generator (v2) — JSON, CSV, and an interactive HTML dashboard.

Consumes the RegistryEngine output (`{target, findings, report, modules}`).
PDF export is optional (via `weasyprint` / `pdfkit` if installed).
"""
from __future__ import annotations

import csv
import io
import json
import os
import time
from typing import Any, Dict, List

_DASHBOARD_CSS = """
:root { --bg:#0a0e14; --surface:#141a22; --surface2:#1c2430; --border:#2a3441;
        --text:#c9d4e0; --muted:#7a8798; --accent:#ff4d4d; --green:#3fb950;
        --yellow:#d29922; --red:#f85149; --blue:#58a6ff; --purple:#bc8cff; }
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:24px;line-height:1.5}
h1{color:var(--accent);font-size:1.7rem}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}
.card .n{font-size:1.9rem;font-weight:700;color:var(--blue)}
.card .l{font-size:.75rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.05em}
.gradeA{color:var(--green)}.gradeB{color:var(--green)}.gradeC{color:var(--yellow)}
.gradeD{color:var(--yellow)}.gradeF{color:var(--red)}
section{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:16px}
section h2{color:var(--blue);font-size:1.05rem;margin-bottom:12px;border-bottom:1px solid var(--border);padding-bottom:8px;display:flex;justify-content:space-between}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:.72rem;font-weight:600;margin:2px}
.b-green{background:#12331f;color:var(--green)}.b-red{background:#3a1414;color:var(--red)}
.b-yellow{background:#332711;color:var(--yellow)}.b-blue{background:#0f2740;color:var(--blue)}
.b-purple{background:#241833;color:var(--purple)}.b-grey{background:#20272f;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:.83rem}
th{background:var(--surface2);color:var(--muted);text-align:left;padding:7px 10px}
td{padding:6px 10px;border-top:1px solid var(--border);vertical-align:top;word-break:break-word}
.mono{font-family:monospace;font-size:.8rem}
.issue{padding:8px 12px;border-radius:6px;margin-bottom:6px;border-left:3px solid var(--border)}
.i-critical{background:#2a0f0f;border-color:var(--red)}.i-high{background:#2a1810;border-color:#ff7b42}
.i-medium{background:#2a2410;border-color:var(--yellow)}.i-low{background:#12202a;border-color:var(--blue)}
.cols{columns:3;column-gap:16px}.cols li{list-style:none;font-family:monospace;font-size:.8rem;color:var(--blue)}
details summary{cursor:pointer;color:var(--muted);font-size:.8rem}
pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;overflow:auto;font-size:.75rem;max-height:400px}
"""


def _flatten_for_csv(findings: Dict[str, Any]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for module, data in findings.items():
        if not isinstance(data, dict):
            rows.append({"module": module, "key": "", "value": str(data)})
            continue
        for k, v in data.items():
            rows.append({"module": module, "key": str(k),
                         "value": json.dumps(v, default=str)[:500]})
    return rows


class ReportGenerator:
    def __init__(self, output_dir: str = "output"):
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir

    def save_json(self, result: Dict[str, Any], filename: str) -> str | None:
        path = os.path.join(self.output_dir, f"{filename}.json")
        try:
            with open(path, "w") as f:
                json.dump(result, f, indent=2, default=str)
            return path
        except OSError:
            return None

    def save_csv(self, result: Dict[str, Any], filename: str) -> str | None:
        path = os.path.join(self.output_dir, f"{filename}.csv")
        rows = _flatten_for_csv(result.get("findings", {}))
        try:
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["module", "key", "value"])
                w.writeheader()
                w.writerows(rows)
            return path
        except OSError:
            return None

    def save_html(self, result: Dict[str, Any], filename: str) -> str | None:
        path = os.path.join(self.output_dir, f"{filename}.html")
        try:
            html = self._render_dashboard(result)
            with open(path, "w") as f:
                f.write(html)
            return path
        except Exception:
            return None

    def save_pdf(self, result: Dict[str, Any], filename: str) -> str | None:
        html_path = self.save_html(result, filename)
        if not html_path:
            return None
        pdf_path = os.path.join(self.output_dir, f"{filename}.pdf")
        try:
            from weasyprint import HTML  # optional
            HTML(html_path).write_pdf(pdf_path)
            return pdf_path
        except Exception:
            try:
                import pdfkit  # optional
                pdfkit.from_file(html_path, pdf_path)
                return pdf_path
            except Exception:
                return None

    # ---- dashboard rendering ----
    def _render_dashboard(self, result: Dict[str, Any]) -> str:
        f = result.get("findings", {})
        rep = result.get("report", {})
        target = result.get("target", "")
        risk = f.get("risk", {})
        ai = f.get("ai_summary", {})

        subs = rep.get("subdomains", [])
        ports = rep.get("open_ports", {})
        dns = rep.get("dns", {})
        grade = risk.get("grade", "-")

        parts: List[str] = []
        parts.append(f"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
        parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
        parts.append(f"<title>ShadowRecon — {target}</title><style>{_DASHBOARD_CSS}</style></head><body>")
        parts.append(f"<h1>ShadowRecon Report</h1>")
        parts.append(f"<div class='sub'>Target: <b>{target}</b> ({result.get('target_type','')}) &nbsp;|&nbsp; "
                     f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} &nbsp;|&nbsp; "
                     f"{len(result.get('modules', {}))} modules run</div>")

        # Summary cards
        parts.append("<div class='grid'>")
        parts.append(f"<div class='card'><div class='n'>{len(subs)}</div><div class='l'>Subdomains</div></div>")
        parts.append(f"<div class='card'><div class='n'>{len(ports)}</div><div class='l'>Open Ports</div></div>")
        parts.append(f"<div class='card'><div class='n'>{sum(len(v) for v in dns.values())}</div><div class='l'>DNS Records</div></div>")
        parts.append(f"<div class='card'><div class='n gradeF' style='color:inherit'>{risk.get('risk_score','-')}</div><div class='l'>Risk Score</div></div>")
        parts.append(f"<div class='card'><div class='n grade{grade}'>{grade}</div><div class='l'>Grade</div></div>")
        parts.append("</div>")

        # AI summary
        if ai:
            parts.append(f"<section><h2>AI Recon Summary <span class='badge b-grey'>{ai.get('engine','')}</span></h2>")
            parts.append(f"<p>{ai.get('summary','')}</p>")
            steps = ai.get("suggested_next_steps", [])
            if steps:
                parts.append("<ul style='margin-top:10px;padding-left:18px'>")
                for s in steps:
                    parts.append(f"<li>{s}</li>")
                parts.append("</ul>")
            parts.append("</section>")

        # Risk issues
        issues = risk.get("issues", [])
        if issues:
            parts.append("<section><h2>Risk Findings</h2>")
            for i in issues:
                sev = i.get("severity", "low")
                parts.append(f"<div class='issue i-{sev}'><b>[{sev.upper()}]</b> {i.get('issue','')} "
                             f"<span class='badge b-grey'>+{i.get('points',0)}</span></div>")
            parts.append("</section>")

        # Per-module findings (generic renderer)
        skip = {"risk", "ai_summary"}
        for module, data in f.items():
            if module in skip or not data:
                continue
            parts.append(f"<section><h2>{module}</h2>")
            parts.append(self._render_generic(module, data, subs))
            parts.append("</section>")

        parts.append("<div class='sub' style='text-align:center;margin-top:20px'>"
                     "Generated by <b>ShadowRecon</b> — For authorized use only.</div>")
        parts.append("</body></html>")
        return "".join(parts)

    def _render_generic(self, module: str, data: Any, subs: List[str]) -> str:
        if module in ("subdomains_passive", "subdomains_active") and isinstance(data, dict):
            slist = data.get("subdomains", [])
            html = "<ul class='cols'>" + "".join(f"<li>{s}</li>" for s in slist[:300]) + "</ul>"
            return html
        if module == "ports" and isinstance(data, dict):
            rows = "".join(
                f"<tr><td class='mono'>{p}</td><td>{i.get('service','')}</td>"
                f"<td>{', '.join(i.get('tech',[]))}</td><td class='mono'>{(i.get('banner') or '')[:80]}</td></tr>"
                for p, i in data.get("open_ports", {}).items())
            return f"<table><tr><th>Port</th><th>Service</th><th>Tech</th><th>Banner</th></tr>{rows}</table>"
        # default: pretty-print JSON in a collapsible block
        try:
            body = json.dumps(data, indent=2, default=str)
        except Exception:
            body = str(data)
        return f"<details open><summary>view</summary><pre>{body}</pre></details>"


def build_report(result: Dict[str, Any], output_dir: str, filename: str,
                 formats: List[str]) -> List[str]:
    gen = ReportGenerator(output_dir)
    paths: List[str] = []
    fmt = {x.lower() for x in formats}
    if "json" in fmt and (p := gen.save_json(result, filename)):
        paths.append(p)
    if "csv" in fmt and (p := gen.save_csv(result, filename)):
        paths.append(p)
    if "html" in fmt and (p := gen.save_html(result, filename)):
        paths.append(p)
    if "pdf" in fmt and (p := gen.save_pdf(result, filename)):
        paths.append(p)
    return paths
