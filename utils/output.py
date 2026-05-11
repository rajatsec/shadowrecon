import json
import os
import time
from typing import Any, Dict

from jinja2 import Template

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowRecon Report — {{ domain }}</title>
<style>
  :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9;
          --accent: #ff4d4d; --green: #3fb950; --yellow: #d29922; --red: #f85149;
          --blue: #58a6ff; --purple: #bc8cff; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; padding: 24px; }
  h1 { color: var(--accent); font-size: 1.8rem; margin-bottom: 4px; }
  .meta { color: #8b949e; font-size: .85rem; margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .card .num { font-size: 2rem; font-weight: bold; color: var(--blue); }
  .card .label { font-size: .8rem; color: #8b949e; margin-top: 4px; }
  section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  section h2 { color: var(--blue); font-size: 1.1rem; margin-bottom: 14px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th { background: #21262d; color: #8b949e; text-align: left; padding: 8px 12px; font-weight: 600; }
  td { padding: 7px 12px; border-top: 1px solid var(--border); vertical-align: top; word-break: break-all; }
  tr:hover td { background: #1c2128; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: .75rem; font-weight: 600; }
  .badge-green { background: #1a3a27; color: var(--green); }
  .badge-red { background: #3d1a1a; color: var(--red); }
  .badge-yellow { background: #3d2e0a; color: var(--yellow); }
  .badge-purple { background: #2a1f3d; color: var(--purple); }
  .takeover-alert { background: #3d1a1a; border: 1px solid var(--red); border-radius: 6px; padding: 12px 16px; margin-bottom: 8px; }
  .mono { font-family: monospace; font-size: .82rem; }
  .score { font-size: 1.4rem; font-weight: bold; }
  .score-good { color: var(--green); }
  .score-warn { color: var(--yellow); }
  .score-bad { color: var(--red); }
  ul.sublist { list-style: none; columns: 3; column-gap: 16px; }
  ul.sublist li { font-size: .82rem; padding: 2px 0; color: var(--blue); font-family: monospace; }
  .provider-chip { display: inline-block; background: #21262d; border: 1px solid var(--border);
                   border-radius: 4px; padding: 3px 8px; margin: 2px; font-size: .75rem; }
  .provider-chip .cnt { color: var(--blue); font-weight: bold; }
</style>
</head>
<body>
<h1>ShadowRecon Report</h1>
<div class="meta">Target: <strong>{{ domain }}</strong> &nbsp;|&nbsp; Generated: {{ timestamp }}</div>

<!-- Summary Cards -->
<div class="grid">
  <div class="card"><div class="num">{{ subdomain_count }}</div><div class="label">Subdomains Found</div></div>
  <div class="card"><div class="num">{{ port_count }}</div><div class="label">Open Ports</div></div>
  <div class="card"><div class="num">{{ dns_record_count }}</div><div class="label">DNS Records</div></div>
  <div class="card">
    <div class="num {% if header_score >= 7 %}score-good{% elif header_score >= 4 %}score-warn{% else %}score-bad{% endif %}">
      {{ header_score }}/{{ total_headers }}
    </div>
    <div class="label">Security Headers</div>
  </div>
  {% if takeover_count %}
  <div class="card"><div class="num score-bad">{{ takeover_count }}</div><div class="label">Takeover Risks</div></div>
  {% endif %}
</div>

<!-- Takeover Alerts -->
{% if takeovers %}
<section>
  <h2>⚠ Subdomain Takeover Risks</h2>
  {% for t in takeovers %}
  <div class="takeover-alert">
    <strong class="score-bad">{{ t.subdomain }}</strong> &rarr; <span class="mono">{{ t.cname }}</span><br>
    <span class="badge badge-red">{{ t.service }}</span>
    <span style="margin-left:8px;font-size:.82rem;">Fingerprint: <em>{{ t.fingerprint }}</em></span>
  </div>
  {% endfor %}
</section>
{% endif %}

<!-- HTTP Analysis -->
{% if http %}
<section>
  <h2>HTTP Analysis</h2>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>URL</td><td class="mono">{{ http.url }}</td></tr>
    <tr><td>Status</td><td>{{ http.status_code }}</td></tr>
    <tr><td>Server</td><td>{{ http.server }}</td></tr>
    {% if http.powered_by %}<tr><td>Powered By</td><td>{{ http.powered_by }}</td></tr>{% endif %}
    {% if http.title %}<tr><td>Title</td><td>{{ http.title }}</td></tr>{% endif %}
    <tr><td>HTTPS</td><td>{% if http.is_https %}<span class="badge badge-green">Yes</span>{% else %}<span class="badge badge-red">No</span>{% endif %}</td></tr>
  </table>

  <h2 style="margin-top:18px;">Security Headers</h2>
  <table>
    <tr><th>Header</th><th>Status</th><th>Value</th></tr>
    {% for h, v in http.found_headers.items() %}
    <tr><td class="mono">{{ h }}</td><td><span class="badge badge-green">Present</span></td><td class="mono">{{ v[:80] }}</td></tr>
    {% endfor %}
    {% for h in http.missing_headers %}
    <tr><td class="mono">{{ h }}</td><td><span class="badge badge-red">Missing</span></td><td></td></tr>
    {% endfor %}
  </table>

  {% if http.cookie_issues %}
  <h2 style="margin-top:18px;">Cookie Issues</h2>
  <ul>{% for issue in http.cookie_issues %}<li class="badge badge-yellow" style="margin:4px 0;">{{ issue }}</li>{% endfor %}</ul>
  {% endif %}
</section>
{% endif %}

<!-- DNS Records -->
{% if dns %}
<section>
  <h2>DNS Records</h2>
  <table>
    <tr><th>Type</th><th>Records</th></tr>
    {% for rtype, records in dns.items() %}
    <tr><td><span class="badge badge-purple">{{ rtype }}</span></td>
        <td class="mono">{{ records | join('<br>') }}</td></tr>
    {% endfor %}
  </table>
</section>
{% endif %}

<!-- Open Ports -->
{% if open_ports %}
<section>
  <h2>Open Ports</h2>
  <table>
    <tr><th>Port</th><th>Service</th><th>Tech</th><th>Banner</th></tr>
    {% for port, info in open_ports.items() %}
    <tr>
      <td><span class="badge badge-blue" style="background:#112233;color:#58a6ff;">{{ port }}</span></td>
      <td>{{ info.service }}</td>
      <td>{% for t in info.tech %}<span class="badge badge-purple" style="margin:1px;">{{ t }}</span>{% endfor %}</td>
      <td class="mono">{{ info.banner[:120] if info.banner else '-' }}</td>
    </tr>
    {% endfor %}
  </table>
</section>
{% endif %}

<!-- Subdomains -->
{% if subdomains %}
<section>
  <h2>Subdomains ({{ subdomains | length }})</h2>
  {% if per_provider %}
  <div style="margin-bottom:12px;">
    {% for name, subs in per_provider.items() %}
    <span class="provider-chip">{{ name }} <span class="cnt">{{ subs | length }}</span></span>
    {% endfor %}
  </div>
  {% endif %}
  <ul class="sublist">
    {% for sub in subdomains %}<li>{{ sub }}</li>{% endfor %}
  </ul>
</section>
{% endif %}

<div class="meta" style="margin-top:24px;text-align:center;">
  Generated by <strong>ShadowRecon</strong> &mdash; For authorized use only.
</div>
</body>
</html>
"""


class OutputHandler:
    def __init__(self, output_dir: str = "output"):
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir

    def save_json(self, data: Dict[str, Any], filename: str) -> str | None:
        filepath = os.path.join(self.output_dir, f"{filename}.json")
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=4, default=str)
            return filepath
        except OSError as e:
            return None

    def save_txt(self, data: Dict[str, Any], filename: str) -> str | None:
        filepath = os.path.join(self.output_dir, f"{filename}.txt")
        domain = data.get("domain", "Target")
        try:
            with open(filepath, "w") as f:
                f.write(f"ShadowRecon Report: {domain}\n")
                f.write("=" * 60 + "\n\n")

                if data.get("dns"):
                    f.write("DNS Records:\n")
                    for rtype, records in data["dns"].items():
                        f.write(f"  {rtype}:\n")
                        for r in records:
                            f.write(f"    - {r}\n")
                    f.write("\n" + "-" * 40 + "\n\n")

                subs = data.get("subdomains", [])
                f.write(f"Subdomains Found ({len(subs)}):\n")
                for sub in subs:
                    f.write(f"  - {sub}\n")

                per_provider = data.get("per_provider", {})
                if per_provider:
                    f.write("\n  Per-Provider Breakdown:\n")
                    for name, psubs in per_provider.items():
                        f.write(f"    {name}: {len(psubs)}\n")

                f.write("\n" + "=" * 60 + "\n\n")

                http = data.get("http", {})
                if http:
                    f.write("HTTP Analysis:\n")
                    f.write(f"  URL: {http.get('url', '')}\n")
                    f.write(f"  Status: {http.get('status_code', '')}\n")
                    f.write(f"  Server: {http.get('server', '')}\n")
                    if http.get("powered_by"):
                        f.write(f"  Powered-By: {http['powered_by']}\n")
                    if http.get("title"):
                        f.write(f"  Title: {http['title']}\n")
                    missing = http.get("missing_headers", [])
                    if missing:
                        f.write("  Missing Security Headers:\n")
                        for mh in missing:
                            f.write(f"    [!] {mh}\n")
                    if http.get("cookie_issues"):
                        f.write("  Cookie Issues:\n")
                        for ci in http["cookie_issues"]:
                            f.write(f"    [!] {ci}\n")
                    f.write("\n" + "-" * 40 + "\n\n")

                ports = data.get("open_ports", {})
                f.write(f"Open Ports ({len(ports)}):\n")
                for port, info in ports.items():
                    tech = ", ".join(info.get("tech", [])) or ""
                    tech_str = f" [{tech}]" if tech else ""
                    banner = f" | {info['banner']}" if info.get("banner") else ""
                    f.write(f"  - {port} ({info.get('service', 'unknown')}){tech_str}{banner}\n")

                takeovers = data.get("takeovers", [])
                if takeovers:
                    f.write("\n" + "=" * 60 + "\n\n")
                    f.write(f"Subdomain Takeover Risks ({len(takeovers)}):\n")
                    for t in takeovers:
                        f.write(f"  [VULNERABLE] {t['subdomain']} -> {t['cname']} ({t['service']})\n")

            return filepath
        except OSError:
            return None

    def save_html(self, data: Dict[str, Any], filename: str) -> str | None:
        filepath = os.path.join(self.output_dir, f"{filename}.html")
        domain = data.get("domain", "")
        http = data.get("http", {})
        found_h = http.get("found_headers", {})
        missing_h = http.get("missing_headers", [])
        total_headers = len(found_h) + len(missing_h)

        try:
            tmpl = Template(_HTML_TEMPLATE)
            html = tmpl.render(
                domain=domain,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                subdomain_count=len(data.get("subdomains", [])),
                port_count=len(data.get("open_ports", {})),
                dns_record_count=sum(len(v) for v in data.get("dns", {}).values()),
                header_score=len(found_h),
                total_headers=total_headers or 1,
                takeover_count=len(data.get("takeovers", [])),
                takeovers=data.get("takeovers", []),
                http=http,
                dns=data.get("dns", {}),
                open_ports=data.get("open_ports", {}),
                subdomains=data.get("subdomains", []),
                per_provider=data.get("per_provider", {}),
            )
            with open(filepath, "w") as f:
                f.write(html)
            return filepath
        except Exception:
            return None
