"""Heuristic risk scoring — turns raw findings into a 0-100 score + graded issues.

Runs in the ANALYSIS phase (last) so every other module has populated the shared
context. No external calls; pure local reasoning.
"""
from __future__ import annotations

from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry

_SENSITIVE_PORTS = {21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP",
                    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                    9200: "Elasticsearch", 5900: "VNC", 445: "SMB"}


class RiskScoreModule(BaseModule):
    name = "risk"
    category = Category.ANALYSIS
    description = "Heuristic attack-surface risk score and graded findings"
    needs_network = False
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        issues: List[Dict[str, str]] = []
        score = 0

        def add(sev: str, points: int, msg: str):
            nonlocal score
            score += points
            issues.append({"severity": sev, "points": points, "issue": msg})

        # Takeovers (critical)
        tk = ctx.results.get("takeover", {}).get("takeovers", [])
        for t in tk:
            add("critical", 30, f"Subdomain takeover: {t.get('subdomain')} → {t.get('service')}")

        # Exposed secrets
        secrets = ctx.results.get("js", {}).get("potential_secrets", [])
        for s in secrets:
            add("high", 15, f"Potential secret in JS ({s.get('type')})")

        # Public cloud buckets with listing
        for b in ctx.results.get("cloud", {}).get("buckets", []):
            if b.get("public_listing"):
                add("high", 15, f"Public cloud bucket listing: {b.get('bucket')} ({b.get('provider')})")

        # Sensitive open ports
        ports = ctx.results.get("ports", {}).get("open_ports", {})
        for p in ports:
            try:
                pi = int(p)
            except (ValueError, TypeError):
                continue
            if pi in _SENSITIVE_PORTS:
                add("medium", 8, f"Sensitive service exposed: {_SENSITIVE_PORTS[pi]} (port {pi})")

        # TLS weaknesses
        ssl = ctx.results.get("ssl", {})
        for weak in ssl.get("weak_protocols", []):
            add("medium", 6, f"Weak TLS protocol enabled: {weak}")
        days = ssl.get("days_until_expiry")
        if isinstance(days, int) and days < 15:
            sev = "high" if days < 0 else "medium"
            add(sev, 8, f"TLS certificate expires in {days} days")

        # Missing security headers
        http = ctx.results.get("http", {})
        missing = http.get("missing_headers", [])
        if len(missing) >= 5:
            add("low", 5, f"{len(missing)} security headers missing")
        for ci in http.get("cookie_issues", []):
            add("low", 2, ci)

        # Interesting exposed dirs
        for d in ctx.results.get("dirs", {}).get("found", []):
            if d.get("path", "").lstrip("/").startswith((".git", ".env", "backup", "phpinfo")):
                add("high", 12, f"Sensitive path exposed: /{d['path']} ({d['status']})")

        # Missing SPF/DMARC
        mail = ctx.results.get("email", {}).get("mail_security", {})
        if mail:
            if not mail.get("spf_present"):
                add("low", 3, "No SPF record (email spoofing risk)")
            if not mail.get("dmarc_present"):
                add("low", 3, "No DMARC record (email spoofing risk)")

        score = min(score, 100)
        if score >= 60:
            grade = "F"
        elif score >= 40:
            grade = "D"
        elif score >= 25:
            grade = "C"
        elif score >= 10:
            grade = "B"
        else:
            grade = "A"

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        issues.sort(key=lambda x: order.get(x["severity"], 9))
        return {
            "risk_score": score,
            "grade": grade,
            "issue_count": len(issues),
            "issues": issues,
        }


registry.register(RiskScoreModule())
