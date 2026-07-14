"""Shodan integration — host intelligence for the target's IP (API key required)."""
from __future__ import annotations

import json
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import resolve_ips, http_get


class ShodanModule(BaseModule):
    name = "shodan"
    category = Category.INTEL
    description = "Shodan host data: open ports, services, vulns, tags (needs API key)"
    needs_api_key = True
    target_types = ["domain", "ip"]
    default_enabled = False

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        key = ctx.config.get("integrations", {}).get("shodan", {}).get("api_key", "")
        if not key:
            return {"note": "set integrations.shodan.api_key in config.yaml"}

        ips = ctx.resolved_ips or await resolve_ips(ctx.target)
        out: Dict[str, Any] = {}
        for ip in ips[:3]:
            r = await http_get(ctx.session, f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=15)
            if not r or r["status"] != 200:
                continue
            try:
                data = json.loads(r["text"])
            except Exception:
                continue
            out[ip] = {
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "isp": data.get("isp", ""),
                "tags": data.get("tags", []),
                "vulns": list(data.get("vulns", []))[:50],
                "services": sorted({f"{d.get('port')}/{d.get('_shodan', {}).get('module', '')}"
                                    for d in data.get("data", [])}),
            }
        return {"hosts": out} if out else {}


registry.register(ShodanModule())
