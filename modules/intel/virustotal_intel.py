"""VirusTotal integration — domain reputation + passive DNS (API key required)."""
from __future__ import annotations

import json
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry


class VirusTotalModule(BaseModule):
    name = "virustotal"
    category = Category.INTEL
    description = "VirusTotal domain reputation, categories, passive DNS (needs API key)"
    needs_api_key = True
    target_types = ["domain", "ip"]
    default_enabled = False

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        key = ctx.config.get("integrations", {}).get("virustotal", {}).get("api_key", "")
        if not key:
            return {"note": "set integrations.virustotal.api_key in config.yaml"}

        import aiohttp
        endpoint = "ip_addresses" if ctx.target_type == "ip" else "domains"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{ctx.target}"
        headers = {"x-apikey": key}
        try:
            async with ctx.session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return {"note": f"virustotal returned HTTP {resp.status}"}
                data = json.loads(await resp.text())
        except Exception as e:
            return {"error": str(e)}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "reputation": attrs.get("reputation"),
            "analysis_stats": stats,
            "categories": attrs.get("categories", {}),
            "registrar": attrs.get("registrar", ""),
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
        }


registry.register(VirusTotalModule())
