"""SecurityTrails integration — historical DNS + subdomains (API key required)."""
from __future__ import annotations

import json
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry


class SecurityTrailsModule(BaseModule):
    name = "securitytrails"
    category = Category.INTEL
    description = "SecurityTrails subdomains + historical DNS (needs API key)"
    needs_api_key = True
    target_types = ["domain"]
    default_enabled = False

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        key = ctx.config.get("integrations", {}).get("securitytrails", {}).get("api_key", "")
        if not key:
            return {"note": "set integrations.securitytrails.api_key in config.yaml"}

        import aiohttp
        headers = {"APIKEY": key}
        out: Dict[str, Any] = {}
        base = "https://api.securitytrails.com/v1"

        async def _get(path):
            try:
                async with ctx.session.get(f"{base}{path}", headers=headers,
                                           timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        return None
                    return json.loads(await resp.text())
            except Exception:
                return None

        subs = await _get(f"/domain/{ctx.target}/subdomains")
        if subs and "subdomains" in subs:
            full = sorted(f"{s}.{ctx.target}" for s in subs["subdomains"])
            out["subdomains"] = full[:500]
            if full:
                ctx.subdomains = sorted(set(ctx.subdomains) | set(full))

        hist = await _get(f"/history/{ctx.target}/dns/a")
        if hist and "records" in hist:
            out["historical_a"] = hist["records"][:20]

        return out


registry.register(SecurityTrailsModule())
