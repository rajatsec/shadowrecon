"""IP intelligence: geolocation / ISP / org (ip-api.com, free) + reverse IP.

Reverse-IP (shared hosting neighbours) uses HackerTarget's free endpoint.
"""
from __future__ import annotations

from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import resolve_ips, http_get, is_ip

_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,asname,reverse,query"
_REVIP_URL = "https://api.hackertarget.com/reverseiplookup/?q={ip}"


class IPIntelModule(BaseModule):
    name = "ip_intel"
    category = Category.NETWORK
    description = "IP geolocation, ISP/org, and reverse-IP (co-hosted domains)"
    target_types = ["domain", "ip"]

    async def _geo(self, ctx: ModuleContext, ip: str) -> Dict[str, Any]:
        r = await http_get(ctx.session, _GEO_URL.format(ip=ip), timeout=10)
        if not r or r["status"] != 200:
            return {}
        try:
            import json
            data = json.loads(r["text"])
        except Exception:
            return {}
        if data.get("status") != "success":
            return {}
        data.pop("status", None)
        return data

    async def _reverse_ip(self, ctx: ModuleContext, ip: str) -> List[str]:
        r = await http_get(ctx.session, _REVIP_URL.format(ip=ip), timeout=15)
        if not r or r["status"] != 200:
            return []
        text = r["text"]
        if "error" in text.lower() or "no records" in text.lower():
            return []
        hosts = sorted({line.strip() for line in text.splitlines() if line.strip()})
        return hosts[:200]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        ips = ctx.resolved_ips or await resolve_ips(ctx.target)
        ctx.resolved_ips = sorted(set(ctx.resolved_ips) | set(ips))
        geo: Dict[str, Any] = {}
        reverse_ip: Dict[str, List[str]] = {}
        for ip in ips:
            if not is_ip(ip) or ":" in ip:
                continue
            g = await self._geo(ctx, ip)
            if g:
                geo[ip] = g
            neighbours = await self._reverse_ip(ctx, ip)
            if neighbours:
                reverse_ip[ip] = neighbours
        out: Dict[str, Any] = {}
        if geo:
            out["geo"] = geo
        if reverse_ip:
            out["reverse_ip"] = reverse_ip
        return out


registry.register(IPIntelModule())
