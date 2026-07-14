"""ASN lookup via Team Cymru's DNS-based IP-to-ASN service (no API key)."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import aiodns

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import resolve_ips, is_ip


async def _cymru_asn(resolver: aiodns.DNSResolver, ip: str) -> Dict[str, str]:
    """origin.asn.cymru.com TXT lookup for an IPv4 address."""
    if ":" in ip:  # IPv6 handled by origin6; keep it simple, skip
        return {}
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    try:
        answers = await resolver.query(query, "TXT")
    except Exception:
        return {}
    if not answers:
        return {}
    txt = answers[0].text
    if isinstance(txt, bytes):
        txt = txt.decode()
    # Format: "ASN | BGP Prefix | CC | Registry | Allocated"
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 5:
        return {}
    asn = parts[0].split()[0]
    info = {"asn": asn, "prefix": parts[1], "country": parts[2], "registry": parts[3]}
    # Second lookup: ASN -> org name
    try:
        as_answers = await resolver.query(f"AS{asn}.asn.cymru.com", "TXT")
        if as_answers:
            as_txt = as_answers[0].text
            if isinstance(as_txt, bytes):
                as_txt = as_txt.decode()
            as_parts = [p.strip() for p in as_txt.split("|")]
            if as_parts:
                info["as_name"] = as_parts[-1]
    except Exception:
        pass
    return info


class ASNModule(BaseModule):
    name = "asn"
    category = Category.NETWORK
    description = "ASN / BGP prefix / AS owner for resolved IPs (Team Cymru)"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        ips = ctx.resolved_ips or await resolve_ips(ctx.target)
        ctx.resolved_ips = sorted(set(ctx.resolved_ips) | set(ips))
        resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        out: Dict[str, Any] = {}
        for ip in ips:
            if is_ip(ip):
                info = await _cymru_asn(resolver, ip)
                if info:
                    out[ip] = info
        return {"asn": out} if out else {}


registry.register(ASNModule())
