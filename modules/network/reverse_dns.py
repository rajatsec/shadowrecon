"""Reverse DNS (PTR) for the target's resolved IP addresses."""
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import resolve_ips, reverse_dns


class ReverseDNSModule(BaseModule):
    name = "reverse_dns"
    category = Category.NETWORK
    description = "Reverse DNS (PTR) records for resolved IPs"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        ips = ctx.resolved_ips or await resolve_ips(ctx.target)
        ctx.resolved_ips = sorted(set(ctx.resolved_ips) | set(ips))
        ptr: Dict[str, str] = {}
        for ip in ips:
            name = await reverse_dns(ip)
            if name:
                ptr[ip] = name
        return {"ptr": ptr} if ptr else {}


registry.register(ReverseDNSModule())
