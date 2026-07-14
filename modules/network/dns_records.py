"""DNS records module — wraps the DNS enumerator into the module framework."""
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.modules.dns_enum import DNSEnum
from shadowrecon.utils.netutil import resolve_ips


class DNSRecordsModule(BaseModule):
    name = "dns"
    category = Category.NETWORK
    description = "DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) + resolved IPs"
    target_types = ["domain"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        records = await DNSEnum(ctx.target).run()
        ips = await resolve_ips(ctx.target)
        if ips:
            # Publish resolved IPs so IP-intel / ASN modules can reuse them
            ctx.resolved_ips = sorted(set(ctx.resolved_ips) | set(ips))
        return {"records": records, "resolved_ips": ips}


registry.register(DNSRecordsModule())
