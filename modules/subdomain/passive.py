"""Passive subdomain enumeration — wraps the 5-provider SubdomainEnum."""
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.modules.subdomain_enum import SubdomainEnum


class PassiveSubdomainModule(BaseModule):
    name = "subdomains_passive"
    category = Category.SUBDOMAIN
    description = "Passive subdomain discovery (crt.sh, hackertarget, certspotter, alienvault, urlscan)"
    target_types = ["domain"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        selected = ctx.flags.get("providers")
        enum = SubdomainEnum(ctx.target, ctx.config, selected)
        result = await enum.run(ctx.session)
        subs = result.get("subdomains", [])
        if subs:
            ctx.subdomains = sorted(set(ctx.subdomains) | set(subs))
        return result


registry.register(PassiveSubdomainModule())
