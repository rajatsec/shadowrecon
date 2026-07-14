"""Subdomain takeover detection — wraps TakeoverDetector into the framework.

Runs against subdomains discovered earlier in the scan (from the passive/active
subdomain modules), so it only does useful work once those have populated the
shared context.
"""
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.modules.takeover import TakeoverDetector


class TakeoverModule(BaseModule):
    name = "takeover"
    category = Category.WEB
    description = "Subdomain takeover detection (dangling CNAME + fingerprint)"
    target_types = ["domain"]
    default_enabled = False  # opt-in; needs subdomains + extra requests

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        subs: List[str] = ctx.subdomains
        if not subs:
            # fall back to whatever passive/active modules stored
            for key in ("subdomains_passive", "subdomains_active"):
                data = ctx.results.get(key, {})
                subs = subs or data.get("subdomains", [])
        if not subs:
            return {}
        takeovers = await TakeoverDetector(ctx.target).run(subs, ctx.session)
        return {"takeovers": takeovers} if takeovers else {}


registry.register(TakeoverModule())
