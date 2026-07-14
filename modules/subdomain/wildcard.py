"""Wildcard DNS detection — resolves random labels to spot catch-all records."""
from __future__ import annotations

import asyncio
import random
import string
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import resolve_ips


def _rand_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class WildcardModule(BaseModule):
    name = "wildcard"
    category = Category.SUBDOMAIN
    description = "Detect wildcard/catch-all DNS so active enum can filter false positives"
    target_types = ["domain"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        probes = [f"{_rand_label()}.{ctx.target}" for _ in range(3)]
        results = await asyncio.gather(*[resolve_ips(p) for p in probes])
        wildcard_ips = sorted({ip for r in results for ip in r})
        is_wildcard = bool(wildcard_ips)
        # Store so the active module can drop matches
        ctx.flags["wildcard_ips"] = wildcard_ips
        return {"is_wildcard": is_wildcard, "wildcard_ips": wildcard_ips}


registry.register(WildcardModule())
