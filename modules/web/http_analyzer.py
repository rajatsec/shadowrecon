"""HTTP analyzer — security headers, server info, title, cookies, redirect chain."""
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.modules.http_probe import HTTPProbe
from shadowrecon.utils.netutil import http_get


class HTTPAnalyzerModule(BaseModule):
    name = "http"
    category = Category.WEB
    description = "HTTP status, server, title, security headers, cookies, redirect chain"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        probe = await HTTPProbe(ctx.target).run(ctx.session)

        # Redirect chain (separate follow to record the hops)
        chain = []
        r = await http_get(ctx.session, f"https://{ctx.target}", timeout=10, allow_redirects=True)
        if not r:
            r = await http_get(ctx.session, f"http://{ctx.target}", timeout=10, allow_redirects=True)
        if r and r.get("history"):
            chain = r["history"] + [r["url"]]

        if chain:
            probe["redirect_chain"] = chain
        # Expose to context for tech-detect / waf modules to reuse
        ctx.results.setdefault("_http_raw", r or {})
        return probe


registry.register(HTTPAnalyzerModule())
