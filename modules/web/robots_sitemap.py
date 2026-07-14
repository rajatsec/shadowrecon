"""robots.txt + sitemap.xml discovery and parsing."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)


class RobotsSitemapModule(BaseModule):
    name = "robots_sitemap"
    category = Category.WEB
    description = "robots.txt directives + sitemap.xml URLs"
    target_types = ["domain"]

    async def _fetch(self, ctx: ModuleContext, path: str):
        for scheme in ("https", "http"):
            r = await http_get(ctx.session, f"{scheme}://{ctx.target}/{path}", timeout=10)
            if r and r["status"] == 200 and r.get("text"):
                return r["text"]
        return ""

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        out: Dict[str, Any] = {}

        robots = await self._fetch(ctx, "robots.txt")
        if robots and "<html" not in robots.lower():
            disallow = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", robots)
            allow = re.findall(r"(?im)^\s*Allow:\s*(\S+)", robots)
            sitemaps = re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", robots)
            out["robots"] = {
                "disallow": sorted(set(disallow))[:100],
                "allow": sorted(set(allow))[:100],
                "sitemaps": sorted(set(sitemaps)),
            }

        sitemap = await self._fetch(ctx, "sitemap.xml")
        if sitemap and "<loc>" in sitemap.lower():
            locs = _LOC_RE.findall(sitemap)
            out["sitemap_urls"] = sorted(set(locs))[:300]

        return out


registry.register(RobotsSitemapModule())
