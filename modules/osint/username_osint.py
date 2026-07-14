"""Username OSINT — check a username's presence across public platforms.

Only queries public profile URLs (no login, no scraping of private data) and
records which return a 200 vs a not-found. Target type: `username`.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

# platform -> (url template, substring that indicates "not found")
_PLATFORMS = {
    "GitHub": ("https://github.com/{u}", "not found"),
    "GitLab": ("https://gitlab.com/{u}", "not found"),
    "Twitter/X": ("https://x.com/{u}", "this account doesn't exist"),
    "Instagram": ("https://www.instagram.com/{u}/", "page not found"),
    "Reddit": ("https://www.reddit.com/user/{u}", "nobody on reddit goes by"),
    "Medium": ("https://medium.com/@{u}", "page not found"),
    "Dev.to": ("https://dev.to/{u}", "404"),
    "Pinterest": ("https://www.pinterest.com/{u}/", "page not found"),
    "TikTok": ("https://www.tiktok.com/@{u}", "couldn't find this account"),
    "Telegram": ("https://t.me/{u}", "tgme_page_title"),  # presence heuristic
    "Keybase": ("https://keybase.io/{u}", "not found"),
    "HackerNews": ("https://news.ycombinator.com/user?id={u}", "no such user"),
    "Replit": ("https://replit.com/@{u}", "404"),
    "Steam": ("https://steamcommunity.com/id/{u}", "the specified profile could not be found"),
}


class UsernameOSINTModule(BaseModule):
    name = "username"
    category = Category.OSINT
    description = "Check username presence across public platforms"
    target_types = ["username"]

    async def _check(self, ctx: ModuleContext, platform: str, tmpl: str, notfound: str, sem):
        url = tmpl.format(u=ctx.target)
        async with sem:
            r = await http_get(ctx.session, url, timeout=10,
                               headers={"User-Agent": "Mozilla/5.0 ShadowRecon"})
        if not r:
            return platform, {"url": url, "found": None, "note": "request failed"}
        status = r["status"]
        body = (r.get("text") or "").lower()
        if status == 200 and notfound not in body:
            return platform, {"url": url, "found": True, "status": status}
        if status == 404 or notfound in body:
            return platform, {"url": url, "found": False, "status": status}
        return platform, {"url": url, "found": None, "status": status}

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        sem = asyncio.Semaphore(15)
        tasks = [self._check(ctx, p, t, nf, sem) for p, (t, nf) in _PLATFORMS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        by_platform: Dict[str, Any] = {}
        for r in results:
            if isinstance(r, tuple):
                by_platform[r[0]] = r[1]
        found = sorted(p for p, v in by_platform.items() if v.get("found") is True)
        return {"username": ctx.target, "found_on": found, "results": by_platform}


registry.register(UsernameOSINTModule())
