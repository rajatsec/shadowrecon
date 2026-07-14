"""Favicon hash — Shodan-style mmh3 hash (fallback md5) for asset pivoting."""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry


class FaviconModule(BaseModule):
    name = "favicon"
    category = Category.WEB
    description = "Favicon mmh3 hash (Shodan pivot) + md5"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        import aiohttp
        for scheme in ("https", "http"):
            url = f"{scheme}://{ctx.target}/favicon.ico"
            try:
                async with ctx.session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10), ssl=False
                ) as resp:
                    if resp.status != 200:
                        continue
                    raw = await resp.read()
            except Exception:
                continue
            if not raw:
                continue
            md5 = hashlib.md5(raw).hexdigest()
            out: Dict[str, Any] = {"url": url, "md5": md5, "size": len(raw)}
            try:
                import mmh3  # optional
                b64 = base64.encodebytes(raw)
                out["mmh3"] = mmh3.hash(b64)
                out["shodan_query"] = f"http.favicon.hash:{out['mmh3']}"
            except Exception:
                out["mmh3"] = "install mmh3 for Shodan-compatible hash"
            return out
        return {}


registry.register(FaviconModule())
