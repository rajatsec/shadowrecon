"""Directory & file discovery — probes a built-in list of common paths.

Concurrency-limited, respects a status-code allowlist. This is intentionally a
small, quiet wordlist (authorized-testing friendly), extensible via config
(`web.dir_wordlist`).
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

_DEFAULT_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    ".git/config", ".env", ".env.local", "config.php", "config.json", "backup",
    "backup.zip", "backup.sql", "db.sql", "dump.sql", "old", "test", "dev",
    "staging", "api", "api/v1", "api/docs", "swagger", "swagger-ui", "openapi.json",
    "phpinfo.php", "info.php", "server-status", "actuator", "actuator/health",
    ".DS_Store", "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known/security.txt",
    "readme.md", "CHANGELOG.md", "LICENSE", "uploads", "images", "assets", "static",
    "console", "cpanel", "webmail", "phpmyadmin", "adminer.php",
]

_INTERESTING = {200, 201, 204, 301, 302, 401, 403, 500}


class DirDiscoveryModule(BaseModule):
    name = "dirs"
    category = Category.WEB
    description = "Common directory/file discovery (admin panels, configs, backups, APIs)"
    target_types = ["domain", "ip"]
    default_enabled = False  # intrusive-ish; opt-in via --modules dirs or full+

    async def _probe(self, ctx: ModuleContext, base: str, path: str, sem: asyncio.Semaphore):
        async with sem:
            r = await http_get(ctx.session, f"{base}/{path}", timeout=8, allow_redirects=False)
            if r and r["status"] in _INTERESTING:
                return path, r["status"], len(r.get("text") or "")
            return None

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        paths = ctx.config.get("web", {}).get("dir_wordlist") or _DEFAULT_PATHS

        # Determine reachable base URL
        base = None
        for scheme in ("https", "http"):
            r = await http_get(ctx.session, f"{scheme}://{ctx.target}", timeout=8)
            if r:
                base = f"{scheme}://{ctx.target}"
                break
        if not base:
            return {}

        sem = asyncio.Semaphore(min(ctx.threads, 30))
        tasks = [self._probe(ctx, base, p, sem) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found = []
        for r in results:
            if isinstance(r, tuple):
                found.append({"path": r[0], "status": r[1], "size": r[2]})
        found.sort(key=lambda x: x["status"])
        return {"base": base, "found": found} if found else {}


registry.register(DirDiscoveryModule())
