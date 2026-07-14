"""JavaScript analysis — extract JS files, hidden endpoints/API routes, and

flag likely secrets (API keys, tokens) using conservative regexes.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_ENDPOINT_RE = re.compile(r'["\'](/[a-zA-Z0-9_\-/.]+(?:\?[^"\']*)?)["\']')
_FULLURL_RE = re.compile(r'["\'](https?://[a-zA-Z0-9._\-/]+/[a-zA-Z0-9._\-/?=&]*)["\']')

# Conservative secret patterns — label -> regex
_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "github_token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "generic_api_key": re.compile(r"(?i)(?:api[_-]?key|secret|token)\"?\s*[:=]\s*\"([A-Za-z0-9_\-]{16,})\""),
}


class JSAnalyzerModule(BaseModule):
    name = "js"
    category = Category.WEB
    description = "JS file extraction, hidden endpoints/API routes, secret detection"
    target_types = ["domain", "ip"]
    default_enabled = False  # fetches multiple JS files; opt-in

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        base = None
        home = None
        for scheme in ("https", "http"):
            r = await http_get(ctx.session, f"{scheme}://{ctx.target}", timeout=12)
            if r:
                base = f"{scheme}://{ctx.target}"
                home = r
                break
        if not home:
            return {}

        html = home.get("text") or ""
        js_urls: Set[str] = set()
        for src in _SCRIPT_SRC_RE.findall(html):
            js_urls.add(urljoin(base + "/", src))
        js_urls = set(list(js_urls)[:15])  # cap

        endpoints: Set[str] = set()
        secrets: List[Dict[str, str]] = []

        async def _scan_js(url: str):
            r = await http_get(ctx.session, url, timeout=10)
            if not r or r["status"] != 200:
                return
            body = r.get("text") or ""
            for ep in _ENDPOINT_RE.findall(body):
                if len(ep) > 2 and not ep.endswith((".png", ".jpg", ".svg", ".css", ".woff", ".gif")):
                    endpoints.add(ep)
            for full in _FULLURL_RE.findall(body):
                endpoints.add(full)
            for label, pat in _SECRET_PATTERNS.items():
                for m in pat.findall(body):
                    val = m if isinstance(m, str) else m[0]
                    secrets.append({"type": label, "value": val[:40], "source": url})

        # Also scan the homepage HTML for inline endpoints/secrets
        await asyncio.gather(*[_scan_js(u) for u in js_urls], return_exceptions=True)
        for ep in _ENDPOINT_RE.findall(html):
            if len(ep) > 2:
                endpoints.add(ep)

        out: Dict[str, Any] = {}
        if js_urls:
            out["js_files"] = sorted(js_urls)
        if endpoints:
            out["endpoints"] = sorted(endpoints)[:200]
        if secrets:
            # de-dupe
            seen = set()
            uniq = []
            for s in secrets:
                key = (s["type"], s["value"])
                if key not in seen:
                    seen.add(key)
                    uniq.append(s)
            out["potential_secrets"] = uniq[:50]
        return out


registry.register(JSAnalyzerModule())
