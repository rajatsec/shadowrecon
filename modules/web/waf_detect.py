"""WAF / CDN detection via response-header and cookie signatures."""
from __future__ import annotations

from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

# Distinctive header-NAME / cookie-NAME signatures per vendor. Matching against
# header names (not arbitrary values) avoids false positives from vendor names
# that merely appear in CSP/link/reference header values.
_HEADER_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
    "akamai": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id"],
    "aws waf / cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid"],
    "fastly": ["x-fastly-request-id", "fastly-restarts"],
    "imperva / incapsula": ["x-iinfo", "x-cdn"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "f5 big-ip": ["x-waf-status"],
    "azure front door": ["x-azure-ref", "x-msedge-ref"],
    "vercel": ["x-vercel-id", "x-vercel-cache"],
    "netlify": ["x-nf-request-id"],
}

# Distinctive cookie names (checked in Set-Cookie)
_COOKIE_SIGNATURES = {
    "cloudflare": ["__cfduid", "__cf_bm"],
    "imperva / incapsula": ["incap_ses", "visid_incap"],
    "f5 big-ip": ["bigipserver"],
    "barracuda": ["barra_counter_session"],
}


class WAFDetectModule(BaseModule):
    name = "waf"
    category = Category.WEB
    description = "WAF / CDN identification (Cloudflare, Akamai, AWS, Fastly, Imperva, ...)"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        r = ctx.results.get("_http_raw") or await http_get(
            ctx.session, f"https://{ctx.target}", timeout=10
        )
        if not r:
            r = await http_get(ctx.session, f"http://{ctx.target}", timeout=10)
        if not r:
            return {}

        headers = r.get("headers", {})
        header_names = {k.lower() for k in headers.keys()}
        cookies = " ".join(v for k, v in headers.items() if k.lower() == "set-cookie").lower()
        server = headers.get("Server", "") or headers.get("server", "")
        server_l = server.lower()

        detected: List[str] = []
        for vendor, sigs in _HEADER_SIGNATURES.items():
            if any(sig in header_names for sig in sigs):
                detected.append(vendor)
        for vendor, sigs in _COOKIE_SIGNATURES.items():
            if any(sig in cookies for sig in sigs) and vendor not in detected:
                detected.append(vendor)
        # High-confidence Server-header hints
        for vendor, token in (("cloudflare", "cloudflare"), ("sucuri", "sucuri"),
                              ("fastly", "fastly"), ("vercel", "vercel")):
            if token in server_l and vendor not in detected:
                detected.append(vendor)

        return {"detected": detected, "server": server} if detected else {"server": server}


registry.register(WAFDetectModule())
