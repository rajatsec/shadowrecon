"""WAF / CDN detection via response-header and cookie signatures."""
from __future__ import annotations

from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

# signature -> vendor. Matched (case-insensitive) against the raw header blob.
_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "akamai": ["akamai", "akamaighost", "x-akamai"],
    "aws_waf / cloudfront": ["x-amz-cf-id", "x-amzn-requestid", "awselb", "cloudfront"],
    "fastly": ["fastly", "x-fastly", "x-served-by"],
    "imperva / incapsula": ["incap_ses", "visid_incap", "x-iinfo", "incapsula"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
    "f5 big-ip": ["bigipserver", "f5-"],
    "barracuda": ["barra_counter_session", "barracuda"],
    "wordfence": ["wordfence"],
    "azure front door": ["x-azure-ref", "x-msedge-ref"],
    "google cloud": ["via: 1.1 google", "gws"],
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

        blob_parts = [f"{k}: {v}" for k, v in r.get("headers", {}).items()]
        blob = " ".join(blob_parts).lower()

        detected: List[str] = []
        for vendor, sigs in _SIGNATURES.items():
            if any(sig in blob for sig in sigs):
                detected.append(vendor)

        server = r.get("headers", {}).get("Server", "")
        return {"detected": detected, "server": server} if detected else {"server": server}


registry.register(WAFDetectModule())
