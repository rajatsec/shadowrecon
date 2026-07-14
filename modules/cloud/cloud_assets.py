"""Cloud asset discovery — guesses public S3 / Azure Blob / GCS buckets from the

organisation name, checks their existence/permissions, and detects the CDN/cloud
provider fronting the target.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

_PERMUTATIONS = [
    "{n}", "{n}-prod", "{n}-dev", "{n}-staging", "{n}-backup", "{n}-backups",
    "{n}-assets", "{n}-static", "{n}-media", "{n}-uploads", "{n}-data",
    "{n}-files", "{n}-public", "{n}-private", "{n}-web", "{n}-cdn", "{n}-logs",
    "prod-{n}", "dev-{n}", "backup-{n}", "assets-{n}", "static-{n}",
]

_PROVIDERS = {
    "aws_s3": "https://{b}.s3.amazonaws.com",
    "gcs": "https://storage.googleapis.com/{b}",
    "azure_blob": "https://{b}.blob.core.windows.net/?comp=list",
}

_CDN_SIGNS = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
    "Akamai": ["akamai"],
    "Fastly": ["fastly", "x-served-by"],
    "Google Cloud": ["gws", "x-goog"],
    "Azure": ["x-azure-ref", "x-ms-"],
}


class CloudAssetsModule(BaseModule):
    name = "cloud"
    category = Category.CLOUD
    description = "Public cloud storage discovery (S3/GCS/Azure) + CDN/provider detection"
    target_types = ["domain"]
    default_enabled = False  # generates guessed requests; opt-in

    def _base_name(self, ctx: ModuleContext) -> str:
        # org from whois if available, else the domain's second-level label
        org = ""
        whois = ctx.results.get("whois", {})
        org = (whois.get("registrant_org") or "").lower()
        name = ctx.target.rsplit(".", 2)[0] if ctx.target.count(".") >= 1 else ctx.target
        name = name.split(".")[-1]
        return "".join(c for c in name if c.isalnum()) or ctx.target.split(".")[0]

    async def _check_bucket(self, ctx: ModuleContext, provider: str, tmpl: str, bucket: str, sem):
        url = tmpl.format(b=bucket)
        async with sem:
            r = await http_get(ctx.session, url, timeout=8, allow_redirects=False)
        if not r:
            return None
        status = r["status"]
        body = (r.get("text") or "").lower()
        # Heuristics for "exists"
        exists = status in (200, 403)
        public = status == 200 and ("<listbucketresult" in body or "<enumerationresults" in body or "<?xml" in body)
        if exists:
            return {
                "provider": provider, "bucket": bucket, "url": url,
                "status": status, "public_listing": public,
            }
        return None

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        base = self._base_name(ctx)
        names = [p.format(n=base) for p in _PERMUTATIONS]

        sem = asyncio.Semaphore(20)
        tasks = []
        for provider, tmpl in _PROVIDERS.items():
            for name in names:
                tasks.append(self._check_bucket(ctx, provider, tmpl, name, sem))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        buckets = [r for r in results if isinstance(r, dict)]

        # CDN / provider detection from homepage headers
        cdn: List[str] = []
        r = ctx.results.get("_http_raw") or await http_get(ctx.session, f"https://{ctx.target}", timeout=10)
        if r:
            blob = " ".join(f"{k}: {v}" for k, v in r.get("headers", {}).items()).lower()
            for name, sigs in _CDN_SIGNS.items():
                if any(s in blob for s in sigs):
                    cdn.append(name)

        out: Dict[str, Any] = {}
        if buckets:
            out["buckets"] = buckets
        if cdn:
            out["cdn"] = sorted(set(cdn))
        return out


registry.register(CloudAssetsModule())
