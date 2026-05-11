import asyncio
import logging
from typing import Any, Dict, List

import aiohttp
import dns.resolver

logger = logging.getLogger("ShadowRecon")

# Service CNAME suffix → fingerprint string in HTTP response body
TAKEOVER_FINGERPRINTS: Dict[str, str] = {
    "s3.amazonaws.com":               "NoSuchBucket",
    "s3-website":                     "NoSuchBucket",
    "github.io":                      "There isn't a GitHub Pages site here",
    "herokuapp.com":                  "No such app",
    "ghost.io":                       "404 — Unknown site",
    "surge.sh":                       "project not found",
    "bitbucket.io":                   "Repository not found",
    "helpjuice.com":                  "We could not find what you're looking for",
    "readme.io":                      "Project doesnt exist",
    "fastly.net":                     "Fastly error: unknown domain",
    "shopify.com":                    "Sorry, this shop is currently unavailable",
    "statuspage.io":                  "Better Uptime",
    "uservoice.com":                  "This UserVoice subdomain is currently available",
    "zendesk.com":                    "Help Center Closed",
    "wp.com":                         "Do you want to register",
    "webflow.io":                     "The page you are looking for doesn't exist",
    "fly.dev":                        "404 Not Found",
    "azurewebsites.net":              "404 Web Site not found",
    "cloudapp.net":                   "404 Web Site not found",
    "trafficmanager.net":             "404 Web Site not found",
    "blob.core.windows.net":          "The specified container does not exist",
    "table.core.windows.net":         "The specified resource does not exist",
    "queue.core.windows.net":         "The specified queue does not exist",
    "firebaseapp.com":                "Firebase App Not Found",
}


def _cname_for(subdomain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


class TakeoverDetector:
    def __init__(self, domain: str):
        self.domain = domain

    async def _check_one(
        self, session: aiohttp.ClientSession, subdomain: str
    ) -> Dict[str, Any] | None:
        cname = await asyncio.get_event_loop().run_in_executor(None, _cname_for, subdomain)
        if not cname:
            return None

        matched_service = None
        matched_fingerprint = None
        for service_suffix, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if service_suffix in cname:
                matched_service = service_suffix
                matched_fingerprint = fingerprint
                break

        if not matched_service:
            return None

        # Verify by fetching the subdomain and checking for fingerprint
        for proto in ("https", "http"):
            url = f"{proto}://{subdomain}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=8),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    body = await asyncio.wait_for(resp.text(errors="ignore"), timeout=5)
                    if matched_fingerprint.lower() in body.lower():
                        return {
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": matched_service,
                            "fingerprint": matched_fingerprint,
                            "vulnerable": True,
                        }
                    break
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                continue

        return None

    async def run(
        self, subdomains: List[str], session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        sem = asyncio.Semaphore(20)

        async def _guarded(sub: str):
            async with sem:
                return await self._check_one(session, sub)

        tasks = [_guarded(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulnerable = []
        for r in results:
            if isinstance(r, dict) and r and r.get("vulnerable"):
                vulnerable.append(r)
        return vulnerable
