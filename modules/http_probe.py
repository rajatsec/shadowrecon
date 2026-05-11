import asyncio
import logging
import re
from typing import Any, Dict

import aiohttp

logger = logging.getLogger("ShadowRecon")

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_cookie_issues(headers: dict) -> list[str]:
    issues = []
    raw = headers.get("Set-Cookie", "")
    if raw:
        if "Secure" not in raw:
            issues.append("Cookie missing Secure flag")
        if "HttpOnly" not in raw:
            issues.append("Cookie missing HttpOnly flag")
        if "SameSite" not in raw:
            issues.append("Cookie missing SameSite flag")
    return issues


class HTTPProbe:
    def __init__(self, domain: str):
        self.domain = domain

    async def _probe(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                headers = dict(resp.headers)
                body = ""
                try:
                    body = await asyncio.wait_for(resp.text(errors="ignore"), timeout=5)
                except (asyncio.TimeoutError, Exception):
                    pass

                title = ""
                m = _TITLE_RE.search(body)
                if m:
                    title = m.group(1).strip()

                found: Dict[str, str] = {}
                missing: list[str] = []
                for h in SECURITY_HEADERS:
                    val = headers.get(h) or headers.get(h.lower())
                    if val:
                        found[h] = val
                    else:
                        missing.append(h)

                return {
                    "url": str(resp.url),
                    "status_code": resp.status,
                    "server": headers.get("Server") or headers.get("server", "unknown"),
                    "powered_by": headers.get("X-Powered-By", ""),
                    "title": title,
                    "is_https": url.startswith("https"),
                    "found_headers": found,
                    "missing_headers": missing,
                    "cookie_issues": _extract_cookie_issues(headers),
                }
        except aiohttp.ClientConnectorError:
            return {}
        except asyncio.TimeoutError:
            return {}
        except Exception as e:
            logger.debug(f"HTTP probe failed for {url}: {e}")
            return {}

    async def run(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        result = await self._probe(session, f"https://{self.domain}")
        if not result:
            result = await self._probe(session, f"http://{self.domain}")
        return result or {
            "url": f"http://{self.domain}",
            "status_code": 0,
            "server": "unknown",
            "powered_by": "",
            "title": "",
            "is_https": False,
            "found_headers": {},
            "missing_headers": SECURITY_HEADERS[:],
            "cookie_issues": [],
        }
