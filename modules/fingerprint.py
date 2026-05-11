import asyncio
import logging
import re
from typing import Any, Dict

import aiohttp

logger = logging.getLogger("ShadowRecon")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_TECH_SIGNATURES: Dict[str, list[str]] = {
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["microsoft-iis"],
    "cloudflare": ["cloudflare"],
    "openssl": ["openssl"],
    "php": ["php", "x-powered-by: php"],
    "wordpress": ["wp-content", "wp-json"],
    "django": ["csrfmiddlewaretoken", "x-frame-options: sameorigin"],
    "flask": ["werkzeug"],
    "express": ["x-powered-by: express"],
    "tomcat": ["apache-coyote", "apache tomcat"],
    "laravel": ["laravel_session"],
}


def _detect_tech(server: str, powered_by: str, body: str, headers_raw: str) -> list[str]:
    detected = []
    combined = (server + " " + powered_by + " " + headers_raw + " " + body[:4096]).lower()
    for tech, sigs in _TECH_SIGNATURES.items():
        if any(sig in combined for sig in sigs):
            detected.append(tech)
    return detected


class ServiceFingerprint:
    def __init__(self, target: str, open_ports: Dict[int, Dict[str, str]]):
        self.target = target
        self.open_ports = open_ports

    async def _http_banner(
        self, session: aiohttp.ClientSession, port: int, use_ssl: bool
    ) -> Dict[str, Any]:
        proto = "https" if use_ssl else "http"
        url = f"{proto}://{self.target}:{port}/"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=5), ssl=False, allow_redirects=True
            ) as resp:
                server = resp.headers.get("Server", "")
                powered_by = resp.headers.get("X-Powered-By", "")
                body = ""
                try:
                    body = await asyncio.wait_for(resp.text(errors="ignore"), timeout=3)
                except (asyncio.TimeoutError, Exception):
                    pass
                title = ""
                m = _TITLE_RE.search(body)
                if m:
                    title = m.group(1).strip()
                headers_raw = str(dict(resp.headers))
                tech = _detect_tech(server, powered_by, body, headers_raw)
                banner = server
                if title:
                    banner += f" (Title: {title})"
                return {"banner": banner, "tech": tech, "title": title}
        except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
            logger.debug(f"HTTP fingerprint failed {url}: {e}")
            return {"banner": "", "tech": [], "title": ""}

    async def _tcp_banner(self, port: int) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port), timeout=3
            )
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data.decode("utf-8", errors="ignore").strip()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return ""

    async def run(self, session: aiohttp.ClientSession | None = None) -> Dict[int, Any]:
        fingerprints: Dict[int, Any] = {}

        for port, info in self.open_ports.items():
            service = info.get("service", "unknown")
            banner = info.get("banner", "")
            tech: list[str] = []

            if not banner:
                if port == 443 or service == "https":
                    result = await self._http_banner(session, port, True) if session else {"banner": "", "tech": [], "title": ""}
                    banner = result["banner"]
                    tech = result["tech"]
                elif port == 80 or service == "http":
                    result = await self._http_banner(session, port, False) if session else {"banner": "", "tech": [], "title": ""}
                    banner = result["banner"]
                    tech = result["tech"]
                else:
                    banner = await self._tcp_banner(port)

            fingerprints[port] = {"service": service, "banner": banner, "tech": tech}

        return fingerprints
