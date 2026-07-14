"""Shared networking helpers used across modules."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import List, Optional

import aiohttp


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def resolve_ips(host: str) -> List[str]:
    """Resolve a hostname to a list of IPv4/IPv6 addresses (async)."""
    if is_ip(host):
        return [host]
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except (socket.gaierror, OSError):
        return []


async def reverse_dns(ip: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    try:
        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


async def http_get(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float = 10,
    allow_redirects: bool = True,
    headers: Optional[dict] = None,
):
    """Thin wrapper returning (response, text) or (None, '') on failure."""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False,
            allow_redirects=allow_redirects,
            headers=headers or {},
        ) as resp:
            try:
                text = await asyncio.wait_for(resp.text(errors="ignore"), timeout=timeout)
            except Exception:
                text = ""
            # Detach what we need before the context closes
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "url": str(resp.url),
                "history": [str(h.url) for h in resp.history],
                "text": text,
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
        return None
