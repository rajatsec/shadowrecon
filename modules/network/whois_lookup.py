"""WHOIS lookup — lightweight socket-based WHOIS (no external dependency).

Queries IANA to find the authoritative WHOIS server for the TLD, then queries
that server and parses the common registrar / date fields. Falls back to the
`python-whois` library if it happens to be installed.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry

_WHOIS_PORT = 43
_IANA_WHOIS = "whois.iana.org"

_FIELDS = {
    "registrar": [r"Registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
    "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)"],
    "expiry_date": [r"Registry Expiry Date:\s*(.+)", r"Expiration Date:\s*(.+)", r"paid-till:\s*(.+)"],
    "updated_date": [r"Updated Date:\s*(.+)", r"last-update:\s*(.+)"],
    "registrant_org": [r"Registrant Organization:\s*(.+)", r"org:\s*(.+)"],
    "registrant_country": [r"Registrant Country:\s*(.+)", r"country:\s*(.+)"],
}


async def _whois_query(server: str, query: str, timeout: float = 10) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, _WHOIS_PORT), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return ""
    try:
        writer.write((query + "\r\n").encode())
        await writer.drain()
        chunks = []
        while True:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="ignore")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _parse(raw: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for field, patterns in _FIELDS.items():
        for pat in patterns:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                parsed[field] = m.group(1).strip()
                break
    ns = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
    if not ns:
        ns = re.findall(r"nserver:\s*(.+)", raw, re.IGNORECASE)
    if ns:
        parsed["name_servers"] = sorted({n.strip().lower() for n in ns})
    return parsed


class WhoisModule(BaseModule):
    name = "whois"
    category = Category.NETWORK
    description = "Domain WHOIS: registrar, dates, registrant, name servers"
    target_types = ["domain"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        domain = ctx.target
        tld = domain.rsplit(".", 1)[-1]

        # Step 1: find the TLD's authoritative whois server via IANA
        iana_raw = await _whois_query(_IANA_WHOIS, tld)
        m = re.search(r"whois:\s*(\S+)", iana_raw, re.IGNORECASE)
        whois_server = m.group(1).strip() if m else None

        raw = ""
        if whois_server:
            raw = await _whois_query(whois_server, domain)
            # Some registries refer you to the registrar's own whois server
            ref = re.search(r"Registrar WHOIS Server:\s*(\S+)", raw, re.IGNORECASE)
            if ref:
                deeper = await _whois_query(ref.group(1).strip(), domain)
                if deeper:
                    raw = deeper

        if not raw:
            return {}
        parsed = _parse(raw)
        parsed["whois_server"] = whois_server or ""
        return parsed


registry.register(WhoisModule())
