"""Email OSINT — harvest emails from the site, derive likely address patterns,

and report MX / mail security posture (SPF, DMARC).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.modules.dns_enum import DNSEnum
from shadowrecon.utils.netutil import http_get

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class EmailOSINTModule(BaseModule):
    name = "email"
    category = Category.OSINT
    description = "Harvest public emails, address patterns, SPF/DMARC posture"
    target_types = ["domain"]

    async def _spf_dmarc(self, domain: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        txt = await DNSEnum(domain).run()
        spf = [t for t in txt.get("TXT", []) if t.lower().startswith("v=spf1")]
        if spf:
            out["spf"] = spf[0]
        dmarc_txt = await DNSEnum(f"_dmarc.{domain}").run()
        dmarc = [t for t in dmarc_txt.get("TXT", []) if "v=dmarc1" in t.lower()]
        if dmarc:
            out["dmarc"] = dmarc[0]
        if txt.get("MX"):
            out["mx"] = txt["MX"]
        out["spf_present"] = bool(spf)
        out["dmarc_present"] = bool(dmarc)
        return out

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        emails: Set[str] = set()
        for scheme in ("https", "http"):
            for path in ("", "contact", "about", "team"):
                r = await http_get(ctx.session, f"{scheme}://{ctx.target}/{path}", timeout=8)
                if r and r.get("text"):
                    for e in _EMAIL_RE.findall(r["text"]):
                        emails.add(e.lower())
            if emails:
                break

        domain_emails = sorted(e for e in emails if e.endswith("@" + ctx.target) or ctx.target in e.split("@")[-1])
        mail = await self._spf_dmarc(ctx.target)

        out: Dict[str, Any] = {"mail_security": mail}
        if emails:
            out["emails"] = sorted(emails)[:100]
        if domain_emails:
            out["domain_emails"] = domain_emails
        # Common professional patterns to try (documented, not actively verified)
        out["patterns"] = [f"{{first}}@{ctx.target}", f"{{first}}.{{last}}@{ctx.target}",
                           f"{{f}}{{last}}@{ctx.target}", f"info@{ctx.target}"]
        return out


registry.register(EmailOSINTModule())
