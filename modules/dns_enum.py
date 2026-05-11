import asyncio
import logging
from typing import Dict, List

import aiodns
import dns.resolver

logger = logging.getLogger("ShadowRecon")

_RECORD_TYPES = ["A", "MX", "NS", "TXT", "CNAME"]


class DNSEnum:
    def __init__(self, domain: str):
        self.domain = domain

    async def _query(self, resolver: aiodns.DNSResolver, rtype: str) -> List[str]:
        try:
            answers = await resolver.query(self.domain, rtype)
            if rtype == "MX":
                return [str(r.host) for r in answers]
            elif rtype in ("NS", "CNAME"):
                return [str(r.host) for r in answers]
            elif rtype == "TXT":
                return [" ".join(r.text.decode() if isinstance(r.text, bytes) else r.text
                                 for r in [ans]) for ans in answers]
            else:
                return [str(r.host) for r in answers]
        except aiodns.error.DNSError:
            return []
        except Exception as e:
            logger.warning(f"DNS {rtype} query failed for {self.domain}: {e}")
            return []

    async def run(self) -> Dict[str, List[str]]:
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        tasks = {rtype: self._query(resolver, rtype) for rtype in _RECORD_TYPES}
        results: Dict[str, List[str]] = {}
        for rtype, coro in tasks.items():
            records = await coro
            if records:
                results[rtype] = records
        return results
