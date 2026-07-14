import asyncio
import logging
from typing import Dict, List

import aiodns

logger = logging.getLogger("ShadowRecon")

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSEnum:
    def __init__(self, domain: str):
        self.domain = domain

    @staticmethod
    def _clean(records: List[str]) -> List[str]:
        # Drop empty values and the bare "." returned for null MX records.
        return [r for r in records if r and r != "."]

    async def _query(self, resolver: aiodns.DNSResolver, rtype: str) -> List[str]:
        try:
            answers = await resolver.query(self.domain, rtype)
            if rtype == "TXT":
                records = [
                    ans.text.decode() if isinstance(ans.text, bytes) else ans.text
                    for ans in answers
                ]
            elif rtype == "SOA":
                # SOA returns a single result object, not an iterable of hosts.
                nsname = getattr(answers, "nsname", "")
                hostmaster = getattr(answers, "hostmaster", "")
                serial = getattr(answers, "serial", "")
                records = [f"{nsname} {hostmaster} serial={serial}".strip()]
            else:
                # A/AAAA/NS/CNAME/MX all expose the value via .host
                records = [str(r.host) for r in answers]
            return self._clean(records)
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
