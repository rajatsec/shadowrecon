import logging
import aiohttp
from .base import BaseProvider
from shadowrecon.utils.retry import with_retry

logger = logging.getLogger("ShadowRecon")


class CertspotterProvider(BaseProvider):
    name = "certspotter"
    _URL = (
        "https://api.certspotter.com/v1/issuances"
        "?domain={domain}&include_subdomains=true&expand=dns_names"
    )

    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> set[str]:
        url = self._URL.format(domain=domain)

        async def _get():
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json(content_type=None)
                results = set()
                for entry in data:
                    for name in entry.get("dns_names", []):
                        results.add(name)
                return self.clean(results, domain)

        result = await with_retry(_get, retries=3, label="certspotter")
        return result or set()
