import logging
import aiohttp
from .base import BaseProvider
from shadowrecon.utils.retry import with_retry

logger = logging.getLogger("ShadowRecon")


class UrlscanProvider(BaseProvider):
    name = "urlscan"
    _URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"

    def __init__(self, api_key: str = ""):
        self._api_key = api_key

    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> set[str]:
        url = self._URL.format(domain=domain)
        headers = {}
        if self._api_key:
            headers["API-Key"] = self._api_key

        async def _get():
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json(content_type=None)
                results = set()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    hostname = page.get("domain", "")
                    if hostname:
                        results.add(hostname)
                return self.clean(results, domain)

        result = await with_retry(_get, retries=3, label="urlscan")
        return result or set()
