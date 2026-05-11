import logging
import aiohttp
from .base import BaseProvider
from shadowrecon.utils.retry import with_retry

logger = logging.getLogger("ShadowRecon")


class HackertargetProvider(BaseProvider):
    name = "hackertarget"
    _URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> set[str]:
        url = self._URL.format(domain=domain)

        async def _get():
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return set()
                text = await resp.text()
                results = set()
                for line in text.splitlines():
                    if "," in line:
                        results.add(line.split(",")[0])
                return self.clean(results, domain)

        result = await with_retry(_get, retries=3, label="hackertarget")
        return result or set()
