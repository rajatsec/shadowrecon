from abc import ABC, abstractmethod
import re
import aiohttp


_WILDCARD_RE = re.compile(r'^\*\.')


class BaseProvider(ABC):
    name: str = ""
    requires_api_key: bool = False

    @abstractmethod
    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> set[str]:
        pass

    def clean(self, subdomains: set[str], domain: str) -> set[str]:
        cleaned = set()
        for s in subdomains:
            s = _WILDCARD_RE.sub("", s.strip().lower())
            if s and s.endswith(domain) and s != domain:
                cleaned.add(s)
        return cleaned
