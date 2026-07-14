import asyncio
import logging
from typing import Dict, List

import aiohttp

from shadowrecon.providers import (
    CrtshProvider,
    HackertargetProvider,
    CertspotterProvider,
    AlienvaultProvider,
    UrlscanProvider,
)
from shadowrecon.providers.base import BaseProvider

logger = logging.getLogger("ShadowRecon")


class SubdomainEnum:
    def __init__(
        self,
        domain: str,
        config: dict | None = None,
        selected: List[str] | None = None,
    ):
        self.domain = domain
        cfg = config or {}
        providers_cfg = cfg.get("providers", {})

        # Optional user-supplied filter (e.g. --providers crtsh,urlscan).
        selected_set = {s.strip().lower() for s in selected} if selected else None

        self._providers: List[BaseProvider] = []
        provider_map = {
            "crtsh": CrtshProvider(),
            "hackertarget": HackertargetProvider(),
            "certspotter": CertspotterProvider(),
            "alienvault": AlienvaultProvider(
                api_key=providers_cfg.get("alienvault", {}).get("api_key", "")
            ),
            "urlscan": UrlscanProvider(
                api_key=providers_cfg.get("urlscan", {}).get("api_key", "")
            ),
        }

        for name, provider in provider_map.items():
            if selected_set is not None:
                if name not in selected_set:
                    continue
            else:
                enabled = providers_cfg.get(name, {}).get("enabled", True)
                if not enabled:
                    continue
            self._providers.append(provider)

    @staticmethod
    def available_providers() -> List[str]:
        return ["crtsh", "hackertarget", "certspotter", "alienvault", "urlscan"]

    async def run(
        self, session: aiohttp.ClientSession
    ) -> Dict[str, object]:
        tasks = {
            p.name: p.fetch(self.domain, session) for p in self._providers
        }
        raw_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        per_provider: Dict[str, List[str]] = {}
        all_subs: set[str] = set()

        for name, result in zip(tasks.keys(), raw_results):
            if isinstance(result, Exception):
                logger.warning(f"Provider {name} raised: {result}")
                per_provider[name] = []
            else:
                subs = sorted(result)
                per_provider[name] = subs
                all_subs.update(result)

        return {
            "subdomains": sorted(all_subs),
            "per_provider": per_provider,
        }
