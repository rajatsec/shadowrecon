import asyncio
import logging
from typing import Any, Dict, List

import aiohttp

from shadowrecon.modules.dns_enum import DNSEnum
from shadowrecon.modules.subdomain import SubdomainEnum
from shadowrecon.modules.http_probe import HTTPProbe
from shadowrecon.modules.portscan import PortScanner
from shadowrecon.modules.fingerprint import ServiceFingerprint
from shadowrecon.modules.takeover import TakeoverDetector
from shadowrecon.core import pipeline

logger = logging.getLogger("ShadowRecon")


class ScanEngine:
    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    async def run(
        self,
        target: str,
        ports: List[int],
        threads: int = 100,
        timeout: float = 1.0,
        enable_takeover: bool = False,
    ) -> Dict[str, Any]:

        scan_cfg = self.config.get("scan", {})
        threads = threads or scan_cfg.get("threads", 100)
        timeout = timeout or scan_cfg.get("timeout", 1.0)

        connector = aiohttp.TCPConnector(ssl=False, limit=200)
        async with aiohttp.ClientSession(connector=connector) as session:

            # Phase 1 — parallel passive recon
            logger.info(f"Phase 1: passive recon for {target}")
            dns_task = asyncio.create_task(DNSEnum(target).run())
            sub_task = asyncio.create_task(SubdomainEnum(target, self.config).run(session))
            http_task = asyncio.create_task(HTTPProbe(target).run(session))

            dns_results, sub_results, http_results = await asyncio.gather(
                dns_task, sub_task, http_task
            )

            # Phase 2 — active port scanning
            logger.info(f"Phase 2: port scan ({len(ports)} ports) for {target}")
            port_results = await PortScanner(target, ports, threads, timeout).run()

            # Phase 3 — service fingerprinting
            logger.info(f"Phase 3: fingerprinting {len(port_results)} open ports")
            fp_results = await ServiceFingerprint(target, port_results).run(session)

            # Phase 4 — optional takeover detection
            takeovers: list = []
            if enable_takeover:
                subdomains = sub_results.get("subdomains", []) if isinstance(sub_results, dict) else []
                if subdomains:
                    logger.info(f"Phase 4: takeover check on {len(subdomains)} subdomains")
                    takeovers = await TakeoverDetector(target).run(subdomains, session)

        return pipeline.normalize({
            "domain": target,
            "dns": dns_results,
            "subdomains": sub_results,
            "http": http_results,
            "ports": port_results,
            "fingerprints": fp_results,
            "takeovers": takeovers,
        })
