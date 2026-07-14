"""ShadowRecon scan engine (v2, registry-driven).

Runs modules grouped by category/phase, sharing one ModuleContext so later
modules build on earlier findings. Any module can fail without killing the scan.
The legacy `ScanEngine` API is preserved (see bottom) for backward compatibility.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import aiohttp

from shadowrecon.core.base_module import (
    BaseModule, Category, ModuleContext, ModuleResult, ModuleStatus,
)
from shadowrecon.core.registry import registry, load_all_modules

# Legacy imports kept so the old ScanEngine keeps working
from shadowrecon.modules.dns_enum import DNSEnum
from shadowrecon.modules.subdomain_enum import SubdomainEnum
from shadowrecon.modules.http_probe import HTTPProbe
from shadowrecon.modules.portscan import PortScanner
from shadowrecon.modules.fingerprint import ServiceFingerprint
from shadowrecon.modules.takeover import TakeoverDetector
from shadowrecon.core import pipeline

logger = logging.getLogger("ShadowRecon")

# Order in which categories/phases execute. Earlier phases feed later ones.
PHASE_ORDER = [
    Category.NETWORK,
    Category.SUBDOMAIN,
    Category.WEB,
    Category.CLOUD,
    Category.INTEL,
    Category.OSINT,
    Category.MEDIA,
    Category.ANALYSIS,   # always last — consumes everything above
]


class RegistryEngine:
    """The modern, module-registry-driven engine."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        load_all_modules()

    def _select(self, target_type: str, only, exclude) -> List[BaseModule]:
        mods = registry.select(target_type, only=only, exclude=exclude)
        # Order within selection by phase
        phase_index = {c: i for i, c in enumerate(PHASE_ORDER)}
        mods.sort(key=lambda m: phase_index.get(m.category, 99))
        return mods

    async def run(
        self,
        target: str,
        target_type: str = "domain",
        ports: Optional[List[int]] = None,
        threads: int = 100,
        timeout: float = 1.0,
        only: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        flags: Optional[Dict[str, Any]] = None,
        progress_cb=None,
    ) -> Dict[str, Any]:
        modules = self._select(target_type, only, exclude)

        connector = aiohttp.TCPConnector(ssl=False, limit=200)
        async with aiohttp.ClientSession(connector=connector) as session:
            ctx = ModuleContext(
                target=target,
                target_type=target_type,
                config=self.config,
                session=session,
                ports=ports or [],
                threads=threads,
                timeout=timeout,
                flags=flags or {},
            )
            module_results: Dict[str, ModuleResult] = {}

            # Run phase by phase; within a phase, run modules concurrently.
            phase_index = {c: i for i, c in enumerate(PHASE_ORDER)}
            grouped: Dict[int, List[BaseModule]] = {}
            for m in modules:
                grouped.setdefault(phase_index.get(m.category, 99), []).append(m)

            for idx in sorted(grouped):
                phase_mods = grouped[idx]

                async def _run_one(mod: BaseModule):
                    if progress_cb:
                        progress_cb("start", mod)
                    res = await mod.execute(ctx)
                    module_results[mod.name] = res
                    if progress_cb:
                        progress_cb("done", mod, res)
                    return res

                await asyncio.gather(*[_run_one(m) for m in phase_mods],
                                     return_exceptions=True)

        return self._assemble(ctx, module_results)

    def _assemble(self, ctx: ModuleContext, results: Dict[str, ModuleResult]) -> Dict[str, Any]:
        """Build the final normalized report dict."""
        modules_out = {name: r.to_dict() for name, r in results.items()}
        # Convenience flattened view for reporting/back-compat
        flat: Dict[str, Any] = {"domain": ctx.target, "target_type": ctx.target_type}

        # Merge subdomains across sources
        subs = set(ctx.subdomains)
        per_provider = ctx.results.get("subdomains_passive", {}).get("per_provider", {})
        flat["subdomains"] = sorted(subs)
        flat["per_provider"] = per_provider

        # DNS
        flat["dns"] = ctx.results.get("dns", {}).get("records", {})
        flat["resolved_ips"] = ctx.resolved_ips

        # HTTP / ports
        flat["http"] = ctx.results.get("http", {})
        op = ctx.results.get("ports", {}).get("open_ports", {})
        flat["open_ports"] = {int(k) if str(k).isdigit() else k: v for k, v in op.items()}

        # Takeovers
        flat["takeovers"] = ctx.results.get("takeover", {}).get("takeovers", [])

        # Risk + AI
        flat["risk"] = ctx.results.get("risk", {})
        flat["ai_summary"] = ctx.results.get("ai_summary", {})

        return {
            "target": ctx.target,
            "target_type": ctx.target_type,
            "modules": modules_out,
            "findings": {k: v for k, v in ctx.results.items() if not k.startswith("_")},
            "report": flat,
        }


class ScanEngine:
    """Legacy engine — original v1.1 behaviour, kept for backward compatibility."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    async def run(
        self,
        target: str,
        ports: List[int],
        threads: int = 100,
        timeout: float = 1.0,
        enable_takeover: bool = False,
        providers: List[str] | None = None,
    ) -> Dict[str, Any]:
        scan_cfg = self.config.get("scan", {})
        threads = threads or scan_cfg.get("threads", 100)
        timeout = timeout or scan_cfg.get("timeout", 1.0)

        connector = aiohttp.TCPConnector(ssl=False, limit=200)
        async with aiohttp.ClientSession(connector=connector) as session:
            logger.info(f"Phase 1: passive recon for {target}")
            dns_task = asyncio.create_task(DNSEnum(target).run())
            sub_task = asyncio.create_task(SubdomainEnum(target, self.config, providers).run(session))
            http_task = asyncio.create_task(HTTPProbe(target).run(session))
            dns_results, sub_results, http_results = await asyncio.gather(
                dns_task, sub_task, http_task
            )

            logger.info(f"Phase 2: port scan ({len(ports)} ports) for {target}")
            port_results = await PortScanner(target, ports, threads, timeout).run()

            logger.info(f"Phase 3: fingerprinting {len(port_results)} open ports")
            fp_results = await ServiceFingerprint(target, port_results).run(session)

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
