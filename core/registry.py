"""Module registry — the single source of truth for every recon module.

Modules register themselves here so the engine and CLI can enumerate them,
group them by category, filter by target type, and select subsets. This is what
makes ShadowRecon an extensible platform: adding a capability = adding one
module class and one line here.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Type

from shadowrecon.core.base_module import BaseModule, Category

logger = logging.getLogger("ShadowRecon")


class ModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, BaseModule] = {}

    def register(self, module: BaseModule) -> BaseModule:
        if module.name in self._modules:
            logger.debug(f"module '{module.name}' already registered — overwriting")
        self._modules[module.name] = module
        return module

    def get(self, name: str) -> Optional[BaseModule]:
        return self._modules.get(name)

    def all(self) -> List[BaseModule]:
        return list(self._modules.values())

    def names(self) -> List[str]:
        return sorted(self._modules.keys())

    def by_category(self, category: Category) -> List[BaseModule]:
        return [m for m in self._modules.values() if m.category == category]

    def for_target(self, target_type: str) -> List[BaseModule]:
        return [m for m in self._modules.values() if m.applies_to(target_type)]

    def select(
        self,
        target_type: str,
        only: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[BaseModule]:
        """Pick the modules to run for a scan."""
        mods = self.for_target(target_type)
        if only:
            only_set = {o.strip().lower() for o in only}
            mods = [m for m in mods if m.name in only_set]
        else:
            mods = [m for m in mods if m.default_enabled]
        if exclude:
            ex_set = {e.strip().lower() for e in exclude}
            mods = [m for m in mods if m.name not in ex_set]
        return mods

    def summary(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for m in self._modules.values():
            out.setdefault(m.category.value, []).append(m.name)
        for k in out:
            out[k] = sorted(out[k])
        return out


# Global registry instance
registry = ModuleRegistry()


def load_all_modules() -> ModuleRegistry:
    """Import every module package so their register() calls run.

    Imports are best-effort: a module file that fails to import (e.g. a syntax
    issue in an optional feature) must not take down the whole platform.
    """
    module_paths = [
        # Network
        "shadowrecon.modules.network.whois_lookup",
        "shadowrecon.modules.network.dns_records",
        "shadowrecon.modules.network.reverse_dns",
        "shadowrecon.modules.network.asn_lookup",
        "shadowrecon.modules.network.ip_intel",
        "shadowrecon.modules.network.port_service",
        # Subdomain
        "shadowrecon.modules.subdomain.passive",
        "shadowrecon.modules.subdomain.active",
        "shadowrecon.modules.subdomain.wildcard",
        # Web
        "shadowrecon.modules.web.http_analyzer",
        "shadowrecon.modules.web.ssl_analyzer",
        "shadowrecon.modules.web.waf_detect",
        "shadowrecon.modules.web.tech_detect",
        "shadowrecon.modules.web.robots_sitemap",
        "shadowrecon.modules.web.dir_discovery",
        "shadowrecon.modules.web.js_analyzer",
        "shadowrecon.modules.web.favicon",
        "shadowrecon.modules.web.takeover_mod",
        # Cloud
        "shadowrecon.modules.cloud.cloud_assets",
        # OSINT
        "shadowrecon.modules.osint.email_osint",
        "shadowrecon.modules.osint.username_osint",
        "shadowrecon.modules.osint.phone_osint",
        "shadowrecon.modules.osint.image_osint",
        "shadowrecon.modules.osint.document_osint",
        # Intel / integrations
        "shadowrecon.modules.intel.shodan_intel",
        "shadowrecon.modules.intel.virustotal_intel",
        "shadowrecon.modules.intel.securitytrails_intel",
        # Analysis
        "shadowrecon.modules.analysis.risk_score",
        "shadowrecon.modules.analysis.ai_summary",
    ]
    import importlib
    for path in module_paths:
        try:
            importlib.import_module(path)
        except Exception as e:  # keep the platform alive even if one file breaks
            logger.warning(f"could not load module '{path}': {e}")
    return registry
