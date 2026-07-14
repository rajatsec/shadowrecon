"""Core module framework for ShadowRecon's enterprise engine.

Every recon capability is a `BaseModule`. Modules declare a name, a category,
optional Python dependencies and whether they need network / an API key. The
engine runs them (grouped by category / phase), shares a single `ModuleContext`
so later modules can reuse earlier findings, and never lets one module crash the
whole scan.
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ShadowRecon")


class Category(str, Enum):
    """High-level phases / groupings for modules."""
    NETWORK = "network"
    SUBDOMAIN = "subdomain"
    WEB = "web"
    CLOUD = "cloud"
    OSINT = "osint"
    INTEL = "intel"          # external API integrations (Shodan, VT, ...)
    MEDIA = "media"          # image / document OSINT
    ANALYSIS = "analysis"    # AI summary, risk scoring


class ModuleStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"      # optional dep / key missing, or not applicable
    ERROR = "error"
    EMPTY = "empty"          # ran fine but found nothing


@dataclass
class ModuleResult:
    name: str
    category: str
    status: ModuleStatus = ModuleStatus.OK
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "message": self.message,
            "duration": round(self.duration, 2),
            "data": self.data,
        }


@dataclass
class ModuleContext:
    """Shared state passed to every module during a scan."""
    target: str                       # primary target (domain / ip / phone / file)
    target_type: str = "domain"       # domain | ip | phone | image | document | username | email
    config: Dict[str, Any] = field(default_factory=dict)
    session: Any = None               # aiohttp.ClientSession (may be None)
    # Scan tuning
    ports: List[int] = field(default_factory=list)
    threads: int = 100
    timeout: float = 1.0
    # Cross-module shared findings (namespaced by module name)
    results: Dict[str, Any] = field(default_factory=dict)
    # Convenience shared fields populated as the scan progresses
    resolved_ips: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    flags: Dict[str, Any] = field(default_factory=dict)

    def get(self, module_name: str, default=None):
        return self.results.get(module_name, default)


class BaseModule(ABC):
    """Base class every recon module inherits from."""

    name: str = "base"
    category: Category = Category.NETWORK
    description: str = ""
    # Optional python packages this module needs (checked before running)
    requires: List[str] = []
    # Does this module need an outbound network / a configured API key?
    needs_network: bool = True
    needs_api_key: bool = False
    # Applicable target types; empty means "any"
    target_types: List[str] = []
    # Enabled by default in a full scan?
    default_enabled: bool = True

    def applies_to(self, target_type: str) -> bool:
        return not self.target_types or target_type in self.target_types

    def missing_deps(self) -> List[str]:
        missing = []
        for mod in self.requires:
            try:
                importlib.import_module(mod)
            except Exception:
                missing.append(mod)
        return missing

    @abstractmethod
    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        """Perform the module's work and return a plain dict of findings."""
        raise NotImplementedError

    async def execute(self, ctx: ModuleContext) -> ModuleResult:
        """Wrapper the engine calls: handles deps, timing, errors uniformly."""
        start = time.time()
        result = ModuleResult(name=self.name, category=self.category.value)

        if not self.applies_to(ctx.target_type):
            result.status = ModuleStatus.SKIPPED
            result.message = f"not applicable to target type '{ctx.target_type}'"
            return result

        missing = self.missing_deps()
        if missing:
            result.status = ModuleStatus.SKIPPED
            result.message = f"optional dependency missing: {', '.join(missing)}"
            logger.warning(f"[{self.name}] skipped — install: pip install {' '.join(missing)}")
            return result

        try:
            data = await self.run(ctx)
            result.data = data or {}
            if not result.data:
                result.status = ModuleStatus.EMPTY
            # Publish into shared context so later modules can build on it
            ctx.results[self.name] = result.data
        except asyncio.CancelledError:
            raise
        except Exception as e:  # never let one module kill the scan
            result.status = ModuleStatus.ERROR
            result.message = str(e)
            logger.warning(f"[{self.name}] error: {e}")
        finally:
            result.duration = time.time() - start
        return result
