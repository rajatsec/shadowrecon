"""Port scanning + service fingerprinting + optional OS fingerprint (nmap)."""
from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.modules.portscan import PortScanner
from shadowrecon.modules.fingerprint import ServiceFingerprint


async def _os_fingerprint(target: str) -> Dict[str, Any]:
    """Best-effort OS detection via nmap if it's installed (needs privileges)."""
    if not shutil.which("nmap"):
        return {}
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-O", "--osscan-guess", "-Pn", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
    except Exception:
        return {}
    text = out.decode(errors="ignore")
    guesses = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Running:") or line.startswith("OS details:") or line.startswith("Aggressive OS guesses:"):
            guesses.append(line)
    return {"nmap_os": guesses} if guesses else {}


class PortServiceModule(BaseModule):
    name = "ports"
    category = Category.NETWORK
    description = "Open ports, service detection, banners, tech + optional OS fingerprint"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        ports = ctx.ports
        scanner = PortScanner(ctx.target, ports, ctx.threads, ctx.timeout)
        open_ports = await scanner.run()

        fp = ServiceFingerprint(ctx.target, open_ports)
        fingerprints = await fp.run(ctx.session)

        merged: Dict[int, Any] = {}
        for port, info in open_ports.items():
            f = fingerprints.get(port, {})
            merged[port] = {
                "service": f.get("service") or info.get("service", "unknown"),
                "banner": f.get("banner") or info.get("banner", ""),
                "tech": f.get("tech", []),
            }

        result: Dict[str, Any] = {"open_ports": {str(k): v for k, v in merged.items()}}

        # OS fingerprint only if explicitly requested (slow / needs privileges)
        if ctx.flags.get("os_fingerprint"):
            os_info = await _os_fingerprint(ctx.target)
            if os_info:
                result.update(os_info)
        return result


registry.register(PortServiceModule())
