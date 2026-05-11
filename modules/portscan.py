import asyncio
import logging
import socket
from typing import Dict, List, Optional, Tuple

from shadowrecon.config import DEFAULT_THREADS, DEFAULT_TIMEOUT

logger = logging.getLogger("ShadowRecon")


class PortScanner:
    def __init__(
        self,
        target: str,
        ports: List[int],
        threads: int = DEFAULT_THREADS,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout

    async def _scan_port(
        self, sem: asyncio.Semaphore, port: int
    ) -> Optional[Tuple[int, str, str]]:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port),
                    timeout=self.timeout,
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                logger.debug(f"Port {port} error: {e}")
                return None

            banner = ""
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                banner = banner_bytes.decode("utf-8", errors="ignore").strip()
            except (asyncio.TimeoutError, Exception):
                pass

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"

            return port, service, banner

    async def run(self) -> Dict[int, Dict[str, str]]:
        sem = asyncio.Semaphore(self.threads)
        tasks = [self._scan_port(sem, port) for port in self.ports]
        results = await asyncio.gather(*tasks)

        open_ports: Dict[int, Dict[str, str]] = {}
        for result in results:
            if result is not None:
                port, service, banner = result
                open_ports[port] = {"service": service, "banner": banner}

        return dict(sorted(open_ports.items()))
