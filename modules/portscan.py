import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
from shadowrecon.config import DEFAULT_THREADS, DEFAULT_TIMEOUT

class PortScanner:
    def __init__(self, target: str, ports: List[int], threads: int = DEFAULT_THREADS, timeout: float = DEFAULT_TIMEOUT):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.open_ports: Dict[int, str] = {}

    def scan_port(self, port: int) -> tuple:
        """Attempts to connect to a single port and grabs the service banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.target, port)) == 0:
                    banner = ""
                    try:
                        # For common services like SSH, FTP, SMTP
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    except:
                        pass
                    
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    return port, service, banner
        except:
            pass
        return None

    def run(self) -> Dict[int, Dict[str, str]]:
        """Runs the multi-threaded port scan."""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in self.ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, service, banner = result
                    self.open_ports[port] = {"service": service, "banner": banner}
        return dict(sorted(self.open_ports.items()))
