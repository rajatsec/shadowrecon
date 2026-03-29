import socket
import ssl
import requests
from typing import Dict, Any

class ServiceFingerprint:
    def __init__(self, target: str, open_ports: Dict[int, Dict[str, str]]):
        self.target = target
        self.open_ports = open_ports
        self.fingerprints: Dict[int, Any] = {}

    def grab_http_banner(self, port: int, use_ssl: bool = False) -> str:
        """Sends a GET / HTTP/1.1 request and grabs the Server header."""
        protocol = "https" if use_ssl else "http"
        try:
            url = f"{protocol}://{self.target}:{port}/"
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            server = response.headers.get("Server", "unknown")
            title = ""
            if "<title>" in response.text:
                title = response.text.split("<title>")[1].split("</title>")[0].strip()
            return f"{server} (Title: {title})" if title else server
        except:
            return ""

    def grab_tcp_banner(self, port: int) -> str:
        """Standard TCP banner grab by sending a generic payload."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((self.target, port))
                # Some services wait for a generic request
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except:
            return ""

    def run(self) -> Dict[int, Any]:
        """Runs the service fingerprinting on identified open ports."""
        for port, info in self.open_ports.items():
            service = info.get("service", "unknown")
            banner = info.get("banner", "")

            # If banner is empty, try a second pass
            if not banner:
                if port == 80:
                    banner = self.grab_http_banner(port, False)
                elif port == 443:
                    banner = self.grab_http_banner(port, True)
                elif service in ["ssh", "ftp", "smtp"]:
                    banner = self.grab_tcp_banner(port)
                else:
                    # Generic try
                    banner = self.grab_tcp_banner(port)
            
            self.fingerprints[port] = {
                "service": service,
                "banner": banner
            }
        return self.fingerprints
