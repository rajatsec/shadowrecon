import requests
from typing import Dict, Any

class HTTPAnalysis:
    def __init__(self, domain: str):
        self.domain = domain
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]

    def run(self) -> Dict[str, Any]:
        """Analyzes HTTP security headers and determines the security posture."""
        results = {
            "found_headers": {},
            "missing_headers": [],
            "server": "unknown",
            "is_secure": False
        }
        
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=10, verify=True)
            headers = response.headers
            
            results["server"] = headers.get("Server", "unknown")
            results["is_secure"] = url.startswith("https")
            
            for header in self.security_headers:
                if header in headers:
                    results["found_headers"][header] = headers[header]
                else:
                    results["missing_headers"].append(header)
        except Exception:
            try:
                # Fallback to HTTP if HTTPS fails
                url = f"http://{self.domain}"
                response = requests.get(url, timeout=10)
                headers = response.headers
                results["server"] = headers.get("Server", "unknown")
                for header in self.security_headers:
                    if header in headers:
                        results["found_headers"][header] = headers[header]
                    else:
                        results["missing_headers"].append(header)
            except Exception:
                pass
                
        return results
