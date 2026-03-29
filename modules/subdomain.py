import requests
import json
import re
from typing import Set, List
from shadowrecon.config import HACKERTARGET_URL, CRTSH_URL

class SubdomainEnum:
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()

    def clean_domain(self, domain: str) -> str:
        """Removes wildcards and protocols from a domain string."""
        domain = domain.strip().lower()
        domain = re.sub(r'^(\*\.)', '', domain)
        return domain

    def fetch_crtsh(self) -> Set[str]:
        """Fetches subdomains from Certificate Transparency logs via crt.sh."""
        results = set()
        try:
            url = CRTSH_URL.format(domain=self.domain)
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        clean_sub = self.clean_domain(sub)
                        if clean_sub.endswith(self.domain):
                            results.add(clean_sub)
        except Exception:
            pass
        return results

    def fetch_hackertarget(self) -> Set[str]:
        """Fetches subdomains via HackerTarget API."""
        results = set()
        try:
            url = HACKERTARGET_URL.format(domain=self.domain)
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if ',' in line:
                        sub = line.split(',')[0]
                        clean_sub = self.clean_domain(sub)
                        if clean_sub.endswith(self.domain):
                            results.add(clean_sub)
        except Exception:
            pass
        return results

    def run(self) -> List[str]:
        """Executes all enumeration sources and returns a sorted list."""
        self.subdomains.update(self.fetch_crtsh())
        self.subdomains.update(self.fetch_hackertarget())
        return sorted(list(self.subdomains))
