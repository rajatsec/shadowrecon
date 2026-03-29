import dns.resolver
from typing import Dict, List

class DNSEnum:
    def __init__(self, domain: str):
        self.domain = domain
        self.records: Dict[str, List[str]] = {}

    def fetch_records(self, record_type: str) -> List[str]:
        """Fetches DNS records of a specific type (A, MX, NS, TXT, CNAME)."""
        results = []
        try:
            answers = dns.resolver.resolve(self.domain, record_type)
            for rdata in answers:
                results.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            pass
        return results

    def run(self) -> Dict[str, List[str]]:
        """Executes all DNS record lookups."""
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        for rtype in record_types:
            records = self.fetch_records(rtype)
            if records:
                self.records[rtype] = records
        return self.records
