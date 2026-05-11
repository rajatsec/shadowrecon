from typing import Any, Dict


def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise and deduplicate raw scan results into a consistent structure."""
    subdomain_data = raw.get("subdomains", {})
    if isinstance(subdomain_data, dict):
        subdomains = subdomain_data.get("subdomains", [])
        per_provider = subdomain_data.get("per_provider", {})
    else:
        subdomains = list(subdomain_data) if subdomain_data else []
        per_provider = {}

    open_ports = raw.get("ports", {}) or {}
    fingerprints = raw.get("fingerprints", {}) or {}

    # Merge fingerprint info into ports
    merged_ports: Dict[int, Any] = {}
    for port, info in open_ports.items():
        fp = fingerprints.get(port, {})
        merged_ports[port] = {
            "service": fp.get("service") or info.get("service", "unknown"),
            "banner": fp.get("banner") or info.get("banner", ""),
            "tech": fp.get("tech", []),
        }

    return {
        "domain": raw.get("domain", ""),
        "dns": raw.get("dns", {}),
        "subdomains": sorted(set(subdomains)),
        "per_provider": per_provider,
        "http": raw.get("http", {}),
        "open_ports": merged_ports,
        "takeovers": raw.get("takeovers", []),
    }
