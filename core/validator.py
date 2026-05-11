import re
from typing import List


_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)

_CIDR_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
)


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain cannot be empty.")
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain format: '{domain}'")
    return domain


def validate_ports(ports_str: str | None, default: List[int] | None = None) -> List[int]:
    if not ports_str:
        return default or []

    port_list: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'")
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Port range out of bounds: '{part}'")
            port_list.extend(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of range (1-65535): '{port}'")
            port_list.append(port)

    return sorted(set(port_list))


def validate_threads(value: int) -> int:
    if not (1 <= value <= 1000):
        raise ValueError(f"Threads must be between 1 and 1000, got {value}.")
    return value


def validate_timeout(value: float) -> float:
    if not (0.1 <= value <= 60.0):
        raise ValueError(f"Timeout must be between 0.1 and 60.0 seconds, got {value}.")
    return value
