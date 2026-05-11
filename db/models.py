from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ScanRecord:
    target: str
    timestamp: int
    dns: Dict[str, List[str]] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    per_provider: Dict[str, List[str]] = field(default_factory=dict)
    http: Dict[str, Any] = field(default_factory=dict)
    open_ports: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    takeovers: List[Dict[str, Any]] = field(default_factory=list)
    scan_id: int = 0
