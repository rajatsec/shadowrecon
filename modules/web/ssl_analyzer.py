"""SSL/TLS analyzer — certificate details, issuer, expiry, TLS version support.

Uses the stdlib `ssl` module (no external dependency). Runs the blocking socket
work in a thread executor.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry

_TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def _fetch_cert(host: str, port: int = 443, timeout: float = 8) -> Dict[str, Any]:
    # getpeercert() only returns a populated dict when the cert is validated,
    # so try a trusting-but-verifying context first, then fall back to CERT_NONE
    # (still records protocol/cipher, marks the cert untrusted).
    trusted = True
    cert = {}
    cipher = None
    proto = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # we scan by IP/vhost, hostname mismatch is fine
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
    except ssl.SSLCertVerificationError:
        trusted = False
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()  # may be {} without validation
                    cipher = ssock.cipher()
                    proto = ssock.version()
        except Exception as e:
            return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

    def _name(seq):
        return {k: v for item in (seq or []) for (k, v) in item}

    subject = _name(cert.get("subject"))
    issuer = _name(cert.get("issuer"))
    not_after = cert.get("notAfter", "")
    days_left = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        except Exception:
            pass
    sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    return {
        "subject_cn": subject.get("commonName", ""),
        "issuer_cn": issuer.get("commonName", ""),
        "issuer_org": issuer.get("organizationName", ""),
        "not_before": cert.get("notBefore", ""),
        "not_after": not_after,
        "days_until_expiry": days_left,
        "serial": cert.get("serialNumber", ""),
        "sans": sorted(set(sans)),
        "negotiated_protocol": proto,
        "cipher": cipher[0] if cipher else "",
        "trusted": trusted,
    }


def _probe_tls_versions(host: str, port: int = 443, timeout: float = 5) -> Dict[str, bool]:
    supported: Dict[str, bool] = {}
    for label, ver in _TLS_VERSIONS.items():
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        try:
            c.minimum_version = ver
            c.maximum_version = ver
        except ValueError:
            supported[label] = False
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with c.wrap_socket(sock, server_hostname=host):
                    supported[label] = True
        except Exception:
            supported[label] = False
    return supported


class SSLAnalyzerModule(BaseModule):
    name = "ssl"
    category = Category.WEB
    description = "TLS certificate details, issuer, expiry, SAN list, TLS version support"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        cert = await loop.run_in_executor(None, _fetch_cert, ctx.target)
        if cert.get("error"):
            return {}
        versions = await loop.run_in_executor(None, _probe_tls_versions, ctx.target)
        cert["tls_versions"] = versions
        weak = [v for v in ("TLSv1", "TLSv1.1") if versions.get(v)]
        if weak:
            cert["weak_protocols"] = weak
        return cert


registry.register(SSLAnalyzerModule())
