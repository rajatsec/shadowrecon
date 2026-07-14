"""Active subdomain enumeration — DNS brute-force with a built-in wordlist.

Honours wildcard detection (drops labels that resolve to the wildcard IPs) and
validates each candidate by resolution. Wordlist extensible via config
(`subdomain.wordlist`).
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Set

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import resolve_ips

_DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
    "admin", "administrator", "portal", "dashboard", "api", "api-dev", "apidev",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "beta", "demo", "sandbox", "preprod", "prod", "production",
    "app", "apps", "mobile", "m", "web", "cdn", "static", "assets", "media",
    "img", "images", "js", "css", "files", "download", "downloads", "upload",
    "vpn", "remote", "gateway", "gw", "proxy", "ns1", "ns2", "dns", "dns1", "dns2",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy",
    "jira", "confluence", "wiki", "docs", "help", "support", "status",
    "blog", "news", "shop", "store", "cart", "checkout", "pay", "payment",
    "auth", "login", "sso", "oauth", "account", "accounts", "user", "users",
    "internal", "intranet", "corp", "office", "hr", "finance", "erp", "crm",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics",
    "secure", "vault", "s3", "storage", "backup", "old", "new", "v1", "v2",
    "cloud", "k8s", "kube", "docker", "registry", "nexus", "artifactory",
]


class ActiveSubdomainModule(BaseModule):
    name = "subdomains_active"
    category = Category.SUBDOMAIN
    description = "Active subdomain brute-force (DNS resolution, wildcard-aware)"
    target_types = ["domain"]
    default_enabled = False  # noisier; opt-in via --modules or full+

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        wordlist = ctx.config.get("subdomain", {}).get("wordlist") or _DEFAULT_WORDLIST
        wildcard_ips = set(ctx.flags.get("wildcard_ips", []))

        sem = asyncio.Semaphore(min(ctx.threads, 100))
        found: Dict[str, List[str]] = {}

        async def _check(label: str):
            host = f"{label}.{ctx.target}"
            async with sem:
                ips = await resolve_ips(host)
            if not ips:
                return
            # Skip pure wildcard matches
            if wildcard_ips and set(ips).issubset(wildcard_ips):
                return
            found[host] = ips

        await asyncio.gather(*[_check(w) for w in wordlist], return_exceptions=True)

        subs = sorted(found.keys())
        if subs:
            ctx.subdomains = sorted(set(ctx.subdomains) | set(subs))
        return {"subdomains": subs, "resolved": found} if subs else {}


registry.register(ActiveSubdomainModule())
