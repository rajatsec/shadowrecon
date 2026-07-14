"""Technology / CMS / framework / analytics detection from HTML + headers."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get

# category -> {tech: [signatures]}  (signatures matched against html+headers, lowercased)
_TECH = {
    "cms": {
        "WordPress": ["wp-content", "wp-includes", "/wp-json"],
        "Joomla": ["/media/jui/", "joomla", "com_content"],
        "Drupal": ["drupal-settings-json", "/sites/default/files", "x-drupal-cache"],
        "Ghost": ["ghost-", "content=\"ghost"],
        "Shopify": ["cdn.shopify.com", "x-shopify-stage", "shopify"],
        "Wix": ["wix.com", "x-wix-request-id"],
        "Squarespace": ["squarespace", "static1.squarespace.com"],
        "Magento": ["magento", "x-magento", "/skin/frontend/", "mage-cache"],
    },
    "framework": {
        "React": ["react", "_next/static", "data-reactroot"],
        "Next.js": ["_next/static", "__next_data__", "x-nextjs"],
        "Vue.js": ["vue.js", "data-v-", "__vue__"],
        "Angular": ["ng-version", "angular", "ng-app"],
        "Laravel": ["laravel_session", "xsrf-token"],
        "Django": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "Ruby on Rails": ["x-runtime", "rails", "csrf-param"],
        "Express": ["x-powered-by: express"],
        "ASP.NET": ["asp.net", "__viewstate", "x-aspnet-version"],
    },
    "analytics": {
        "Google Analytics": ["google-analytics.com", "gtag(", "ga('create"],
        "Google Tag Manager": ["googletagmanager.com"],
        "Facebook Pixel": ["connect.facebook.net", "fbq("],
        "Hotjar": ["static.hotjar.com", "hotjar"],
    },
    "js_library": {
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Tailwind": ["tailwindcss", "tailwind"],
        "Font Awesome": ["fontawesome", "font-awesome"],
    },
}

_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def _matches(sig: str, text: str) -> bool:
    """Substring match that won't fire inside a larger word.

    e.g. 'mage/' must not match 'image/'. We reject a hit when the character
    immediately before the signature is alphanumeric.
    """
    start = 0
    while True:
        i = text.find(sig, start)
        if i == -1:
            return False
        before = text[i - 1] if i > 0 else " "
        if not before.isalnum():
            return True
        start = i + 1


class TechDetectModule(BaseModule):
    name = "tech"
    category = Category.WEB
    description = "CMS, framework, analytics and JS-library detection"
    target_types = ["domain", "ip"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        r = ctx.results.get("_http_raw") or await http_get(
            ctx.session, f"https://{ctx.target}", timeout=12
        )
        if not r:
            r = await http_get(ctx.session, f"http://{ctx.target}", timeout=12)
        if not r:
            return {}

        html = (r.get("text") or "")[:200000].lower()
        headers = " ".join(f"{k}: {v}" for k, v in r.get("headers", {}).items()).lower()
        combined = html + " " + headers

        found: Dict[str, List[str]] = {}
        for category, techs in _TECH.items():
            hits = [name for name, sigs in techs.items() if any(_matches(s, combined) for s in sigs)]
            if hits:
                found[category] = sorted(hits)

        gen = _GENERATOR_RE.search(r.get("text") or "")
        if gen:
            found.setdefault("generator", []).append(gen.group(1).strip())
        return found


registry.register(TechDetectModule())
