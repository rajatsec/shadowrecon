"""AI recon summary.

If an LLM API key is configured (Anthropic or OpenAI), it asks the model for a
concise executive summary + suggested next steps. Otherwise it falls back to a
fully local, template-based natural-language summary so the feature always works.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry


def _local_summary(ctx: ModuleContext) -> Dict[str, Any]:
    r = ctx.results
    lines: List[str] = []
    target = ctx.target

    subs = set()
    for key in ("subdomains_passive", "subdomains_active", "securitytrails"):
        subs |= set(r.get(key, {}).get("subdomains", []))
    ports = r.get("ports", {}).get("open_ports", {})
    risk = r.get("risk", {})

    lines.append(f"Reconnaissance of {target} completed.")
    if r.get("dns", {}).get("resolved_ips"):
        lines.append(f"Resolves to {len(r['dns']['resolved_ips'])} IP(s): "
                     f"{', '.join(r['dns']['resolved_ips'][:5])}.")
    asn = r.get("asn", {}).get("asn", {})
    if asn:
        first = next(iter(asn.values()))
        lines.append(f"Hosted on AS{first.get('asn','?')} ({first.get('as_name','unknown')}).")
    if subs:
        lines.append(f"{len(subs)} subdomain(s) discovered.")
    if ports:
        lines.append(f"{len(ports)} open port(s): {', '.join(str(p) for p in list(ports)[:10])}.")
    tech = r.get("tech", {})
    if tech:
        flat = [t for v in tech.values() for t in (v if isinstance(v, list) else [v])]
        if flat:
            lines.append(f"Technologies: {', '.join(flat[:8])}.")
    waf = r.get("waf", {}).get("detected", [])
    if waf:
        lines.append(f"Protected by: {', '.join(waf)}.")
    if risk:
        lines.append(f"Risk score: {risk.get('risk_score')}/100 (grade {risk.get('grade')}), "
                     f"{risk.get('issue_count', 0)} issue(s).")

    next_steps: List[str] = []
    for issue in risk.get("issues", [])[:5]:
        next_steps.append(f"[{issue['severity'].upper()}] {issue['issue']}")
    if not next_steps:
        next_steps.append("No high-priority issues surfaced by automated checks; consider manual review.")

    return {
        "engine": "local-heuristic",
        "summary": " ".join(lines),
        "suggested_next_steps": next_steps,
    }


async def _llm_summary(ctx: ModuleContext, provider: str, key: str) -> Dict[str, Any]:
    import aiohttp
    # Compact the findings so we don't blow the context
    compact = {k: v for k, v in ctx.results.items() if not k.startswith("_")}
    payload_text = json.dumps(compact, default=str)[:12000]
    prompt = (
        "You are a senior penetration tester. Given these JSON reconnaissance "
        f"findings for {ctx.target}, write a concise executive summary (4-6 sentences) "
        "and a prioritised list of suggested next steps. Findings:\n" + payload_text
    )
    try:
        if provider == "anthropic":
            url = "https://api.anthropic.com/v1/messages"
            headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
                       "content-type": "application/json"}
            body = {"model": "claude-sonnet-5", "max_tokens": 700,
                    "messages": [{"role": "user", "content": prompt}]}
            async with ctx.session.post(url, headers=headers, json=body,
                                        timeout=aiohttp.ClientTimeout(total=45)) as resp:
                data = json.loads(await resp.text())
            text = "".join(b.get("text", "") for b in data.get("content", []))
        else:  # openai
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {key}", "content-type": "application/json"}
            body = {"model": "gpt-4o-mini", "max_tokens": 700,
                    "messages": [{"role": "user", "content": prompt}]}
            async with ctx.session.post(url, headers=headers, json=body,
                                        timeout=aiohttp.ClientTimeout(total=45)) as resp:
                data = json.loads(await resp.text())
            text = data["choices"][0]["message"]["content"]
        return {"engine": provider, "summary": text.strip()}
    except Exception as e:
        out = _local_summary(ctx)
        out["note"] = f"LLM call failed ({e}); used local summary"
        return out


class AISummaryModule(BaseModule):
    name = "ai_summary"
    category = Category.ANALYSIS
    description = "AI (or local heuristic) executive summary + suggested next steps"
    needs_network = False
    target_types = ["domain", "ip", "phone", "username", "image", "document"]

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        ai_cfg = ctx.config.get("integrations", {}).get("ai", {})
        provider = (ai_cfg.get("provider") or "").lower()
        key = ai_cfg.get("api_key", "")
        if provider in ("anthropic", "openai") and key and ctx.session:
            return await _llm_summary(ctx, provider, key)
        return _local_summary(ctx)


registry.register(AISummaryModule())
