"""Phone number OSINT (public information only).

Uses the `phonenumbers` library for validation, country, carrier, line type,
timezone and E.164/national/international formatting. Optional NumVerify API
enrichment if a key is configured. Target type: `phone`.
"""
from __future__ import annotations

from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry
from shadowrecon.utils.netutil import http_get


class PhoneOSINTModule(BaseModule):
    name = "phone"
    category = Category.OSINT
    description = "Phone validation, country, carrier, line type, timezone, formatting"
    requires = ["phonenumbers"]
    target_types = ["phone"]
    needs_network = False

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as pn_timezone

        raw = ctx.target
        default_region = ctx.config.get("osint", {}).get("phone_default_region", "IN")
        try:
            num = phonenumbers.parse(raw, None if raw.strip().startswith("+") else default_region)
        except Exception as e:
            return {"error": f"could not parse number: {e}"}

        valid = phonenumbers.is_valid_number(num)
        possible = phonenumbers.is_possible_number(num)
        number_type = phonenumbers.number_type(num)
        type_map = {
            0: "fixed_line", 1: "mobile", 2: "fixed_line_or_mobile", 3: "toll_free",
            4: "premium_rate", 5: "shared_cost", 6: "voip", 7: "personal_number",
            8: "pager", 9: "uan", 10: "unknown", 27: "emergency",
        }

        out: Dict[str, Any] = {
            "input": raw,
            "valid": valid,
            "possible": possible,
            "country_code": num.country_code,
            "national_number": num.national_number,
            "region": geocoder.region_code_for_number(num),
            "location": geocoder.description_for_number(num, "en"),
            "carrier": carrier.name_for_number(num, "en"),
            "line_type": type_map.get(number_type, "unknown"),
            "timezones": list(pn_timezone.time_zones_for_number(num)),
            "formats": {
                "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
                "rfc3966": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.RFC3966),
            },
        }

        # Optional NumVerify enrichment
        api_key = ctx.config.get("integrations", {}).get("numverify", {}).get("api_key", "")
        if api_key and ctx.session:
            url = f"http://apilayer.net/api/validate?access_key={api_key}&number={out['formats']['e164']}"
            r = await http_get(ctx.session, url, timeout=10)
            if r and r["status"] == 200:
                try:
                    import json
                    out["numverify"] = json.loads(r["text"])
                except Exception:
                    pass
        return out


registry.register(PhoneOSINTModule())
