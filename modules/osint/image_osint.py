"""Image OSINT — EXIF metadata, GPS, image properties, optional OCR.

Target type: `image` (a local file path). Uses Pillow for EXIF/properties and
pytesseract for OCR when available (both optional).
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry


def _to_degrees(value) -> float:
    d, m, s = value
    return float(d) + float(m) / 60.0 + float(s) / 3600.0


class ImageOSINTModule(BaseModule):
    name = "image"
    category = Category.MEDIA
    description = "EXIF metadata, GPS coordinates, image properties, optional OCR"
    requires = ["PIL"]
    target_types = ["image"]
    needs_network = False

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        path = ctx.target
        if not os.path.isfile(path):
            return {"error": f"file not found: {path}"}

        with open(path, "rb") as f:
            raw = f.read()
        out: Dict[str, Any] = {
            "file": os.path.basename(path),
            "size_bytes": len(raw),
            "md5": hashlib.md5(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

        try:
            img = Image.open(path)
        except Exception as e:
            return {**out, "error": f"cannot open image: {e}"}

        out["properties"] = {
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "resolution": f"{img.width}x{img.height}",
        }

        exif_data = {}
        gps = {}
        try:
            raw_exif = img._getexif() or {}
        except Exception:
            raw_exif = {}
        for tag_id, value in raw_exif.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                for t in value:
                    gps[GPSTAGS.get(t, t)] = value[t]
            else:
                if isinstance(value, bytes):
                    try:
                        value = value.decode(errors="ignore")
                    except Exception:
                        value = str(value)
                exif_data[str(tag)] = str(value)[:200]

        interesting = {k: exif_data[k] for k in (
            "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
            "Orientation", "LensModel", "Artist", "Copyright") if k in exif_data}
        if interesting:
            out["exif"] = interesting
        if exif_data:
            out["exif_all_keys"] = sorted(exif_data.keys())

        # GPS coordinates
        if gps and "GPSLatitude" in gps and "GPSLongitude" in gps:
            try:
                lat = _to_degrees(gps["GPSLatitude"])
                if gps.get("GPSLatitudeRef") == "S":
                    lat = -lat
                lon = _to_degrees(gps["GPSLongitude"])
                if gps.get("GPSLongitudeRef") == "W":
                    lon = -lon
                out["gps"] = {
                    "latitude": round(lat, 6),
                    "longitude": round(lon, 6),
                    "maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                }
            except Exception:
                pass

        # Optional OCR
        try:
            import pytesseract  # noqa
            text = pytesseract.image_to_string(img)
            text = text.strip()
            if text:
                out["ocr_text"] = text[:2000]
        except Exception:
            pass

        return out


registry.register(ImageOSINTModule())
