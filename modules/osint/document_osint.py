"""Document metadata OSINT — PDF / DOCX / PPTX / XLSX.

Extracts author, creator/producer software, timestamps, and embedded links.
Target type: `document` (a local file path). Uses pypdf and python-docx when
available (both optional).
"""
from __future__ import annotations

import hashlib
import os
import re
import zipfile
from typing import Any, Dict, List

from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")


def _pdf_meta(path: str) -> Dict[str, Any]:
    try:
        from pypdf import PdfReader
    except Exception:
        try:
            from PyPDF2 import PdfReader  # older name
        except Exception:
            return {"note": "install pypdf for PDF metadata"}
    try:
        reader = PdfReader(path)
        info = reader.metadata or {}
        meta = {k[1:] if k.startswith("/") else k: str(v) for k, v in info.items()}
        return {"pages": len(reader.pages), "metadata": meta}
    except Exception as e:
        return {"error": str(e)}


def _office_meta(path: str) -> Dict[str, Any]:
    """DOCX/PPTX/XLSX are zip files with core.xml metadata."""
    out: Dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path) as z:
            if "docProps/core.xml" in z.namelist():
                core = z.read("docProps/core.xml").decode(errors="ignore")
                for field in ("creator", "lastModifiedBy", "created", "modified", "title", "revision"):
                    m = re.search(rf"<(?:dc|cp|dcterms):{field}[^>]*>(.*?)</", core, re.I)
                    if m:
                        out[field] = m.group(1)
            if "docProps/app.xml" in z.namelist():
                app = z.read("docProps/app.xml").decode(errors="ignore")
                m = re.search(r"<Application>(.*?)</Application>", app, re.I)
                if m:
                    out["application"] = m.group(1)
                m = re.search(r"<Company>(.*?)</Company>", app, re.I)
                if m:
                    out["company"] = m.group(1)
    except Exception as e:
        out["error"] = str(e)
    return out


class DocumentOSINTModule(BaseModule):
    name = "document"
    category = Category.MEDIA
    description = "PDF/Office metadata: author, software, timestamps, embedded links"
    target_types = ["document"]
    needs_network = False

    async def run(self, ctx: ModuleContext) -> Dict[str, Any]:
        path = ctx.target
        if not os.path.isfile(path):
            return {"error": f"file not found: {path}"}
        with open(path, "rb") as f:
            raw = f.read()
        out: Dict[str, Any] = {
            "file": os.path.basename(path),
            "size_bytes": len(raw),
            "md5": hashlib.md5(raw).hexdigest(),
        }
        ext = os.path.splitext(path)[1].lower()
        if ext == ".pdf":
            out["pdf"] = _pdf_meta(path)
        elif ext in (".docx", ".pptx", ".xlsx"):
            out["office"] = _office_meta(path)
        else:
            out["note"] = f"unsupported extension '{ext}' (supported: pdf, docx, pptx, xlsx)"

        # Embedded links (from raw text for PDFs, safe subset)
        try:
            text = raw.decode("latin-1", errors="ignore")
            links = sorted(set(_URL_RE.findall(text)))[:50]
            if links:
                out["embedded_links"] = links
        except Exception:
            pass
        return out


registry.register(DocumentOSINTModule())
