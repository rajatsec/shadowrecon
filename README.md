<div align="center">

# 🛡️ ShadowRecon

### Enterprise OSINT & Reconnaissance Platform

*One target in — a full attack-surface map, risk score and AI summary out.*

<br>

![Version](https://img.shields.io/badge/version-2.0.0-red?style=for-the-badge)
![Modules](https://img.shields.io/badge/modules-29-orange?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-1793D1?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
![License](https://img.shields.io/badge/use-Authorized%20Only-critical?style=for-the-badge)

<br>

**Built with**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![asyncio](https://img.shields.io/badge/asyncio-000000?style=flat-square&logo=python&logoColor=white)
![aiohttp](https://img.shields.io/badge/aiohttp-2C5BB4?style=flat-square&logo=aiohttp&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)
![Typer](https://img.shields.io/badge/Typer-000000?style=flat-square&logo=typer&logoColor=white)
![Rich](https://img.shields.io/badge/Rich-FAD8B0?style=flat-square&logo=windowsterminal&logoColor=black)
![Jinja](https://img.shields.io/badge/Jinja-B41717?style=flat-square&logo=jinja&logoColor=white)
![Pillow](https://img.shields.io/badge/Pillow-11557C?style=flat-square&logo=python&logoColor=white)

**Data sources & integrations**

![Shodan](https://img.shields.io/badge/Shodan-C31E32?style=flat-square&logo=shodan&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=flat-square&logo=virustotal&logoColor=white)
![SecurityTrails](https://img.shields.io/badge/SecurityTrails-00C176?style=flat-square)
![crt.sh](https://img.shields.io/badge/crt.sh-4B8BBE?style=flat-square)
![AlienVault OTX](https://img.shields.io/badge/AlienVault_OTX-00A4EF?style=flat-square)
![urlscan.io](https://img.shields.io/badge/urlscan.io-EF5B25?style=flat-square)
![HackerTarget](https://img.shields.io/badge/HackerTarget-0B5FFF?style=flat-square)

<br>

<sub>Built by <b><a href="https://github.com/rajatsec">@secure_with_rajat</a></b> · For authorized security testing, CTFs & research only</sub>

</div>

---

## 📖 Overview

**ShadowRecon** is a fully-asynchronous, modular reconnaissance platform. Point it
at a **domain, IP, phone number, username, image or document** and it runs a suite
of **29 specialised modules** — then produces machine-readable JSON/CSV **and** a
polished interactive HTML dashboard with a computed **risk score** and an
**AI-generated executive summary**.

It's built as a *platform*, not a script: every capability is a self-contained
module registered in a central registry, so the engine can enumerate, select and
run them phase-by-phase over a shared context — and one failing module never takes
down a scan.

> ⚠️ **Legal & ethical use only.** ShadowRecon queries **public** data sources and
> runs non-intrusive checks by default. Intrusive modules (brute-force, directory
> discovery, JS crawling, cloud enumeration) are **strictly opt-in**. Only use it
> against assets you are explicitly authorized to assess.

---

## ✨ Feature Highlights

<table>
<tr>
<td width="50%" valign="top">

**🌐 Network Recon**
- WHOIS (registrar, dates, registrant, name servers)
- DNS records — A, AAAA, MX, NS, TXT, CNAME, SOA
- Reverse DNS (PTR)
- ASN / BGP prefix / AS owner (Team Cymru)
- IP geolocation, ISP/Org, reverse-IP neighbours
- Port scanning + service/banner detection
- Optional OS fingerprint (nmap)

**🔎 Subdomain Enumeration**
- Passive discovery — 5 providers
- Active DNS brute-force (wildcard-aware)
- Wildcard / catch-all detection
- Automatic validation & dedup

**☁️ Cloud Recon**
- Public S3 / GCS / Azure bucket discovery
- Public-listing detection
- CDN / cloud provider identification

**🛰️ Threat Intelligence** *(optional API keys)*
- Shodan host data (ports, vulns, tags)
- VirusTotal reputation & analysis
- SecurityTrails subdomains + historical DNS

</td>
<td width="50%" valign="top">

**🌍 Web Analysis**
- HTTP status, server, title, cookies
- Security-header audit (10 headers)
- Redirect chain tracing
- SSL/TLS — cert, issuer, expiry, SAN, TLS versions
- WAF / CDN detection (Cloudflare, Akamai, AWS, Fastly, Imperva…)
- Technology / CMS / framework / analytics detection
- robots.txt + sitemap.xml parsing
- Favicon hash (Shodan pivot)
- Directory & file discovery
- JavaScript endpoint + secret extraction
- Subdomain takeover detection

**📱 Digital Identity OSINT**
- Email harvesting + SPF/DMARC posture
- Username presence across 14 platforms
- Phone OSINT — validation, carrier, region, line type, timezone

**🖼️ Media & Document OSINT**
- Image EXIF, GPS coords, properties, OCR
- PDF / DOCX / PPTX / XLSX metadata + embedded links

**🤖 Analysis & Reporting**
- Heuristic risk score + graded findings
- AI (or local) executive summary + next steps
- JSON · CSV · HTML dashboard · optional PDF
- SQLite scan history + diff over time

</td>
</tr>
</table>

---

## 🧩 Module Matrix (29)

| Category | Modules | Default |
|----------|---------|:-------:|
| 🌐 **Network** (6) | `whois` · `dns` · `reverse_dns` · `asn` · `ip_intel` · `ports` | ✅ |
| 🔎 **Subdomain** (3) | `subdomains_passive` · `subdomains_active` · `wildcard` | passive ✅ |
| 🌍 **Web** (9) | `http` · `ssl` · `waf` · `tech` · `robots_sitemap` · `favicon` · `dirs` · `js` · `takeover` | core ✅ |
| ☁️ **Cloud** (1) | `cloud` | opt-in |
| 📱 **OSINT** (3) | `email` · `username` · `phone` | ✅ |
| 🖼️ **Media** (2) | `image` · `document` | ✅ |
| 🛰️ **Intel** (3) | `shodan` · `virustotal` · `securitytrails` | opt-in (API key) |
| 🤖 **Analysis** (2) | `risk` · `ai_summary` | ✅ |

> Run `shadowrecon modules` for the live, self-documenting list.

---

## 🚀 Installation

```bash
# 1. Clone
git clone https://github.com/rajatsec/shadowrecon.git
cd shadowrecon

# 2. Create a virtualenv & install core deps
python3 -m venv shadowrecon/venv
shadowrecon/venv/bin/pip install -r shadowrecon/requirements.txt

# 3. Run
python3 shadowrecon/main.py            # interactive shell
```

<details>
<summary><b>📦 Dependencies</b></summary>

**Core (required):** `typer` · `rich` · `aiohttp` · `aiodns` · `dnspython` · `pyyaml` · `aiosqlite` · `jinja2`

**Optional (auto-enable their module when present):**
| Package | Enables |
|---------|---------|
| `phonenumbers` | Phone OSINT |
| `Pillow` | Image EXIF / properties |
| `pypdf` | PDF metadata |
| `mmh3` | Shodan-compatible favicon hash |
| `pytesseract` *(+ tesseract binary)* | Image OCR |
| `weasyprint` | PDF report export |
| `cryptography` | Richer SSL parsing |

Modules whose optional dependency is missing **skip gracefully** — the platform never hard-fails.
</details>

<details>
<summary><b>📱 Termux (Android)</b></summary>

ShadowRecon auto-switches to a compact banner on Termux / narrow terminals.

```bash
pkg install python git
git clone https://github.com/rajatsec/shadowrecon.git
cd shadowrecon && pip install -r shadowrecon/requirements.txt
python main.py
```
</details>

---

## 🧭 Usage

### Interactive shell
```bash
python3 shadowrecon/main.py
```
```text
scan example.com                      # full domain recon (+ AI summary & risk)
scan -d example.com --full            # every module (intrusive-ish)
scan -d example.com --modules dns,ssl,waf,tech
scan -d example.com --exclude dirs,js
phone +14155552671                    # phone OSINT
username torvalds                     # username across public platforms
image ~/photo.jpg                     # EXIF / GPS / OCR
doc ~/report.pdf                      # document metadata
history example.com                   # past scans
compare 1 2                           # diff two scans over time
modules                               # list all modules
manual                                # full help
```

### One-off commands
```bash
python3 shadowrecon/main.py scan -d example.com --full
python3 shadowrecon/main.py phone +14155552671
python3 shadowrecon/main.py username torvalds
python3 shadowrecon/main.py image ./pic.jpg
python3 shadowrecon/main.py doc ./file.pdf
python3 shadowrecon/main.py modules
```

### Scan flags
| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain / IP |
| `-p, --ports` | `22,80,443` or a range `1-1000` |
| `-t, --threads` | Concurrent workers (default `100`) |
| `-to, --timeout` | Port timeout seconds (default `1.0`) |
| `-o, --output` | Output directory (default `output`) |
| `--modules` | Only run these modules (comma-separated) |
| `--exclude` | Skip these modules |
| `--full` | Enable **every** applicable module |
| `--providers` | Passive subdomain provider subset |
| `--os` | OS fingerprint (needs `nmap` + privileges) |

---

## 🏗️ Architecture

```text
shadowrecon/
├── main.py · recon · cli.py        Entry points, rich CLI & interactive shell
├── core/
│   ├── base_module.py              BaseModule · ModuleContext · ModuleResult
│   ├── registry.py                 ModuleRegistry — single source of truth
│   ├── engine.py                   RegistryEngine (v2) + legacy ScanEngine
│   ├── pipeline.py · validator.py
├── modules/
│   ├── network/  subdomain/  web/  cloud/  osint/  intel/  analysis/
│   └── (dns_enum · portscan · fingerprint · http_probe · takeover · subdomain_enum)
├── providers/                      Passive subdomain sources (crt.sh, urlscan, …)
├── db/                             SQLite scan history + diff
└── utils/                          report generator · netutil · logger · retry
```

**How a scan flows:** `validate → RegistryEngine selects modules → runs them
phase-by-phase (Network → Subdomain → Web → Cloud → Intel → OSINT → Media →
Analysis) over one shared ModuleContext → normalize → risk score + AI summary →
render JSON / CSV / HTML + save to history DB.`

### 🔌 Extending it — one class, one line
```python
from shadowrecon.core.base_module import BaseModule, Category, ModuleContext
from shadowrecon.core.registry import registry

class MyModule(BaseModule):
    name = "my_module"
    category = Category.WEB
    description = "What it does"
    target_types = ["domain"]

    async def run(self, ctx: ModuleContext) -> dict:
        # ctx.target, ctx.session, ctx.results (shared findings)…
        return {"hello": ctx.target}

registry.register(MyModule())
```
Add its import path to `core/registry.py` and it appears in `modules`, the engine and reports automatically.

---

## 📊 Output & Reporting

Every scan writes to `output/`:

| Format | Contents |
|--------|----------|
| **JSON** | Full structured findings + per-module status & timing |
| **CSV** | Flattened findings for spreadsheets / pipelines |
| **HTML** | Interactive dashboard — summary cards, risk grade, AI summary, graded issues, per-module sections |
| **PDF** | Optional (`weasyprint`) |

Domain/IP scans are also written to a **SQLite history** DB, so `history` and
`compare` let you track how a target's attack surface changes over time.

---

## 🔑 Optional API Integrations

Add keys in `config.yaml` under `integrations:` — everything works without them
(modules skip or fall back gracefully):

| Service | Powers |
|---------|--------|
| ![Shodan](https://img.shields.io/badge/Shodan-C31E32?style=flat-square&logo=shodan&logoColor=white) | Host ports, services, vulns, tags |
| ![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=flat-square&logo=virustotal&logoColor=white) | Domain/IP reputation & analysis |
| ![SecurityTrails](https://img.shields.io/badge/SecurityTrails-00C176?style=flat-square) | Subdomains + historical DNS |
| ![NumVerify](https://img.shields.io/badge/NumVerify-2D9CDB?style=flat-square) | Phone number enrichment |
| ![AI](https://img.shields.io/badge/Anthropic%20%2F%20OpenAI-412991?style=flat-square&logo=openai&logoColor=white) | LLM-written recon summary |

Without an AI key, ShadowRecon uses a fully-local heuristic summary generator.

---

## 🗺️ Roadmap

- [ ] Headless-browser screenshots & visual recon
- [ ] Reverse image search & scene/logo detection
- [ ] Attack-surface graph / network diagram visualization
- [ ] Scheduled scans + change-detection alerts (webhooks / email)
- [ ] REST API + web dashboard

---

## ⚖️ Disclaimer

ShadowRecon is intended for **educational purposes and authorized security testing
only**. You are responsible for complying with all applicable laws. Only use it
against systems you own or have **explicit written permission** to test. OSINT
modules query **public** data sources only. The authors assume no liability for
misuse.

<div align="center">
<br>
<sub>⭐ If ShadowRecon helps your recon, consider starring the repo.</sub><br>
<sub>Made with 🖤 by <a href="https://github.com/rajatsec"><b>@secure_with_rajat</b></a></sub>
</div>
