# ShadowRecon 🛡️

**ShadowRecon v2.0 — Enterprise OSINT & Reconnaissance Platform.**

An extensible, fully-async, all-in-one recon platform. Point it at a domain, IP,
phone number, username, image or document and it runs a suite of **29 modules**
across network, web, subdomain, cloud, OSINT, media, threat-intel and AI-analysis
categories — then produces JSON / CSV and an interactive HTML dashboard with a
risk score and an AI-generated summary.

> For **authorized security testing, CTFs and research only.** Public data sources
> and non-intrusive checks by default; intrusive modules are strictly opt-in.

---

## ✨ What's inside

| Category | Modules |
|----------|---------|
| 🌐 **Network** | `dns` (A/AAAA/MX/NS/TXT/CNAME/SOA), `whois`, `reverse_dns`, `asn` (Team Cymru), `ip_intel` (geo/ISP/reverse-IP), `ports` (+ optional nmap OS fingerprint) |
| 🔎 **Subdomain** | `subdomains_passive` (crt.sh, hackertarget, certspotter, alienvault, urlscan), `subdomains_active` (DNS brute-force), `wildcard` detection |
| 🌍 **Web** | `http` (headers/cookies/redirect chain), `ssl` (cert/issuer/expiry/TLS versions), `waf` (CDN/WAF detect), `tech` (CMS/framework/analytics), `robots_sitemap`, `favicon` (Shodan hash), `dirs` (dir/file discovery), `js` (endpoints + secret detection), `takeover` |
| ☁️ **Cloud** | `cloud` — S3 / GCS / Azure bucket discovery + CDN/provider ID |
| 📱 **OSINT** | `email` (harvest + SPF/DMARC), `username` (14 public platforms), `phone` (validation/carrier/region/line-type/timezone) |
| 🖼️ **Media** | `image` (EXIF/GPS/properties/OCR), `document` (PDF/DOCX/PPTX/XLSX metadata) |
| 🛰️ **Threat-Intel** | `shodan`, `virustotal`, `securitytrails` *(optional, API key)* |
| 🤖 **Analysis** | `risk` (heuristic score + graded issues), `ai_summary` (LLM or local heuristic) |

Run `shadowrecon modules` to see the live list.

---

## 🚀 Install

```bash
git clone https://github.com/rajatsec/shadowrecon.git
cd shadowrecon
pip install -r shadowrecon/requirements.txt      # core deps
```

Optional modules activate automatically when their (optional) dependency is
present — `phonenumbers`, `Pillow`, `pypdf`, `mmh3` are in requirements; OCR
(`pytesseract`), PDF export (`weasyprint`) and richer SSL (`cryptography`) are
commented out — uncomment to enable. Modules whose deps are missing **skip
gracefully** instead of failing.

A convenience launcher is included:

```bash
./recon                 # interactive shell
./recon scan example.com --full
```

---

## 🧭 Usage

### Interactive shell
```bash
python3 shadowrecon/main.py
```
```
scan example.com                 # full domain recon (+ AI summary & risk)
scan -d example.com --full       # every module (intrusive-ish)
scan -d example.com --modules dns,ssl,waf,tech
scan -d example.com --exclude dirs,js
phone +14155552671               # phone OSINT
username torvalds                # username across public platforms
image ~/photo.jpg                # EXIF / GPS / OCR
doc ~/report.pdf                 # document metadata
history example.com              # past scans
compare 1 2                      # diff two scans
modules                          # list all modules
manual                           # full help
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
| Flag | Meaning |
|------|---------|
| `-d, --domain` | Target domain / IP |
| `-p, --ports` | `22,80,443` or `1-1000` |
| `-t, --threads` | Concurrent workers (default 100) |
| `-to, --timeout` | Port timeout seconds (default 1.0) |
| `-o, --output` | Output directory (default `output`) |
| `--modules` | Only run these modules |
| `--exclude` | Skip these modules |
| `--full` | Enable **every** module |
| `--providers` | Passive subdomain provider subset |
| `--os` | OS fingerprint (needs `nmap` + privileges) |

---

## 🧱 Architecture

```
shadowrecon/
├── main.py / recon / cli.py     # entry points + rich CLI & interactive shell
├── core/
│   ├── base_module.py           # BaseModule interface + ModuleContext + ModuleResult
│   ├── registry.py              # module registry (single source of truth)
│   ├── engine.py                # RegistryEngine — runs modules phase-by-phase
│   ├── pipeline.py, validator.py
├── modules/
│   ├── network/  subdomain/  web/  cloud/  osint/  intel/  analysis/
│   └── (legacy dns_enum, portscan, fingerprint, http_probe, takeover, subdomain_enum)
├── providers/                   # passive subdomain sources
├── db/                          # SQLite scan history + diff
└── utils/                       # report generator, netutil, logger, retry
```

**Extending it is one class + one line:** subclass `BaseModule`, set `name` /
`category` / `target_types`, implement `async run(ctx)`, and register it. The
engine runs modules grouped by phase, shares one `ModuleContext` so later
modules build on earlier findings, and isolates failures so one bad module never
takes down a scan.

---

## 📊 Output & reporting

Every scan writes to `output/`:
- **JSON** — full structured findings + per-module status/timing
- **CSV** — flattened findings for spreadsheets / pipelines
- **HTML** — interactive dashboard with summary cards, risk grade, AI summary,
  graded issues and per-module sections
- **PDF** — optional (`weasyprint`)

Domain/IP scans are also saved to a **SQLite history** DB so you can `history`
and `compare` scans to track attack-surface changes over time.

---

## 🔌 Optional API integrations

Add keys in `config.yaml` under `integrations:` to enable them (all optional):
Shodan, VirusTotal, SecurityTrails, NumVerify (phone enrichment), and an AI
provider (`anthropic` / `openai`) for LLM-written summaries. Without an AI key,
ShadowRecon falls back to a fully-local heuristic summary.

---

## ⚖️ Disclaimer

This tool is for **educational and authorized security testing only**. Only use
it against targets you have explicit permission to assess. OSINT modules query
**public** data sources only.
