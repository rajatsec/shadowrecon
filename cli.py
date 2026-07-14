import asyncio
import os
import time
import shlex
import sys
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.align import Align
from rich.markdown import Markdown
from rich.prompt import Prompt

try:
    import readline
except ImportError:
    readline = None

from shadowrecon.config import (
    PROJECT_NAME, VERSION, TAGLINE, BANNER_STYLE, SUCCESS_STYLE,
    ERROR_STYLE, INFO_STYLE, HIGHLIGHT_STYLE, PANEL_STYLE,
    TOP_1000_PORTS, INIT_FILE,
)
from shadowrecon.core.engine import RegistryEngine
from shadowrecon.core.registry import load_all_modules, registry
from shadowrecon.core.validator import (
    validate_domain, validate_ports, validate_threads, validate_timeout, validate_providers,
)
from shadowrecon.db.models import ScanRecord
from shadowrecon.db.storage import ScanDB
from shadowrecon.utils.logger import logger
from shadowrecon.utils.report import build_report

app = typer.Typer(
    help=f"{PROJECT_NAME} - {TAGLINE}",
    no_args_is_help=False,
    rich_markup_mode="rich",
)
console = Console()

_DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

_CATEGORY_ICON = {
    "network": "🌐", "subdomain": "🔎", "web": "🌍", "cloud": "☁️",
    "osint": "📱", "media": "🖼️", "intel": "🛰️", "analysis": "🤖",
}


def load_config(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        console.print(f"[{ERROR_STYLE}]Config parse error:[/] {e}")
        return {}


def print_banner(clear: bool = True):
    if clear:
        os.system("cls" if os.name == "nt" else "clear")

    use_compact = "TERMUX_VERSION" in os.environ or console.width < 100
    if use_compact:
        banner_text = f"""
[bold red]  ___ _              _
 / __| |_  __ _ __| |_____ __ __
 \\__ \\ ' \\/ _` / _` / _ \\ V  V /
 |___/_||_\\__,_\\__,_\\___/\\_/\\_/
 [bold white]  ___
  | _ \\___  ___ ___  _ __
  |   / -_)/ _// _ \\| '_ \\
  |_|_\\___\\\\__\\\\___/| .__/
                    |_|[/]

    [dim white]v{VERSION} | {TAGLINE}
    Built by [bold cyan]@secure_with_rajat[/][/dim white]
    """
    else:
        banner_text = f"""
[bold red]███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/]

           [dim white]v{VERSION} | {TAGLINE} | Built by [bold cyan]@secure_with_rajat[/][/dim white]
    """

    console.print(Align.center(Panel(banner_text, style="red", border_style="bright_red", expand=False)))


def show_first_run_guide():
    guide = f"""
# Welcome to {PROJECT_NAME} v{VERSION}

**{TAGLINE}** — a modular platform: {len(load_all_modules().names())} recon modules across
network, web, subdomain, cloud, OSINT, media, threat-intel and AI analysis.

- Interactive mode: just run the tool and type commands
- `scan example.com`     full domain recon (+ AI summary & risk score)
- `phone +14155552671`   phone number OSINT
- `username johndoe`     username across public platforms
- `image ./photo.jpg`    image EXIF / GPS / OCR
- `doc ./file.pdf`       document metadata
- `modules`              list every available module
- `manual`               full help
"""
    console.print(Panel(Markdown(guide), title="[bold green]Initialized[/]", border_style="green"))
    with open(INIT_FILE, "w") as f:
        f.write(str(time.time()))


def print_manual():
    content = f"""
[bold cyan]{PROJECT_NAME} v{VERSION} — {TAGLINE}[/]

[bold yellow]TARGET COMMANDS[/]
[green]scan[/]        Full domain / IP reconnaissance
[green]phone[/]       Phone number OSINT (validation, carrier, region, line type)
[green]username[/]    Username presence across public platforms
[green]image[/]       Image OSINT (EXIF, GPS, properties, OCR)
[green]doc[/]         Document metadata (PDF / DOCX / PPTX / XLSX)

[bold yellow]DATA COMMANDS[/]
[green]history[/]     View past scans for a target
[green]compare[/]     Diff two past scans by ID (compare <id1> <id2>)
[green]modules[/]     List all available modules by category
[green]manual[/]      Show this manual   [green]clear[/]  Clear   [green]exit[/]  Quit

[bold yellow]SCAN FLAGS[/]
[blue]-d, --domain[/]    Target domain / IP
[blue]-p, --ports[/]     Ports: 22,80,443 or 1-1000
[blue]-t, --threads[/]   Concurrent workers (default 100)
[blue]-to, --timeout[/]  Port timeout seconds (default 1.0)
[blue]-o, --output[/]    Output directory (default output)
[blue]--modules[/]       Only run these modules (comma-separated)
[blue]--exclude[/]       Skip these modules
[blue]--full[/]          Enable every module (active brute-force, dirs, JS, cloud, takeover)
[blue]--providers[/]     Passive subdomain providers subset
[blue]--os[/]            OS fingerprint (needs nmap + privileges)

[bold yellow]EXAMPLES[/]
[white]scan example.com[/]                        default modules + AI summary
[white]scan -d example.com --full[/]              everything (intrusive-ish)
[white]scan -d example.com --modules dns,ssl,waf,tech[/]
[white]scan -d example.com --exclude dirs,js[/]
[white]phone +14155552671[/]      [white]username torvalds[/]
[white]image ~/pic.jpg[/]         [white]doc ~/report.pdf[/]

[dim]Optional API keys (Shodan / VirusTotal / SecurityTrails / AI) go in config.yaml.[/]
    """
    console.print(Panel(content, title="[bold red]Documentation[/]", border_style="cyan"))


def _show_modules():
    load_all_modules()
    summary = registry.summary()
    table = Table(title=f"{PROJECT_NAME} Modules ({len(registry.names())})",
                  header_style="bold magenta", border_style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Module", style="green")
    table.add_column("Default", justify="center")
    table.add_column("Description", style="dim")
    order = ["network", "subdomain", "web", "cloud", "intel", "osint", "media", "analysis"]
    for cat in order:
        for name in summary.get(cat, []):
            m = registry.get(name)
            icon = _CATEGORY_ICON.get(cat, "")
            default = "[green]✓[/]" if m.default_enabled else "[dim]opt[/]"
            table.add_row(f"{icon} {cat}", name, default, m.description)
    console.print(table)


# ------------------------- result display -------------------------

def _kv_table(title: str, data: dict):
    t = Table(title=title, header_style="bold magenta", border_style="dim")
    t.add_column("Field", style="cyan")
    t.add_column("Value")
    for k, v in data.items():
        if isinstance(v, (dict, list)):
            import json as _j
            v = _j.dumps(v, default=str)
        t.add_row(str(k), str(v))
    console.print(t)


def _display_osint(ttype: str, f: dict):
    if ttype == "phone":
        d = f.get("phone", {})
        if not d:
            console.print(f"[{ERROR_STYLE}]No phone data.[/]"); return
        base = {k: d[k] for k in ("input", "valid", "region", "location", "carrier",
                                  "line_type", "country_code") if k in d}
        _kv_table("📱 Phone OSINT", base)
        if d.get("timezones"):
            console.print(f"  [bold]Timezones:[/] {', '.join(d['timezones'])}")
        if d.get("formats"):
            console.print("  [bold]Formats:[/] " + "  ".join(f"[dim]{k}:[/] {v}" for k, v in d["formats"].items()))
    elif ttype == "username":
        d = f.get("username", {})
        found = d.get("found_on", [])
        console.print(f"\n[bold green]Found '{d.get('username','')}' on {len(found)} platform(s):[/]")
        for p in found:
            console.print(f"  [green]✓[/] {p}: [dim]{d['results'][p]['url']}[/]")
    elif ttype == "image":
        d = f.get("image", {})
        _kv_table("🖼️ Image OSINT", {k: d[k] for k in ("file", "size_bytes", "md5") if k in d})
        if d.get("properties"):
            _kv_table("Properties", d["properties"])
        if d.get("exif"):
            _kv_table("EXIF", d["exif"])
        if d.get("gps"):
            console.print(f"  [bold red]GPS:[/] {d['gps'].get('latitude')}, {d['gps'].get('longitude')} "
                          f"→ [cyan]{d['gps'].get('maps_url')}[/]")
        if d.get("ocr_text"):
            console.print(Panel(d["ocr_text"][:500], title="OCR Text", border_style="dim"))
    elif ttype == "document":
        d = f.get("document", {})
        _kv_table("📄 Document OSINT", {k: d[k] for k in ("file", "size_bytes", "md5") if k in d})
        if d.get("pdf"):
            _kv_table("PDF Metadata", d["pdf"].get("metadata", {}) or {"pages": d["pdf"].get("pages")})
        if d.get("office"):
            _kv_table("Office Metadata", d["office"])
        if d.get("embedded_links"):
            console.print(f"  [bold]Embedded links:[/] {len(d['embedded_links'])}")


def _display(result: dict):
    f = result.get("findings", {})
    rep = result.get("report", {})
    target = result.get("target", "")

    # Module run summary
    mods = result.get("modules", {})
    ok = sum(1 for m in mods.values() if m["status"] == "ok")
    console.print(f"\n[bold]Modules:[/] {ok}/{len(mods)} produced data")

    # OSINT / media targets: render their dedicated findings
    ttype = result.get("target_type")
    if ttype in ("phone", "username", "image", "document"):
        _display_osint(ttype, f)
        ai = rep.get("ai_summary", {})
        if ai.get("summary"):
            console.print(Panel(ai["summary"], title=f"[bold cyan]AI Summary ({ai.get('engine','')})[/]",
                                border_style="cyan"))
        return

    # DNS
    dns = rep.get("dns", {})
    if dns:
        t = Table(title=f"DNS — {target}", header_style="bold magenta", border_style="dim")
        t.add_column("Type", style="cyan", width=8)
        t.add_column("Records")
        for rtype, records in dns.items():
            t.add_row(rtype, "\n".join(records))
        console.print(t)

    # Network intel
    asn = f.get("asn", {}).get("asn", {})
    geo = f.get("ip_intel", {}).get("geo", {})
    if asn or geo:
        for ip in set(list(asn.keys()) + list(geo.keys())):
            a = asn.get(ip, {}); g = geo.get(ip, {})
            console.print(f"  [cyan]{ip}[/]  "
                          f"AS{a.get('asn','?')} [yellow]{a.get('as_name','')}[/]  "
                          f"{g.get('city','')} {g.get('country','')} [dim]{g.get('isp','')}[/]")

    # HTTP
    http = rep.get("http", {})
    if http:
        found = len(http.get("found_headers", {}))
        total = found + len(http.get("missing_headers", []))
        style = "green" if found >= 7 else ("yellow" if found >= 4 else "red")
        console.print(f"\n[bold]HTTP[/] {http.get('url','')}  Status: [cyan]{http.get('status_code','-')}[/]  "
                      f"Server: [yellow]{http.get('server','-')}[/]  Headers: [{style}]{found}/{total}[/]")

    # SSL
    ssl = f.get("ssl", {})
    if ssl and ssl.get("issuer_cn"):
        console.print(f"[bold]SSL[/] Issuer: [yellow]{ssl.get('issuer_cn')}[/]  "
                      f"Expires in: [cyan]{ssl.get('days_until_expiry')}[/] days  "
                      f"Trusted: {'[green]yes[/]' if ssl.get('trusted') else '[red]no[/]'}")

    # WAF / Tech
    waf = f.get("waf", {}).get("detected", [])
    if waf:
        console.print(f"[bold]WAF/CDN:[/] [magenta]{', '.join(waf)}[/]")
    tech = f.get("tech", {})
    if tech:
        flat = [x for v in tech.values() for x in (v if isinstance(v, list) else [v])]
        if flat:
            console.print(f"[bold]Tech:[/] [purple]{', '.join(flat)}[/]")

    # Ports
    ports = rep.get("open_ports", {})
    if ports:
        t = Table(title=f"Open Ports — {target}", border_style="red")
        t.add_column("Port", justify="right", style="cyan")
        t.add_column("Service", style="magenta")
        t.add_column("Tech", style="purple")
        t.add_column("Banner", style="yellow")
        for port, info in ports.items():
            t.add_row(str(port), info.get("service", "unknown"),
                      ", ".join(info.get("tech", [])) or "-", (info.get("banner") or "-")[:70])
        console.print(t)

    # Subdomains
    subs = rep.get("subdomains", [])
    if subs:
        console.print(f"\n[bold green]Subdomains:[/] {len(subs)} found")
        pp = rep.get("per_provider", {})
        if pp:
            console.print("  " + "  ".join(f"[dim]{n}:[/][cyan]{len(s)}[/]" for n, s in pp.items() if s))

    # Takeovers
    tk = rep.get("takeovers", [])
    if tk:
        console.print(f"\n[bold red]TAKEOVER RISKS ({len(tk)}):[/]")
        for t_ in tk:
            console.print(f"  [red][VULNERABLE][/] {t_['subdomain']} → {t_['cname']} ([yellow]{t_['service']}[/])")

    # Risk + AI
    risk = rep.get("risk", {})
    if risk:
        g = risk.get("grade", "-")
        gstyle = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}.get(g, "white")
        console.print(f"\n[bold]Risk Score:[/] [{gstyle}]{risk.get('risk_score')}/100  (grade {g})[/]  "
                      f"{risk.get('issue_count',0)} issue(s)")
        for i in risk.get("issues", [])[:8]:
            sev = i["severity"]
            sstyle = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            console.print(f"  [{sstyle}][{sev.upper()}][/] {i['issue']}")

    ai = rep.get("ai_summary", {})
    if ai.get("summary"):
        console.print(Panel(ai["summary"], title=f"[bold cyan]AI Summary ({ai.get('engine','')})[/]",
                            border_style="cyan"))


def _save_history(result: dict, config: dict):
    """Persist domain/ip scans to the SQLite history DB (best-effort)."""
    if result.get("target_type") not in ("domain", "ip"):
        return
    rep = result.get("report", {})
    try:
        db = ScanDB(config.get("db", {}).get("path", "shadowrecon.db"))
        record = ScanRecord(
            target=result.get("target", ""),
            timestamp=int(time.time()),
            dns=rep.get("dns", {}),
            subdomains=rep.get("subdomains", []),
            per_provider=rep.get("per_provider", {}),
            http=rep.get("http", {}),
            open_ports={str(k): v for k, v in rep.get("open_ports", {}).items()},
            takeovers=rep.get("takeovers", []),
        )
        asyncio.run(_save_async(db, record))
    except Exception as e:
        logger.warning(f"could not save scan history: {e}")


async def _save_async(db, record):
    await db.init()
    await db.save_scan(record)


# ------------------------- scan runners -------------------------

def run_registry_scan(target: str, target_type: str, config: dict, ports=None,
                      threads=100, timeout=1.0, only=None, exclude=None,
                      output_dir="output", flags=None):
    label = {"domain": "domain", "ip": "host", "phone": "number",
             "username": "username", "image": "image", "document": "document"}.get(target_type, "target")
    console.print(f"\n[bold yellow]>>> Recon on {label} [cyan]{target}[/cyan][/]")
    logger.info(f"Scan started: {target} ({target_type})")

    eng = RegistryEngine(config)
    result = {}

    async def _run():
        nonlocal result
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            task = progress.add_task(description="[cyan]Running modules...[/]", total=None)

            def cb(event, mod, res=None):
                if event == "start":
                    progress.update(task, description=f"[cyan]{mod.category.value}[/] · running [bold]{mod.name}[/]...")

            result = await eng.run(target, target_type=target_type, ports=ports or [],
                                   threads=threads, timeout=timeout, only=only,
                                   exclude=exclude, flags=flags or {}, progress_cb=cb)
            progress.update(task, description="[green]Scan complete[/]")

    asyncio.run(_run())
    _display(result)

    # Reports
    out_cfg = config.get("output", {})
    if output_dir == "output" and out_cfg.get("directory"):
        output_dir = out_cfg["directory"]
    formats = out_cfg.get("formats", ["json", "csv", "html"])
    filename = f"{target.replace('.', '_').replace('+', '').replace('/', '_')}_{int(time.time())}"
    paths = build_report(result, output_dir, filename, formats)
    if paths:
        console.print(Panel("[bold green]Saved:[/] " + " | ".join(f"[cyan]{p}[/]" for p in paths),
                            border_style="green"))

    _save_history(result, config)
    return result


# ------------------------- history / compare -------------------------

def _show_history(domain: str, config: dict):
    db = ScanDB(config.get("db", {}).get("path", "shadowrecon.db"))

    async def _get():
        await db.init()
        return await db.get_scans(domain)

    scans = asyncio.run(_get())
    if not scans:
        console.print(f"[{INFO_STYLE}]No scan history for {domain}[/]")
        return
    table = Table(title=f"Scan History — {domain}", header_style="bold magenta", border_style="dim")
    for col in ("ID", "Timestamp", "Subdomains", "Open Ports", "Takeovers"):
        table.add_column(col, style="cyan" if col == "ID" else None,
                         justify="right" if col not in ("ID", "Timestamp") else "left")
    for s in scans:
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["timestamp"]))
        table.add_row(str(s["id"]), ts, str(len(s.get("subdomains", []))),
                      str(len(s.get("open_ports", {}))), str(len(s.get("takeovers", []))))
    console.print(table)


def _show_compare(id1: int, id2: int, config: dict):
    db = ScanDB(config.get("db", {}).get("path", "shadowrecon.db"))

    async def _cmp():
        await db.init()
        return await db.compare_scans(id1, id2)

    diff = asyncio.run(_cmp())
    if not diff:
        console.print(f"[{ERROR_STYLE}]Could not find scans with IDs {id1} and {id2}.[/]")
        return
    console.print(f"\n[bold]Comparing scan [cyan]{id1}[/] → [cyan]{id2}[/][/]")
    rows = [("[green]+ New subdomains[/]", diff["new_subdomains"]),
            ("[red]- Removed subdomains[/]", diff["removed_subdomains"]),
            ("[green]+ New open ports[/]", diff["new_ports"]),
            ("[red]- Closed ports[/]", diff["closed_ports"])]
    any_change = False
    for label, items in rows:
        if items:
            any_change = True
            console.print(f"{label} ({len(items)}): [dim]{', '.join(map(str, items))}[/]")
    if not any_change:
        console.print("[dim]No differences between the two scans.[/]")


# ------------------------- interactive shell -------------------------

def interactive_shell():
    print_banner()
    config = load_config()
    if not os.path.exists(INIT_FILE):
        show_first_run_guide()
    if readline:
        readline.set_history_length(1000)
    console.print("[bold yellow]Interactive Shell[/] [dim](type 'manual' for help, 'exit' to quit)[/]")

    while True:
        try:
            cmd_input = Prompt.ask("\n[bold red]shadowrecon[/][bold white] >[/]").strip()
            if not cmd_input:
                continue
            low = cmd_input.lower()
            if low in ("exit", "quit"):
                console.print("[bold yellow]Shutting down... Goodbye![/]"); break
            if low == "manual":
                print_manual(); continue
            if low == "clear":
                print_banner(); continue
            if low == "modules":
                _show_modules(); continue

            try:
                args = shlex.split(cmd_input)
            except ValueError as e:
                console.print(f"[{ERROR_STYLE}]Parse error:[/] {e}"); continue
            if not args:
                continue
            cmd = args[0].lower()

            if cmd == "scan":
                _handle_shell_scan(args[1:], config)
            elif cmd == "phone" and len(args) >= 2:
                run_registry_scan(args[1], "phone", config, only=["phone", "ai_summary"])
            elif cmd == "username" and len(args) >= 2:
                run_registry_scan(args[1], "username", config, only=["username", "ai_summary"])
            elif cmd == "image" and len(args) >= 2:
                run_registry_scan(args[1], "image", config, only=["image", "ai_summary"])
            elif cmd in ("doc", "document") and len(args) >= 2:
                run_registry_scan(args[1], "document", config, only=["document", "ai_summary"])
            elif cmd == "history" and len(args) >= 2:
                _show_history(args[1], config)
            elif cmd == "compare" and len(args) >= 3:
                try:
                    _show_compare(int(args[1]), int(args[2]), config)
                except ValueError:
                    console.print(f"[{ERROR_STYLE}]Scan IDs must be integers.[/]")
            elif "." in args[0] and not args[0].startswith("-"):
                try:
                    domain = validate_domain(args[0])
                    run_registry_scan(domain, "domain", config, ports=TOP_1000_PORTS)
                except ValueError as e:
                    console.print(f"[{ERROR_STYLE}]Error:[/] {e}")
            else:
                console.print(f"[{ERROR_STYLE}]Unknown command.[/] Try [green]scan <domain>[/], "
                              f"[green]phone <num>[/], [green]modules[/], or [green]manual[/].")
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted. Type 'exit' to quit.[/]")
        except EOFError:
            console.print("\n[bold yellow]Shutting down... Goodbye![/]"); break
        except Exception as e:
            console.print(f"[{ERROR_STYLE}]Error:[/] {e}")


def _handle_shell_scan(args: list, config: dict):
    domain = None; ports_str = None; threads = 100; timeout = 1.0
    output = "output"; only = None; exclude = None; full = False; providers_str = None
    os_fp = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-d", "--domain") and i + 1 < len(args):
            domain = args[i + 1]; i += 2
        elif a in ("-p", "--ports") and i + 1 < len(args):
            ports_str = args[i + 1]; i += 2
        elif a in ("-t", "--threads") and i + 1 < len(args):
            threads = int(args[i + 1]); i += 2
        elif a in ("-to", "--timeout") and i + 1 < len(args):
            timeout = float(args[i + 1]); i += 2
        elif a in ("-o", "--output") and i + 1 < len(args):
            output = args[i + 1]; i += 2
        elif a == "--modules" and i + 1 < len(args):
            only = [x.strip() for x in args[i + 1].split(",")]; i += 2
        elif a == "--exclude" and i + 1 < len(args):
            exclude = [x.strip() for x in args[i + 1].split(",")]; i += 2
        elif a == "--providers" and i + 1 < len(args):
            providers_str = args[i + 1]; i += 2
        elif a == "--full":
            full = True; i += 1
        elif a == "--os":
            os_fp = True; i += 1
        else:
            if not domain and not a.startswith("-"):
                domain = a
            i += 1

    if not domain:
        console.print(f"[{ERROR_STYLE}]Provide a domain (-d).[/]"); return
    try:
        domain = validate_domain(domain)
        port_list = validate_ports(ports_str, TOP_1000_PORTS)
        threads = validate_threads(threads)
        timeout = validate_timeout(timeout)
        provider_list = validate_providers(providers_str)
    except ValueError as e:
        console.print(f"[{ERROR_STYLE}]{e}[/]"); return

    flags = {"os_fingerprint": os_fp}
    if provider_list:
        flags["providers"] = provider_list
    if full:
        only = [m.name for m in registry.for_target("domain")]  # everything
    run_registry_scan(domain, "domain", config, ports=port_list, threads=threads,
                      timeout=timeout, only=only, exclude=exclude, output_dir=output, flags=flags)


# ------------------------- typer commands -------------------------

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """ShadowRecon — Enterprise OSINT & Reconnaissance Platform"""
    if ctx.invoked_subcommand is None:
        interactive_shell()


@app.command()
def scan(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain / IP"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Ports: 22,80 or 1-1000"),
    threads: int = typer.Option(100, "--threads", "-t"),
    timeout: float = typer.Option(1.0, "--timeout", "-to"),
    output_dir: str = typer.Option("output", "--output", "-o"),
    modules: Optional[str] = typer.Option(None, "--modules", help="Only run these modules"),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="Skip these modules"),
    providers: Optional[str] = typer.Option(None, "--providers", help="Passive provider subset"),
    full: bool = typer.Option(False, "--full", help="Enable every module"),
    os_fp: bool = typer.Option(False, "--os", help="OS fingerprint (needs nmap)"),
    config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c"),
):
    """Run a full reconnaissance scan on a domain or IP."""
    print_banner(clear=False)
    config = load_config(config_path)
    if not domain:
        console.print(f"[{ERROR_STYLE}]Provide --domain.[/]"); raise typer.Exit(1)
    try:
        domain = validate_domain(domain)
        port_list = validate_ports(ports, TOP_1000_PORTS)
        threads = validate_threads(threads)
        timeout = validate_timeout(timeout)
        provider_list = validate_providers(providers)
    except ValueError as e:
        console.print(f"[{ERROR_STYLE}]Validation error:[/] {e}"); raise typer.Exit(1)

    only = [x.strip() for x in modules.split(",")] if modules else None
    excl = [x.strip() for x in exclude.split(",")] if exclude else None
    flags = {"os_fingerprint": os_fp}
    if provider_list:
        flags["providers"] = provider_list
    if full:
        load_all_modules()
        only = [m.name for m in registry.for_target("domain")]
    run_registry_scan(domain, "domain", config, ports=port_list, threads=threads,
                      timeout=timeout, only=only, exclude=excl, output_dir=output_dir, flags=flags)


@app.command()
def phone(number: str = typer.Argument(..., help="Phone number (E.164 preferred)"),
          config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c")):
    """Phone number OSINT."""
    print_banner(clear=False)
    run_registry_scan(number, "phone", load_config(config_path), only=["phone", "ai_summary"])


@app.command()
def username(name: str = typer.Argument(..., help="Username to search"),
             config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c")):
    """Username OSINT across public platforms."""
    print_banner(clear=False)
    run_registry_scan(name, "username", load_config(config_path), only=["username", "ai_summary"])


@app.command()
def image(path: str = typer.Argument(..., help="Path to an image file"),
          config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c")):
    """Image OSINT (EXIF, GPS, properties, OCR)."""
    print_banner(clear=False)
    run_registry_scan(path, "image", load_config(config_path), only=["image", "ai_summary"])


@app.command()
def doc(path: str = typer.Argument(..., help="Path to a document (PDF/DOCX/PPTX/XLSX)"),
        config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c")):
    """Document metadata OSINT."""
    print_banner(clear=False)
    run_registry_scan(path, "document", load_config(config_path), only=["document", "ai_summary"])


@app.command()
def modules():
    """List all available modules by category."""
    _show_modules()


@app.command()
def history(domain: str = typer.Argument(...),
            config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c")):
    """View past scan history for a target."""
    _show_history(domain, load_config(config_path))


@app.command()
def compare(id1: int = typer.Argument(...), id2: int = typer.Argument(...),
            config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c")):
    """Compare two past scans by ID."""
    _show_compare(id1, id2, load_config(config_path))


@app.command()
def manual():
    """Open the user manual."""
    print_banner()
    print_manual()


if __name__ == "__main__":
    app()
