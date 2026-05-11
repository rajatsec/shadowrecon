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
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.align import Align
from rich.markdown import Markdown
from rich.prompt import Prompt

try:
    import readline
except ImportError:
    readline = None

from shadowrecon.config import (
    PROJECT_NAME, VERSION, BANNER_STYLE, SUCCESS_STYLE,
    ERROR_STYLE, INFO_STYLE, HIGHLIGHT_STYLE, PANEL_STYLE,
    TOP_1000_PORTS, INIT_FILE,
)
from shadowrecon.core.engine import ScanEngine
from shadowrecon.core.validator import validate_domain, validate_ports, validate_threads, validate_timeout
from shadowrecon.db.models import ScanRecord
from shadowrecon.db.storage import ScanDB
from shadowrecon.utils.logger import logger
from shadowrecon.utils.output import OutputHandler

app = typer.Typer(
    help=f"{PROJECT_NAME} - Professional Recon Framework",
    no_args_is_help=False,
    rich_markup_mode="rich",
)
console = Console()

_DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")


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

    is_mobile = "TERMUX_VERSION" in os.environ
    if is_mobile:
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

    [dim white]v{VERSION} | Built by [bold cyan]@secure_with_rajat[/][/dim white]
    """
    else:
        banner_text = f"""
[bold red]███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/]

              [dim white]v{VERSION} | Built by [bold cyan]@secure_with_rajat[/] | Async Engine | 5 Providers[/dim white]
    """

    console.print(Align.center(Panel(banner_text, style="red", border_style="bright_red", expand=False)))


def show_first_run_guide():
    guide = f"""
# Welcome to {PROJECT_NAME} v{VERSION}

**Async engine** — parallel scanning, 5 subdomain providers, takeover detection.

- Interactive mode: just run the tool and type commands
- Commands: `scan google.com`, `history google.com`, `manual`, `exit`
- Flags: `scan -d target.com --takeover --html`
    """
    console.print(Panel(Markdown(guide), title="[bold green]Initialized[/]", border_style="green"))
    with open(INIT_FILE, "w") as f:
        f.write(str(time.time()))


def print_manual():
    content = f"""
[bold cyan]{PROJECT_NAME} v{VERSION} — User Manual[/]

[bold yellow]COMMANDS[/]
[green]scan[/]         Full recon scan (async, multi-provider)
[green]history[/]      View past scans for a domain
[green]manual[/]       Show this manual
[green]clear[/]        Clear screen
[green]exit[/]         Quit

[bold yellow]SCAN FLAGS[/]
[blue]-d, --domain[/]     Target domain
[blue]-f, --file[/]       File with list of domains (one per line)
[blue]-p, --ports[/]      Ports: e.g. [dim]22,80,443[/dim] or [dim]1-1000[/dim]
[blue]-t, --threads[/]    Concurrent workers (default 100)
[blue]-to, --timeout[/]   Timeout in seconds (default 1.0)
[blue]-o, --output[/]     Output directory (default [dim]output[/dim])
[blue]--takeover[/]        Enable subdomain takeover detection
[blue]--html[/]            Save HTML report (in addition to JSON/TXT)
[blue]--providers[/]       Comma-separated provider list (crtsh,hackertarget,certspotter,alienvault,urlscan)

[bold yellow]EXAMPLES[/]
[dim]Basic scan[/dim]
[white]shadowrecon > scan -d example.com[/]

[dim]Full scan with takeover detection and HTML report[/dim]
[white]shadowrecon > scan -d example.com --takeover --html[/]

[dim]Batch scan[/dim]
[white]shadowrecon > scan -f targets.txt -p 80,443,8080[/]

[dim]View scan history[/dim]
[white]shadowrecon > history example.com[/]
    """
    console.print(Panel(content, title="[bold red]Documentation[/]", border_style="cyan"))


def _display_results(results: dict, domain: str):
    """Print rich-formatted tables for scan results."""
    # DNS
    if results.get("dns"):
        dns_table = Table(
            title=f"DNS Records — {domain}",
            header_style="bold magenta",
            border_style="dim",
        )
        dns_table.add_column("Type", style="cyan", width=8)
        dns_table.add_column("Records")
        for rtype, records in results["dns"].items():
            dns_table.add_row(rtype, "\n".join(records))
        console.print(dns_table)

    # HTTP summary
    http = results.get("http", {})
    if http:
        found = len(http.get("found_headers", {}))
        missing = len(http.get("missing_headers", []))
        total = found + missing
        score_style = "green" if found >= 7 else ("yellow" if found >= 4 else "red")
        console.print(
            f"\n[bold]HTTP[/] {http.get('url', '')}  "
            f"Status: [cyan]{http.get('status_code', '-')}[/]  "
            f"Server: [yellow]{http.get('server', '-')}[/]  "
            f"Headers: [{score_style}]{found}/{total}[/]"
        )
        if http.get("title"):
            console.print(f"  Title: [dim]{http['title']}[/]")
        if http.get("cookie_issues"):
            for ci in http["cookie_issues"]:
                console.print(f"  [yellow][!] {ci}[/]")

    # Ports
    ports = results.get("open_ports", {})
    if ports:
        port_table = Table(
            title=f"Open Ports — {domain}",
            style=INFO_STYLE,
            border_style="red",
        )
        port_table.add_column("Port", justify="right", style="cyan", width=7)
        port_table.add_column("Service", style="magenta", width=12)
        port_table.add_column("Tech", style="purple")
        port_table.add_column("Banner", style="yellow")
        for port, info in ports.items():
            tech = ", ".join(info.get("tech", [])) or "-"
            port_table.add_row(
                str(port),
                info.get("service", "unknown"),
                tech,
                (info.get("banner") or "-")[:80],
            )
        console.print(port_table)
    else:
        console.print(f"[{ERROR_STYLE}]![/] No open ports found.")

    # Subdomains summary
    subs = results.get("subdomains", [])
    per_prov = results.get("per_provider", {})
    if subs:
        console.print(f"\n[bold green]Subdomains:[/] {len(subs)} found")
        if per_prov:
            chips = "  ".join(
                f"[dim]{name}:[/][cyan]{len(s)}[/]" for name, s in per_prov.items() if s
            )
            console.print(f"  {chips}")

    # Takeovers
    takeovers = results.get("takeovers", [])
    if takeovers:
        console.print(f"\n[bold red]TAKEOVER RISKS ({len(takeovers)}):[/]")
        for t in takeovers:
            console.print(
                f"  [red][VULNERABLE][/] {t['subdomain']} → {t['cname']} "
                f"([yellow]{t['service']}[/])"
            )


def run_scan_sync(
    domain: str,
    threads: int,
    timeout: float,
    port_list: List[int],
    output_dir: str,
    enable_takeover: bool,
    save_html: bool,
    config: dict,
) -> dict:
    """Run async scan and save results."""
    console.print(f"\n[bold yellow]>>> Scanning [cyan]{domain}[/cyan][/]")
    logger.info(f"Scan started: {domain}")

    engine = ScanEngine(config)
    db_cfg = config.get("db", {})
    db = ScanDB(db_cfg.get("path", "shadowrecon.db"))

    results: dict = {}

    async def _run():
        nonlocal results
        await db.init()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(description="[cyan]Running async recon...[/]", total=None)
            results = await engine.run(
                target=domain,
                ports=port_list,
                threads=threads,
                timeout=timeout,
                enable_takeover=enable_takeover,
            )
            progress.update(task, description="[green]Scan complete[/]")

        record = ScanRecord(
            target=domain,
            timestamp=int(time.time()),
            dns=results.get("dns", {}),
            subdomains=results.get("subdomains", []),
            per_provider=results.get("per_provider", {}),
            http=results.get("http", {}),
            open_ports=results.get("open_ports", {}),
            takeovers=results.get("takeovers", []),
        )
        await db.save_scan(record)

    asyncio.run(_run())

    _display_results(results, domain)

    handler = OutputHandler(output_dir)
    filename = f"{domain.replace('.', '_')}_{int(time.time())}"
    paths = []
    if p := handler.save_json(results, filename):
        paths.append(p)
    if p := handler.save_txt(results, filename):
        paths.append(p)
    if save_html:
        if p := handler.save_html(results, filename):
            paths.append(p)

    if paths:
        console.print(
            Panel(
                f"[bold green]Saved:[/] " + " | ".join(f"[cyan]{p}[/]" for p in paths),
                border_style="green",
            )
        )
    return results


def _show_history(domain: str, config: dict):
    db_cfg = config.get("db", {})
    db = ScanDB(db_cfg.get("path", "shadowrecon.db"))

    async def _get():
        await db.init()
        return await db.get_scans(domain)

    scans = asyncio.run(_get())
    if not scans:
        console.print(f"[{INFO_STYLE}]No scan history for {domain}[/]")
        return

    table = Table(title=f"Scan History — {domain}", header_style="bold magenta", border_style="dim")
    table.add_column("ID", style="cyan", width=6)
    table.add_column("Timestamp")
    table.add_column("Subdomains", justify="right")
    table.add_column("Open Ports", justify="right")
    table.add_column("Takeovers", justify="right")
    for s in scans:
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["timestamp"]))
        table.add_row(
            str(s["id"]),
            ts,
            str(len(s.get("subdomains", []))),
            str(len(s.get("open_ports", {}))),
            str(len(s.get("takeovers", []))),
        )
    console.print(table)


def interactive_shell():
    print_banner()
    config = load_config()
    if not os.path.exists(INIT_FILE):
        show_first_run_guide()
    if readline:
        readline.set_history_length(1000)

    console.print("[bold yellow]Interactive Shell[/] [dim](type 'exit' to quit, 'manual' for help)[/]")

    while True:
        try:
            cmd_input = Prompt.ask("\n[bold red]shadowrecon[/][bold white] >[/]").strip()
            if not cmd_input:
                continue
            if cmd_input.lower() in ("exit", "quit"):
                console.print("[bold yellow]Shutting down... Goodbye![/]")
                break
            if cmd_input.lower() == "manual":
                print_manual()
                continue
            if cmd_input.lower() == "clear":
                print_banner()
                continue

            try:
                args = shlex.split(cmd_input)
            except ValueError as e:
                console.print(f"[{ERROR_STYLE}]Parse error:[/] {e}")
                continue

            if not args:
                continue

            cmd = args[0].lower()

            if cmd == "scan":
                _handle_shell_scan(args[1:], config)

            elif cmd == "history":
                if len(args) < 2:
                    console.print(f"[{ERROR_STYLE}]Usage:[/] history <domain>")
                else:
                    _show_history(args[1], config)

            elif "." in args[0] and not args[0].startswith("-"):
                # Direct domain shortcut: e.g. "example.com"
                try:
                    domain = validate_domain(args[0])
                    run_scan_sync(domain, 100, 1.0, TOP_1000_PORTS, "output", False, False, config)
                except ValueError as e:
                    console.print(f"[{ERROR_STYLE}]Error:[/] {e}")
            else:
                console.print(f"[{ERROR_STYLE}]Unknown command.[/] Use [green]scan <domain>[/], [green]history <domain>[/], or [green]manual[/].")

        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted. Type 'exit' to quit.[/]")
        except EOFError:
            console.print("\n[bold yellow]Shutting down... Goodbye![/]")
            break
        except Exception as e:
            console.print(f"[{ERROR_STYLE}]Error:[/] {e}")


def _handle_shell_scan(args: list, config: dict):
    domain = None
    file_path = None
    ports_str = None
    threads = 100
    timeout = 1.0
    output = "output"
    takeover = False
    save_html = False

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-d", "--domain") and i + 1 < len(args):
            domain = args[i + 1]; i += 2
        elif a in ("-f", "--file") and i + 1 < len(args):
            file_path = args[i + 1]; i += 2
        elif a in ("-p", "--ports") and i + 1 < len(args):
            ports_str = args[i + 1]; i += 2
        elif a in ("-t", "--threads") and i + 1 < len(args):
            try:
                threads = validate_threads(int(args[i + 1]))
            except ValueError as e:
                console.print(f"[{ERROR_STYLE}]{e}[/]"); return
            i += 2
        elif a in ("-to", "--timeout") and i + 1 < len(args):
            try:
                timeout = validate_timeout(float(args[i + 1]))
            except ValueError as e:
                console.print(f"[{ERROR_STYLE}]{e}[/]"); return
            i += 2
        elif a in ("-o", "--output") and i + 1 < len(args):
            output = args[i + 1]; i += 2
        elif a == "--takeover":
            takeover = True; i += 1
        elif a == "--html":
            save_html = True; i += 1
        else:
            if not domain and not a.startswith("-"):
                domain = a
            i += 1

    try:
        port_list = validate_ports(ports_str, TOP_1000_PORTS)
    except ValueError as e:
        console.print(f"[{ERROR_STYLE}]{e}[/]"); return

    domains: List[str] = []
    if domain:
        try:
            domains.append(validate_domain(domain))
        except ValueError as e:
            console.print(f"[{ERROR_STYLE}]{e}[/]"); return

    if file_path:
        if not os.path.exists(file_path):
            console.print(f"[{ERROR_STYLE}]File not found:[/] {file_path}"); return
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    domains.append(validate_domain(line))
                except ValueError:
                    console.print(f"[{ERROR_STYLE}]Skipping invalid domain:[/] {line}")

    if not domains:
        console.print(f"[{ERROR_STYLE}]Provide a domain (-d) or file (-f).[/]"); return

    for d in domains:
        run_scan_sync(d, threads, timeout, port_list, output, takeover, save_html, config)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """ShadowRecon — Professional Async Recon Framework"""
    if ctx.invoked_subcommand is None:
        interactive_shell()


@app.command()
def scan(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="File with domains"),
    threads: int = typer.Option(100, "--threads", "-t", help="Concurrent workers"),
    timeout: float = typer.Option(1.0, "--timeout", "-to", help="Timeout in seconds"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Ports: 22,80 or 1-1000"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Output directory"),
    takeover: bool = typer.Option(False, "--takeover", help="Enable takeover detection"),
    html: bool = typer.Option(False, "--html", help="Save HTML report"),
    config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c", help="Config YAML path"),
):
    """Run a full async reconnaissance scan."""
    print_banner(clear=False)
    config = load_config(config_path)

    if not domain and not file:
        console.print(f"[{ERROR_STYLE}]Provide --domain or --file.[/]")
        raise typer.Exit(1)

    try:
        port_list = validate_ports(ports, TOP_1000_PORTS)
        threads = validate_threads(threads)
        timeout = validate_timeout(timeout)
    except ValueError as e:
        console.print(f"[{ERROR_STYLE}]Validation error:[/] {e}")
        raise typer.Exit(1)

    domains: List[str] = []
    if domain:
        try:
            domains.append(validate_domain(domain))
        except ValueError as e:
            console.print(f"[{ERROR_STYLE}]{e}[/]")
            raise typer.Exit(1)

    if file:
        if not os.path.exists(file):
            console.print(f"[{ERROR_STYLE}]File not found:[/] {file}")
            raise typer.Exit(1)
        with open(file) as f_:
            for line in f_:
                line = line.strip()
                if not line:
                    continue
                try:
                    domains.append(validate_domain(line))
                except ValueError:
                    console.print(f"[{ERROR_STYLE}]Skipping invalid domain:[/] {line}")

    for d in domains:
        run_scan_sync(d, threads, timeout, port_list, output_dir, takeover, html, config)


@app.command()
def history(
    domain: str = typer.Argument(..., help="Domain to look up"),
    config_path: str = typer.Option(_DEFAULT_CONFIG_PATH, "--config", "-c"),
):
    """View past scan history for a domain."""
    config = load_config(config_path)
    _show_history(domain, config)


@app.command()
def manual():
    """Open the user manual."""
    print_banner()
    print_manual()


if __name__ == "__main__":
    app()
