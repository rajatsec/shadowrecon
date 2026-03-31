import urllib3
import warnings

# Suppress InsecureRequestWarning globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.align import Align
from rich.markdown import Markdown
from rich.prompt import Prompt
from typing import Optional, List
import os
import time
import shlex
import sys

# For History and Cursor Movement
try:
    import readline
except ImportError:
    readline = None

from shadowrecon.config import (
    PROJECT_NAME, VERSION, BANNER_STYLE, SUCCESS_STYLE, ERROR_STYLE, 
    INFO_STYLE, HIGHLIGHT_STYLE, PANEL_STYLE, TOP_1000_PORTS, INIT_FILE
)
from shadowrecon.modules.subdomain import SubdomainEnum
from shadowrecon.modules.portscan import PortScanner
from shadowrecon.modules.dns_enum import DNSEnum
from shadowrecon.modules.http_analysis import HTTPAnalysis
from shadowrecon.modules.service_fingerprint import ServiceFingerprint
from shadowrecon.utils.logger import logger
from shadowrecon.utils.output import OutputHandler

app = typer.Typer(
    help=f"{PROJECT_NAME} - Red Team Recon Tool",
    no_args_is_help=False,
    rich_markup_mode="rich"
)
console = Console()

def print_banner(clear: bool = True):
    if clear:
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')

    # Detect if running on mobile (Termux)
    is_mobile = "TERMUX_VERSION" in os.environ

    if is_mobile:
        banner_text = f"""
[bold red]  ___ _              _            
 / __| |_  __ _ __| |_____ __ __
 \__ \ ' \/ _` / _` / _ \ V  V /
 |___/_||_\__,_\__,_\___/\_/\_/ 
 [bold white]  ___                     
  | _ \___ __ ___ _ _ 
  |   / -_) _/ _ \ ' \ 
  |_|_\___\__\___/_||_|[/]

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

                     [dim white]v{VERSION} | Built by [bold cyan]@secure_with_rajat[/][/dim white]
    """

    console.print(Align.center(Panel(banner_text, style="red", border_style="bright_red", expand=False)))

def show_first_run_guide():
    guide_content = f"""
# 🛡️ Welcome to {PROJECT_NAME}

It looks like this is your first time. Here's the quick mission brief:

- **Interactive Mode**: Just run the tool and type commands.
- **Commands**: Type `scan google.com`, `manual`, or `exit`.
- **Power User**: Use flags like `scan -f targets.txt -p 80,443`.

---
*Type `manual` anytime for full documentation.*
    """
    console.print(Panel(Markdown(guide_content), title="[bold green]System Initialized[/]", border_style="green"))
    with open(INIT_FILE, 'w') as f:
        f.write(str(time.time()))

def print_manual():
    manual_content = f"""
[bold cyan]{PROJECT_NAME} User Manual[/]

[bold yellow]CORE COMMANDS[/]
[green]scan[/]             Perform a full reconnaissance scan.
[green]manual[/]           Display this detailed user manual.
[green]clear[/]            Clear the terminal screen.
[green]exit / quit[/]      Close the toolkit.

[bold yellow]SCAN OPTIONS & FLAGS[/]
[blue]-d, --domain[/]     Target domain (e.g., [dim]google.com[/dim])
[blue]-f, --file[/]       File with list of domains (one per line)
[blue]-p, --ports[/]      Ports to scan (e.g., [dim]22,80,443[/dim]). Default: Top 20.
[blue]-t, --threads[/]    Concurrent threads for scanning (default: [dim]100[/dim])
[blue]-to, --timeout[/]   Socket timeout in seconds (default: [dim]1.0[/dim])
[blue]-o, --output[/]      Directory to save results (default: [dim]output[/dim])

[bold yellow]EXAMPLES[/]
[dim]# Basic scan in shell[/]
shadowrecon > [white]scan -d example.com[/]

[dim]# Batch scan from file with custom ports[/]
shadowrecon > [white]scan -f targets.txt -p 80,443,8080[/]

[dim]# Fast scan with many threads[/]
shadowrecon > [white]scan -d target.com -t 300 -to 0.5[/]
    """
    console.print(Panel(manual_content, title="[bold red]Help & Documentation[/]", border_style="cyan"))

def parse_ports(ports_str: Optional[str]) -> List[int]:
    """Parses port string supporting commas and ranges (e.g., '80,443' or '1-100')."""
    if not ports_str:
        return TOP_1000_PORTS
    
    port_list = []
    try:
        for part in ports_str.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start, end = map(int, part.split("-"))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
    except ValueError:
        raise ValueError(f"Invalid port format: {ports_str}")
    
    return sorted(list(set(port_list)))

def run_recon(domain: str, threads: int, timeout: float, port_list: List[int], output_dir: str):
    console.print(f"\n[bold yellow]>>> Starting Recon for [cyan]{domain}[/cyan][/]")
    logger.info(f"Starting scan for {domain}")

    results = {
        "domain": domain,
        "subdomains": [],
        "open_ports": {},
        "dns": {},
        "http": {}
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        # 1. DNS Enumeration
        task_dns = progress.add_task(description=f"[cyan]Fetching DNS records...[/]", total=None)
        dns_enum = DNSEnum(domain)
        results["dns"] = dns_enum.run()
        progress.update(task_dns, description="[green]DNS Records Fetched[/]")

        # 2. Subdomain Enumeration
        task_sub = progress.add_task(description=f"[cyan]Enumerating subdomains...[/]", total=None)
        enum = SubdomainEnum(domain)
        subdomains = enum.run()
        results["subdomains"] = subdomains
        progress.update(task_sub, description="[green]Subdomains Enumerated[/]")

        # 3. HTTP Header Analysis
        task_http = progress.add_task(description=f"[cyan]Analyzing HTTP headers...[/]", total=None)
        http_analyser = HTTPAnalysis(domain)
        results["http"] = http_analyser.run()
        progress.update(task_http, description="[green]HTTP Analysis Completed[/]")

        # 4. Port Scanning
        task_port = progress.add_task(description=f"[cyan]Scanning {len(port_list)} ports...[/]", total=None)
        scanner = PortScanner(domain, port_list, threads=threads, timeout=timeout)
        open_ports = scanner.run()
        results["open_ports"] = open_ports
        progress.update(task_port, description="[green]Port Scan Finished[/]")

        # 5. Service Fingerprinting (Second Pass on Open Ports)
        if open_ports:
            task_finger = progress.add_task(description=f"[cyan]Fingerprinting {len(open_ports)} open ports...[/]", total=None)
            fingerprinter = ServiceFingerprint(domain, open_ports)
            results["open_ports"] = fingerprinter.run()
            progress.update(task_finger, description="[green]Service Fingerprinting Completed[/]")
    
    # Visual Output - DNS
    if results["dns"]:
        dns_table = Table(title=f"DNS Records for {domain}", show_header=True, header_style="bold magenta", border_style="dim")
        dns_table.add_column("Type", style="cyan")
        dns_table.add_column("Records")
        for rtype, records in results["dns"].items():
            dns_table.add_row(rtype, "\n".join(records))
        console.print(dns_table)

    # Visual Output - Ports Table
    table = Table(title=f"Open Ports on {domain}", style=INFO_STYLE, border_style="red")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Service", style="magenta")
    table.add_column("Banner", style="yellow")

    for port, info in open_ports.items():
        table.add_row(str(port), info["service"], info["banner"] or "-")
    
    if open_ports:
        console.print(table)
    else:
        console.print(f"[{ERROR_STYLE}]![/] No open ports found.")

    # Save Results
    handler = OutputHandler(output_dir)
    filename = f"{domain.replace('.', '_')}_{int(time.time())}"
    json_path = handler.save_json(results, filename)
    txt_path = handler.save_txt(results, filename)

    if json_path:
        console.print(Panel(f"[bold green]SUCCESS:[/] Results saved to [bold cyan]{output_dir}[/]", border_style="green"))
    
    return results

def interactive_shell():
    print_banner()
    if not os.path.exists(INIT_FILE):
        show_first_run_guide()
    
    # Enable Readline History
    if readline:
        readline.set_history_length(1000)

    console.print("[bold yellow]Interactive Shell Mode[/] [dim](Type 'exit' to quit, 'manual' for help)[/]")
    
    while True:
        try:
            # Using rich's Prompt for input (which uses standard input() internally)
            cmd_input = Prompt.ask(f"\n[bold red]shadowrecon[/][bold white] >[/]").strip()
            
            if not cmd_input:
                continue
            
            if cmd_input.lower() in ["exit", "quit"]:
                console.print("[bold yellow]Shutting down ShadowRecon... Goodbye![/]")
                break
            
            if cmd_input.lower() == "manual":
                print_manual()
                continue

            if cmd_input.lower() == "clear":
                print_banner()
                continue
            
            # Smart parsing for shell commands
            try:
                args = shlex.split(cmd_input)
                if args[0] == "scan":
                    domain = None
                    file_path = None
                    ports = None
                    threads = 100
                    timeout = 1.0
                    output = "output"

                    i = 1
                    while i < len(args):
                        arg = args[i]
                        if arg in ["-d", "--domain"]:
                            domain = args[i+1]; i += 2
                        elif arg in ["-f", "--file"]:
                            file_path = args[i+1]; i += 2
                        elif arg in ["-p", "--ports"]:
                            ports = args[i+1]; i += 2
                        elif arg in ["-t", "--threads"]:
                            threads = int(args[i+1]); i += 2
                        elif arg in ["-to", "--timeout"]:
                            timeout = float(args[i+1]); i += 2
                        elif arg in ["-o", "--output"]:
                            output = args[i+1]; i += 2
                        else:
                            if not domain and not arg.startswith("-"):
                                domain = arg
                            i += 1
                    
                    try:
                        port_list = parse_ports(ports)
                    except ValueError as e:
                        console.print(f"[{ERROR_STYLE}]Error:[/] {e}")
                        continue
                    
                    domains = []
                    if domain: domains.append(domain)
                    if file_path and os.path.exists(file_path):
                        with open(file_path, 'r') as f:
                            domains.extend([line.strip() for line in f if line.strip()])
                    
                    if not domains:
                        console.print(f"[{ERROR_STYLE}]Error:[/] Please provide a domain or a valid file.")
                    else:
                        for d in domains:
                            run_recon(d, threads, timeout, port_list, output)
                
                elif "." in args[0]: # Direct domain shortcut
                    run_recon(args[0], 100, 1.0, TOP_1000_PORTS, "output")
                else:
                    console.print(f"[{ERROR_STYLE}]Error:[/] Unknown command. Use [green]scan <domain>[/] or [green]manual[/].")
            
            except Exception as e:
                console.print(f"[{ERROR_STYLE}]Parser Error:[/] {e}")
                
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Session interrupted. Type 'exit' to close properly.[/]")
        except EOFError: # Handle Ctrl+D
            console.print("\n[bold yellow]Shutting down ShadowRecon... Goodbye![/]")
            break
        except Exception as e:
            console.print(f"[{ERROR_STYLE}]System Error:[/] {e}")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    ShadowRecon - Red Team Recon Toolkit
    """
    if ctx.invoked_subcommand is None:
        interactive_shell()

@app.command()
def scan(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain for scanning"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="File containing list of domains"),
    threads: int = typer.Option(100, "--threads", "-t", help="Number of threads for port scanning"),
    timeout: float = typer.Option(1.0, "--timeout", "-to", help="Port scan timeout in seconds"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Comma-separated list of ports to scan"),
    output_dir: str = typer.Option("output", "--output", "-o", help="Directory to save output files"),
):
    """
    🚀 Start a reconnaissance mission (Direct Command).
    """
    print_banner(clear=False) 

    if not domain and not file:
        console.print(f"[{ERROR_STYLE}]Error:[/] Please provide a domain (-d) or use interactive mode.")
        raise typer.Exit()

    try:
        port_list = parse_ports(ports)
    except ValueError as e:
        console.print(f"[{ERROR_STYLE}]Error:[/] {e}")
        raise typer.Exit()

    domains = []
    if domain:
        domains.append(domain)
    if file:
        if os.path.exists(file):
            with open(file, 'r') as f:
                domains.extend([line.strip() for line in f if line.strip()])
        else:
            console.print(f"[{ERROR_STYLE}]Error:[/] File {file} not found.")
            raise typer.Exit()
        
    for d in domains:
        run_recon(d, threads, timeout, port_list, output_dir)

@app.command()
def manual():
    """
    📖 Open the detailed user manual.
    """
    print_banner()
    print_manual()

if __name__ == "__main__":
    app()
