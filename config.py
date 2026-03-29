# ShadowRecon - Global Configuration
import os

PROJECT_NAME = "ShadowRecon"
VERSION = "1.1.0"
AUTHOR = "Rajat (@secure_with_rajat)"

# API Endpoints for Subdomain Enumeration
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

# Scan Configuration
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 1.0
TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

# Visuals (Rich Styles)
PRIMARY_COLOR = "bright_red"
SECONDARY_COLOR = "cyan"
BANNER_STYLE = "bold bright_red on black"
SUCCESS_STYLE = "bold green"
ERROR_STYLE = "bold red"
INFO_STYLE = "bold cyan"
HIGHLIGHT_STYLE = "bold magenta"
PANEL_STYLE = "dim white"

# File Paths
INIT_FILE = ".shadowrecon_init"
