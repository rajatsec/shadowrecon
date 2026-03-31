# ShadowRecon 🛡️

ShadowRecon is a fast, modular, and professional-grade reconnaissance CLI tool designed for red teaming and security research. It automates subdomain enumeration and port scanning with high-fidelity terminal output.

## Features

- **Subdomain Enumeration**: Fetches data from `crt.sh` and `HackerTarget`.
- **Multi-threaded Port Scanning**: High-performance scanning using Python's `ThreadPoolExecutor`.
- **Structured Output**: Saves results in both `JSON` and `TXT` formats.
- **Hacker-style UI**: Built with `typer` and `rich` for a clean, professional terminal experience.
- **Logging**: Automatic logging of all activities and errors.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/rajatsec/shadowrecon.git
   cd shadowrecon
   ```

2. **Install dependencies**:
   ```bash
   pip install -r shadowrecon/requirements.txt
   ```

3. **(Optional) Set up Python path**:
   If you are running from the root directory:
   ```bash
   export PYTHONPATH=$PYTHONPATH:$(pwd)
   ```

## Usage

### Basic Scan
Perform a subdomain enumeration and scan top 20 common ports:
```bash
python3 shadowrecon/main.py scan -d example.com
```

### Advanced Scan
Scan specific ports with custom threads and timeout:
```bash
python3 shadowrecon/main.py scan -d example.com -p 80,443,8080,22 -t 200 -to 0.5
```

### Options
- `-d, --domain`: Target domain (Required)
- `-t, --threads`: Number of concurrent threads (Default: 100)
- `-to, --timeout`: Timeout for port scanning in seconds (Default: 1.0)
- `-p, --ports`: Comma-separated list of ports to scan
- `-o, --output`: Directory to save results (Default: `output`)

## Output
Results are saved in the `output/` directory:
- `domain_timestamp.json`: Full structured data.
- `domain_timestamp.txt`: Human-readable summary.

## Disclaimer
This tool is for educational and ethical security testing purposes only. Use it only on targets you have explicit permission to test.
