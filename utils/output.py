import json
import os
from typing import Dict, Any, List

class OutputHandler:
    def __init__(self, output_dir: str = "output"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        self.output_dir = output_dir

    def save_json(self, data: Dict[str, Any], filename: str):
        """Saves scan data as a JSON file."""
        filepath = os.path.join(self.output_dir, f"{filename}.json")
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            return filepath
        except Exception as e:
            return None

    def save_txt(self, data: Dict[str, Any], filename: str):
        """Saves scan results in a clean TXT format."""
        filepath = os.path.join(self.output_dir, f"{filename}.txt")
        try:
            with open(filepath, 'w') as f:
                f.write(f"ShadowRecon Report: {data.get('domain', 'Target')}\n")
                f.write("=" * 60 + "\n\n")
                
                # DNS Records
                if data.get("dns"):
                    f.write(f"DNS Records:\n")
                    for rtype, records in data["dns"].items():
                        f.write(f"  {rtype}:\n")
                        for r in records:
                            f.write(f"    - {r}\n")
                    f.write("\n" + "-" * 40 + "\n\n")

                # Subdomains
                f.write(f"Subdomains Found ({len(data.get('subdomains', []))}):\n")
                for sub in data.get('subdomains', []):
                    f.write(f"- {sub}\n")
                
                f.write("\n" + "=" * 60 + "\n\n")

                # HTTP Analysis
                if data.get("http"):
                    f.write(f"HTTP Analysis:\n")
                    f.write(f"  Server: {data['http'].get('server')}\n")
                    f.write(f"  Missing Headers:\n")
                    for mh in data['http'].get('missing_headers', []):
                        f.write(f"    - [!] {mh}\n")
                    f.write("\n" + "-" * 40 + "\n\n")

                # Open Ports
                f.write(f"Open Ports ({len(data.get('open_ports', {}))}):\n")
                for port, info in data.get('open_ports', {}).items():
                    banner = f" | Banner: {info['banner']}" if info['banner'] else ""
                    f.write(f"- {port} ({info['service']}){banner}\n")

            return filepath
        except Exception as e:
            return None
