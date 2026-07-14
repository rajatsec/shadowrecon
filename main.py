import os
import sys
import warnings

# Make the package importable no matter how this file is launched
# (e.g. `python shadowrecon/main.py`) without needing PYTHONPATH.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib3
from shadowrecon.cli import app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    app()
