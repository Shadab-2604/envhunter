#!/usr/bin/env python3
"""
EnvHunter: Automated GitHub .env and Environment Configuration History Scanner.

Entrypoint script to run EnvHunter from the command line.
Compatible with Python 3.11+ and Kali Linux.
"""

import sys
from pathlib import Path

# Ensure package is on sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from envhunter.cli import main

if __name__ == "__main__":
    main()
