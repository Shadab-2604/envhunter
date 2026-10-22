"""
Configuration constants and paths for EnvHunter.
"""

from pathlib import Path
import os
import re

# Application metadata
APP_NAME = "EnvHunter"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "GitHub Repository Hygiene Auditor"
USER_AGENT = f"{APP_NAME}-Auditor/{APP_VERSION} (+https://github.com/security/envhunter)"

# Configuration paths and permissions
CONFIG_DIR = Path(os.environ.get("ENVHUNTER_CONFIG_DIR", Path.home() / ".config" / "envhunter"))
TOKEN_FILE = CONFIG_DIR / "token"
DEFAULT_DB_PATH = CONFIG_DIR / "envhunter.db"
DEFAULT_REPORTS_DIR = Path("reports")

DIR_PERMISSIONS = 0o700   # rwx------
FILE_PERMISSIONS = 0o600  # rw-------

# GitHub API endpoints and defaults
GITHUB_API_BASE = "https://api.github.com"
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 30.0
DEFAULT_TIMEOUT = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0
API_PER_PAGE = 100
MAX_WORKER_THREADS = 4

# Exposure status constants
STATUS_CURRENTLY_PRESENT = "CURRENTLY_PRESENT"
STATUS_HISTORICAL_ONLY = "HISTORICAL_ONLY"
STATUS_DELETED = "DELETED_FROM_SCANNED_BRANCHES"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_INCOMPLETE = "INCOMPLETE_SCAN"

# Severity levels
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_INFORMATIONAL = "INFORMATIONAL"
SEVERITY_UNKNOWN = "UNKNOWN"

# Scan modes
SCAN_MODE_CURRENT = "current"
SCAN_MODE_FULL = "full"
SCAN_MODE_DEEP = "deep"


def redact_token(text: str, token: str | None = None) -> str:
    """
    Safely redacts any GitHub personal access token patterns or known token from text.
    Ensures tokens never leak into exceptions, logs, or reports.
    """
    if not text:
        return ""

    redacted = str(text)

    # If an exact token is provided, mask it
    if token and len(token) > 4:
        redacted = redacted.replace(token, "[REDACTED_TOKEN]")

    # Redact standard GitHub token formats
    # Classic PAT: ghp_[A-Za-z0-9]{36}
    # Fine-grained PAT: github_pat_[A-Za-z0-9_]{82}
    # OAuth: gho_[A-Za-z0-9]{36}
    patterns = [
        r"ghp_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{50,}",
        r"gho_[A-Za-z0-9]{30,}",
        r"ghu_[A-Za-z0-9]{30,}",
        r"ghs_[A-Za-z0-9]{30,}",
        r"ghr_[A-Za-z0-9]{30,}",
        r"bearer\s+[A-Za-z0-9_\-\.]{20,}",
        r"token\s+[A-Za-z0-9_\-\.]{20,}",
    ]
    for pattern in patterns:
        redacted = re.sub(pattern, "[REDACTED_CREDENTIAL]", redacted, flags=re.IGNORECASE)

    return redacted
