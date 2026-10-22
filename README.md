# EnvHunter — GitHub Repository Hygiene Auditor

**EnvHunter** is an interactive command-line security and repository hygiene auditing tool developed for Kali Linux and UNIX-like environments. It audits publicly accessible GitHub repositories and reachable Git commit history for a specified GitHub username to detect exposed environment configuration files (`.env` and its variants) appearing in current snapshots or historical commits.

EnvHunter operates strictly as a defensive visibility tool: it identifies file paths, repository locations, commit metadata, and exposure status without extracting, displaying, or exporting sensitive file contents or credential values.

---

## Key Features

- **Interactive Main Terminal Menu:** Built with `rich`, providing live token authentication status, application version, update status, and interactive navigation.
- **First-Time Setup Wizard:** Guided 5-step authentication setup with clickable links, fine-grained PAT instructions, hidden input (`getpass`), real-time rate limit display, and secure storage outside the repository.
- **GitHub User Profile & Repository Search:** Rapidly search any GitHub user's public profile and repository overview before initiating an audit, complete with paginated repository tables.
- **Deep Repository Hygiene Auditing:** Inspects branch snapshots and Git commit history for `.env` exposures with SHA deduplication across branches and multi-mode scanning.
- **Exact Exposure Links:** Pinpoints the exact GitHub commit and blob URL for every identified finding.
- **Template Separation:** Accurately distinguishes benign template files (e.g. `.env.example`, `.env.sample`) from potentially exposed active environment files.
- **Exposure Classification:** Categorizes findings into `CURRENTLY_PRESENT`, `HISTORICAL_ONLY`, or `DELETED_FROM_SCANNED_BRANCHES`.
- **Safe Automatic Updates:** In-app update checker connected to upstream (`https://github.com/Shadab-2604/envhunter.git`) that performs safe fast-forward updates while strictly refusing to overwrite uncommitted user changes.
- **Resumable SQLite State:** Scan state is tracked in a local SQLite database (WAL mode), allowing interrupted scans to resume seamlessly without losing progress.
- **Multi-Format Export:** Generates rich terminal tables, spreadsheet-ready CSV, structured JSON, and XSS-sanitized interactive HTML reports.
- **Defensive Security Safeguards:** Strict `.gitignore` exclusions for `.env`, tokens, reports, and databases. Tokens are stored in user configuration with `0600` permissions.

---

## Architecture & Technology Stack

- **Language:** Python 3.11+
- **Terminal Interface:** `rich` (interactive tables, colored severity badges, progress bars, panels)
- **HTTP Client:** `requests` (connection pooling with `HTTPAdapter` and exponential backoff)
- **Git Operations:** Standard library `subprocess` with safe argument lists (`shell=False`)
- **Persistence:** SQLite3 standard library with indexed query structures
- **Testing:** `pytest` suite with mocked GitHub API responses and isolated temporary repositories

---

## Installation on Kali Linux

### 1. Install System Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

### 2. Clone the Repository

```bash
git clone https://github.com/Shadab-2604/envhunter.git
cd envhunter
```

### 3. Create and Activate Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## First-Time Setup Wizard

When EnvHunter is launched for the first time without a saved token, the interactive setup wizard starts automatically before presenting the main menu.

### Step 1 — Open GitHub Token Settings
Visit the GitHub Personal Access Token settings page:
- Clickable URL in supported terminals: [https://github.com/settings/personal-access-tokens](https://github.com/settings/personal-access-tokens)
- Plain text: `https://github.com/settings/personal-access-tokens`

### Step 2 — Generate a Fine-Grained Token
Configure the token with minimal permissions:
- **Token Name:** `EnvHunter Auditor` (or any custom identifier)
- **Expiration:** 30, 60, or 90 days recommended
- **Repository Access:** **Public Repositories (read-only)**
- **Permissions:** Public repository information only.
  > **Note:** EnvHunter never asks for repository write access, private repository access, or organization administration permissions.

### Step 3 — Enter Token
Enter the token when prompted. Input is hidden using `getpass` to prevent exposure on the screen or in terminal logs.

### Step 4 — Validation
EnvHunter validates the token by calling `GET https://api.github.com/user`:
- **HTTP 200:** Authentication succeeded. Reports the authenticated username and remaining API rate-limit quota (5,000 requests/hour).
- **HTTP 401:** Explains that the token is invalid, expired, revoked, or mistyped.
- **HTTP 403 / 429:** Parses rate-limit headers and displays the reset timestamp.
- **Network / TLS errors:** Returns diagnostic information without revealing token content.

### Step 5 — Secure Local Storage
EnvHunter offers to securely store the token in:
```text
~/.config/envhunter/token
```
- Directory permissions: `0700` (`rwx------`)
- File permissions: `0600` (`rw-------`)
- **Security Guarantee:** The token is never written to the project's `.env`, source code, SQLite database, terminal logs, or Git history.
- If declined, the token is retained in memory for the active session only.

---

## Interactive Main Menu

Launch the application:

```bash
python envhunter.py
```

The interactive Rich startup menu displays live account and application status:

```text
====================================================
                  ENVHUNTER
           GitHub Repository Auditor
====================================================

GitHub Account : <authenticated username>
Token Status   : Valid
Application    : v1.0.0
Update Status  : Up to date

----------------------------------------------------
MAIN MENU
----------------------------------------------------

[1] Search GitHub User
[2] Audit GitHub User
[3] Check for Updates
[4] Change GitHub Token
[5] Exit

Select an option:
```

### Menu Options Explained

#### Option [1] — Search GitHub User
- Queries public profile metadata (username, display name, public repos, bio, company, location).
- Enumerates public repositories with pagination.
- Displays a clean Rich table showing repository name, URL, default branch, type (Fork/Original), archived status, and size.
- Offers an immediate option to audit the searched user.
- **Notice:** Searching public profile and repositories never triggers an automatic full commit scan.

#### Option [2] — Audit GitHub User
- Validates the target GitHub account.
- Prompts for scanning mode:
  - `[1] Full` (Current snapshots and all reachable commit history — Recommended)
  - `[2] Current` (Current branch snapshots only — Fastest)
  - `[3] Deep` (Full reachable history + extra ref inspection)
- Offers optional repository limits and inclusion of forks/archived repositories.
- Displays a configuration review card and requests confirmation before starting.
- Displays live multi-stage progress bars and exports CSV, JSON, and HTML reports upon completion.

#### Option [3] — Check for Updates
- Checks the local installation against the upstream GitHub repository (`https://github.com/Shadab-2604/envhunter.git`).
- Compares local Git commit revisions and version numbers.
- If an update is available:
  - Verifies that the Git remote origin is valid.
  - Verifies that the working tree is clean. If uncommitted local edits are found, the update stops and prompts the user to commit or stash changes.
  - Never executes `git reset --hard` or destructive operations.
  - Performs a safe `git pull --ff-only origin main`.
  - Automatically updates dependencies from `requirements.txt` if changed.
  - Runs a post-update self-check.

#### Option [4] — Change GitHub Token
- Retains the currently active token until a replacement is validated.
- Prompts for a replacement token using hidden input.
- Validates the replacement against `GET https://api.github.com/user`.
- If valid, securely writes the replacement to `~/.config/envhunter/token` (0600).
- If validation fails, preserves the previously saved valid token.
- Clarifies that token revocation is managed through GitHub settings.

#### Option [5] — Exit
- Closes the application cleanly.
- Preserves SQLite database records and generated reports.
- Handles `Ctrl+C` gracefully without tracebacks.

---

## Direct CLI Command Execution

In addition to the interactive menu, EnvHunter preserves complete compatibility with direct CLI commands for scripting and automated pipelines:

### 1. Launch Main Menu
```bash
python envhunter.py
# or explicitly:
python envhunter.py menu
```

### 2. Configure Token Directly
```bash
python envhunter.py setup
```

### 3. Scan a Target Username
```bash
python envhunter.py scan <USERNAME>
```

### 4. Advanced Scan Options
```bash
# Limit to 5 repositories for quick auditing
python envhunter.py scan <USERNAME> --max-repos 5

# Specify scan depth
python envhunter.py scan <USERNAME> --history full     # default: snapshots + commit history
python envhunter.py scan <USERNAME> --history current  # branch snapshots only
python envhunter.py scan <USERNAME> --history deep     # extended ref inspection

# Include forks and archived repositories
python envhunter.py scan <USERNAME> --include-forks --include-archived

# Resume an interrupted scan session
python envhunter.py scan <USERNAME> --resume

# Discard previous SQLite records for user and scan fresh
python envhunter.py scan <USERNAME> --fresh

# Specify export format and custom output directory
python envhunter.py scan <USERNAME> --format all --output-dir /custom/reports/
```

### 5. Export Reports from Stored Scans
```bash
python envhunter.py report <USERNAME> --format all
python envhunter.py report <USERNAME> --format html
python envhunter.py report <USERNAME> --format csv
python envhunter.py report <USERNAME> --format json
```

---

## Finding Output Fields

Each finding in the terminal table and generated reports includes:

| Field | Description |
|---|---|
| `repository_owner` | GitHub username or organization owning the repository |
| `repository_name` | Name of the repository |
| `repository_url` | Web URL of the repository on GitHub |
| `file_url` | Exact URL to view the file or blob on GitHub at that specific commit |
| `branch_names` | Branches where the commit or file exists |
| `file_path` | Relative file path within the repository |
| `event_type` | Git change event (`added`, `modified`, `renamed`, `deleted`, `present_in_snapshot`) |
| `commit_sha` | Full 40-character Git commit hash |
| `short_sha` | Abbreviated 7-character commit hash |
| `commit_url` | Web URL linking directly to the commit on GitHub |
| `author_name` | Self-reported author name in Git commit metadata |
| `author_date_utc` | Author timestamp in UTC |
| `committer_name` | Self-reported committer name in Git commit metadata |
| `committer_date_utc` | Committer timestamp in UTC |
| `current_status` | Current exposure (`CURRENTLY_PRESENT`, `HISTORICAL_ONLY`, `DELETED_FROM_SCANNED_BRANCHES`) |
| `severity` | Calculated severity classification (`HIGH`, `MEDIUM`, `INFORMATIONAL`, `UNKNOWN`) |
| `detection_reason` | Matching rule and directory context explanation |

---

## Exposure Classifications & Severity

- **HIGH:** Active exposure. A non-template environment file is verified present in current branch HEAD snapshots (`CURRENTLY_PRESENT`).
- **MEDIUM:** Historical exposure. An environment file was committed in historical commits but has been deleted or renamed in current branch HEADs (`HISTORICAL_ONLY` or `DELETED_FROM_SCANNED_BRANCHES`).
- **INFORMATIONAL:** Template file detected (e.g. `.env.example`, `.env.sample`, `.env.template`).
- **UNKNOWN:** Incomplete scan state prevents full verification.

---

## Report Output Locations

Exported reports are stored in per-user directories under `reports/<USERNAME>/`:

```text
reports/
└── <USERNAME>/
    ├── envhunter_findings_<USERNAME>_<TIMESTAMP>.csv
    ├── envhunter_findings_<USERNAME>_<TIMESTAMP>.json
    └── envhunter_findings_<USERNAME>_<TIMESTAMP>.html
```

- **CSV:** Comma-separated spreadsheet format.
- **JSON:** Complete structured JSON with scan summary metrics and finding details.
- **HTML:** Responsive dark-themed report with sanitized HTML escaping (`html.escape`) to prevent cross-site scripting (XSS).

---

## Security Safeguards & Pre-Commit Policy

EnvHunter enforces strict security policies:
1. **No Content Exfiltration:** The tool inspects file paths and Git object trees. It never downloads, displays, or exports the contents of `.env` files or credentials.
2. **Git Ignore Configuration:** `.gitignore` excludes `.env`, `.env.*` (while keeping `.env.example`), `*.db`, `*.sqlite`, `reports/`, virtual environments, and token files.
3. **No Embedded Secrets:** Real credentials and Personal Access Tokens are never committed to the repository, stored in `.env.example`, or displayed in terminal output.
4. **Safe Updates:** Fast-forward Git updates verify remote origin URLs, require clean working trees, and never run `git reset --hard` or delete local databases/reports.

---

## Troubleshooting

- **HTTP 401 Unauthorized:** The Personal Access Token is invalid, mistyped, or expired. Use Option 4 (`Change GitHub Token`) or run `python envhunter.py setup`.
- **HTTP 403 / 429 Rate Limit:** The GitHub API rate limit has been reached. EnvHunter displays the reset time. Active scan progress is safely stored in SQLite; resume with `--resume` after the reset epoch.
- **Network / SSL Errors:** EnvHunter automatically retries transient connection drops with exponential backoff up to 3 times.
- **Interrupted Scan (Ctrl+C):** If a scan is stopped, progress up to the last completed repository is preserved. Resume with `python envhunter.py scan <USERNAME> --resume`.

---

## Running Automated Tests

Run the full automated test suite:

```bash
pytest tests/ -v
```

The test suite covers:
- Initial setup when no token exists
- Hidden token entry and validation
- Token status handling (200, 401, 403, 429, TLS errors)
- Main interactive menu navigation and Ctrl+C handling
- User profile search and repository enumeration
- Scan wizard configuration and resume workflow
- Token replacement and validation preservation
- Safe updater: fast-forward pull, dirty working tree rejection, remote verification, and manual fallback
- Secret detection and `.gitignore` file exclusion verification
