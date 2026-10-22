# EnvHunter — Test and Validation Report

**Application Overview:** EnvHunter is a defensive repository hygiene and security auditing CLI tool that audits publicly accessible GitHub repositories and reachable commit history for exposed `.env` files and configuration variants without exfiltrating secret contents.

---

### Test Environment
- **Operating System:** Kali Linux x86_64 (Debian/UNIX-compatible)
- **Runtimes:** Python 3.11+, Git 2.30+
- **Core Dependencies:** `requests`, `rich`, `pytest`, SQLite 3 (WAL mode)

---

### Execution Modes
```bash
# 1. Interactive Startup Menu (Rich terminal UI)
python envhunter.py

# 2. Automated Token Setup Wizard
python envhunter.py setup

# 3. Direct User Audit
python envhunter.py scan <USERNAME> --format all
```

---

### Verification Summary
- **Automated Test Suite:** 53 / 53 automated unit and integration tests passing (`pytest tests/ -v`).
- **Feature Coverage:**
  - Token validation, 401/403/429 handling, and header-based rate-limit parsing.
  - Interactive startup menu, search profile preview, audit wizard, and token change workflows.
  - Safe updater fast-forward Git pull, remote origin validation, and dirty tree refusal.
  - Repository discovery, branch discovery, and commit history traversal.
  - Exposure classification (`CURRENTLY_PRESENT`, `HISTORICAL_ONLY`, `DELETED_FROM_SCANNED_BRANCHES`).
  - Strict secret detection and exclusion verification (`.env` exclusion, clean `.env.example`).
  - SQLite WAL persistence, state resume, and deduplication across branches.
  - Multi-format report exports: CSV, JSON, and XSS-sanitized HTML.
- **Security Safeguards:**
  - Zero PATs or credential values committed to source code or documentation.
  - Token stored outside repository at `~/.config/envhunter/token` with `0600` permissions.
  - Real `.env` files, SQLite databases, caches, and report files excluded by `.gitignore`.

---

### Report Output Structure
```text
reports/
└── <USERNAME>/
    ├── envhunter_findings_<USERNAME>_<TIMESTAMP>.csv
    ├── envhunter_findings_<USERNAME>_<TIMESTAMP>.json
    └── envhunter_findings_<USERNAME>_<TIMESTAMP>.html
```
