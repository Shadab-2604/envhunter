"""
Report generation for EnvHunter.
Produces Rich terminal tables, CSV, JSON, and sanitized HTML reports.
"""

import csv
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envhunter.config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_REPORTS_DIR,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_MEDIUM,
    SEVERITY_UNKNOWN,
    STATUS_CURRENTLY_PRESENT,
    STATUS_DELETED,
    STATUS_HISTORICAL_ONLY,
    STATUS_UNKNOWN,
)


class Reporter:
    """
    Renders scan summaries and findings to terminal, CSV, JSON, and HTML.
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_summary_table(self, summary: Dict[str, Any]) -> None:
        """Prints a high-level summary of the scan results to the terminal."""
        table = Table(title=f"🛡️  {APP_NAME} Scan Summary", border_style="bold blue")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="bold white")

        table.add_row("Target Username", str(summary.get("target_username", "N/A")))
        table.add_row("Scan Mode", str(summary.get("scan_mode", "N/A")))
        table.add_row("Scan Status", str(summary.get("status", "N/A")))
        table.add_row("Started At (UTC)", str(summary.get("started_at", "N/A")))
        table.add_row("Finished At (UTC)", str(summary.get("finished_at", "In Progress")))
        table.add_row("Repositories Discovered", str(summary.get("total_repos", 0)))
        table.add_row("Repositories Completed", str(summary.get("completed_repos", 0)))
        table.add_row("Branches Discovered", str(summary.get("total_branches", 0)))
        table.add_row("Unique Commits Inspected", str(summary.get("unique_commits", 0)))

        sev_counts = summary.get("findings_by_severity", {})
        high_cnt = sev_counts.get(SEVERITY_HIGH, 0)
        med_cnt = sev_counts.get(SEVERITY_MEDIUM, 0)
        info_cnt = sev_counts.get(SEVERITY_INFORMATIONAL, 0)

        table.add_row(
            "Findings (HIGH)",
            f"[bold red]{high_cnt}[/bold red]" if high_cnt > 0 else "0",
        )
        table.add_row(
            "Findings (MEDIUM)",
            f"[bold yellow]{med_cnt}[/bold yellow]" if med_cnt > 0 else "0",
        )
        table.add_row(
            "Findings (INFORMATIONAL)",
            f"[bold cyan]{info_cnt}[/bold cyan]" if info_cnt > 0 else "0",
        )
        table.add_row("Total Findings", f"[bold white]{summary.get('total_findings', 0)}[/bold white]")

        self.console.print("\n")
        self.console.print(table)

    def print_findings_table(self, findings: List[Dict[str, Any]]) -> None:
        """Prints a detailed table of findings to the terminal."""
        if not findings:
            self.console.print("\n[bold green]✓ No environment files or variants were detected across inspected repositories.[/bold green]\n")
            return

        table = Table(title=f"🔍 Identified Environment File Occurrences ({len(findings)})", border_style="dim")
        table.add_column("Severity", justify="center", no_wrap=True)
        table.add_column("Repository", style="bold cyan")
        table.add_column("File Path", style="bold white")
        table.add_column("Event", style="magenta")
        table.add_column("Current Status", justify="center")
        table.add_column("Commit", style="blue")
        table.add_column("Author", style="dim")
        table.add_column("Date (UTC)", style="dim")

        for f in findings:
            sev = f.get("severity", SEVERITY_UNKNOWN)
            if sev == SEVERITY_HIGH:
                sev_styled = "[bold white on red] HIGH [/bold white on red]"
            elif sev == SEVERITY_MEDIUM:
                sev_styled = "[bold black on yellow] MEDIUM [/bold black on yellow]"
            elif sev == SEVERITY_INFORMATIONAL:
                sev_styled = "[bold white on blue] INFO [/bold white on blue]"
            else:
                sev_styled = f"[white]{sev}[/white]"

            status = f.get("current_status", STATUS_UNKNOWN)
            if status == STATUS_CURRENTLY_PRESENT:
                status_styled = "[bold red]PRESENT[/bold red]"
            elif status == STATUS_HISTORICAL_ONLY:
                status_styled = "[yellow]HISTORICAL[/yellow]"
            elif status == STATUS_DELETED:
                status_styled = "[green]DELETED[/green]"
            else:
                status_styled = f"[dim]{status}[/dim]"

            repo_str = f"{f.get('repo_owner')}/{f.get('repo_name')}"
            short_sha = f.get("short_sha", "") or (f.get("commit_sha", "")[:7])

            table.add_row(
                sev_styled,
                repo_str,
                f.get("file_path", ""),
                f.get("event_type", ""),
                status_styled,
                short_sha,
                f.get("author_name", "")[:20],
                str(f.get("author_date", ""))[:19],
            )

        self.console.print("\n")
        self.console.print(table)
        self.console.print(
            "[italic dim]Note: Git commit author metadata is self-reported in git commits and does not cryptographically prove who pushed the commit to GitHub.[/italic dim]\n"
        )

    def prepare_output_dir(self, target_username: str, custom_output_dir: Optional[str] = None) -> Path:
        """
        Creates and resolves the sanitized output directory for reports:
        reports/{USERNAME}/
        """
        if custom_output_dir:
            out_path = Path(custom_output_dir).resolve()
        else:
            out_path = (DEFAULT_REPORTS_DIR / target_username).resolve()

        out_path.mkdir(parents=True, exist_ok=True)
        return out_path

    def export_csv(
        self,
        target_username: str,
        findings: List[Dict[str, Any]],
        output_dir: Optional[str] = None,
    ) -> Path:
        """Exports all findings to a CSV file."""
        out_dir = self.prepare_output_dir(target_username, output_dir)
        ts_str = datetime.now(timezone.utc).strftime("%H%M%S")
        file_path = out_dir / f"envhunter_findings_{target_username}_{ts_str}.csv"

        fieldnames = [
            "repository_owner",
            "repository_name",
            "repository_url",
            "branch_names",
            "file_path",
            "file_url",
            "event_type",
            "commit_sha",
            "short_sha",
            "commit_url",
            "author_name",
            "author_email",
            "author_date_utc",
            "committer_name",
            "committer_email",
            "committer_date_utc",
            "parent_shas",
            "current_status",
            "severity",
            "detection_reason",
            "scan_timestamp_utc",
            "verification_status",
        ]

        with open(file_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    "repository_owner": finding.get("repo_owner", ""),
                    "repository_name": finding.get("repo_name", ""),
                    "repository_url": finding.get("repo_url", ""),
                    "branch_names": finding.get("branch_names", ""),
                    "file_path": finding.get("file_path", ""),
                    "file_url": finding.get("file_url", ""),
                    "event_type": finding.get("event_type", ""),
                    "commit_sha": finding.get("commit_sha", ""),
                    "short_sha": finding.get("short_sha", ""),
                    "commit_url": finding.get("commit_url", ""),
                    "author_name": finding.get("author_name", ""),
                    "author_email": finding.get("author_email", ""),
                    "author_date_utc": finding.get("author_date", ""),
                    "committer_name": finding.get("committer_name", ""),
                    "committer_email": finding.get("committer_email", ""),
                    "committer_date_utc": finding.get("committer_date", ""),
                    "parent_shas": finding.get("parent_shas", ""),
                    "current_status": finding.get("current_status", ""),
                    "severity": finding.get("severity", ""),
                    "detection_reason": finding.get("detection_reason", ""),
                    "scan_timestamp_utc": finding.get("scan_timestamp", ""),
                    "verification_status": finding.get("verification_status", ""),
                })

        return file_path

    def export_json(
        self,
        target_username: str,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_dir: Optional[str] = None,
    ) -> Path:
        """Exports scan summary and findings to a structured JSON file."""
        out_dir = self.prepare_output_dir(target_username, output_dir)
        ts_str = datetime.now(timezone.utc).strftime("%H%M%S")
        file_path = out_dir / f"envhunter_findings_{target_username}_{ts_str}.json"

        report_data = {
            "metadata": {
                "tool": APP_NAME,
                "version": APP_VERSION,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "target_username": target_username,
                "scope": "Public GitHub repositories and reachable commit history",
            },
            "summary": summary,
            "findings": findings,
        }

        with open(file_path, mode="w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return file_path

    def export_html(
        self,
        target_username: str,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_dir: Optional[str] = None,
    ) -> Path:
        """
        Exports an interactive, sanitized HTML report with responsive styling.
        Escapes all user and repository inputs to prevent XSS.
        """
        out_dir = self.prepare_output_dir(target_username, output_dir)
        ts_str = datetime.now(timezone.utc).strftime("%H%M%S")
        file_path = out_dir / f"envhunter_findings_{target_username}_{ts_str}.html"

        # Build rows safely escaping strings
        rows_html = []
        for f in findings:
            sev = html.escape(str(f.get("severity", SEVERITY_UNKNOWN)))
            sev_class = {
                SEVERITY_HIGH: "badge-high",
                SEVERITY_MEDIUM: "badge-med",
                SEVERITY_INFORMATIONAL: "badge-info",
            }.get(sev, "badge-unknown")

            repo_name = html.escape(f"{f.get('repo_owner')}/{f.get('repo_name')}")
            file_path_esc = html.escape(str(f.get("file_path", "")))
            file_url = html.escape(str(f.get("file_url", "") or f.get("commit_url", "")))
            event_type = html.escape(str(f.get("event_type", "")))
            status = html.escape(str(f.get("current_status", "")))
            short_sha = html.escape(str(f.get("short_sha", "")))
            commit_url = html.escape(str(f.get("commit_url", "")))
            author = html.escape(str(f.get("author_name", "")))
            author_date = html.escape(str(f.get("author_date", ""))[:19])
            reason = html.escape(str(f.get("detection_reason", "")))
            branches = html.escape(str(f.get("branch_names", "")))

            rows_html.append(f"""
            <tr>
                <td><span class="badge {sev_class}">{sev}</span></td>
                <td><strong>{repo_name}</strong><br><small class="text-muted">{branches}</small></td>
                <td>
                    <a href="{file_url}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
                        <code>{file_path_esc}</code>
                    </a>
                    <br><small class="text-muted">{reason}</small>
                </td>
                <td><span class="event-badge">{event_type}</span></td>
                <td><span class="status-tag status-{status.lower()}">{status}</span></td>
                <td>
                    <a href="{commit_url}" target="_blank" rel="noopener noreferrer">Commit: {short_sha}</a><br>
                    <a href="{file_url}" target="_blank" rel="noopener noreferrer" class="view-file-link">View File ↗</a>
                </td>
                <td>{author}<br><small class="text-muted">{author_date}</small></td>
            </tr>
            """)

        all_rows = "\n".join(rows_html) if rows_html else "<tr><td colspan='7' style='text-align:center;'>No environment file occurrences found.</td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EnvHunter Audit Report - {html.escape(target_username)}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #475569;
            --high: #ef4444;
            --medium: #f59e0b;
            --info: #3b82f6;
            --accent: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: var(--bg-secondary);
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        h1 {{
            margin: 0 0 0.5rem 0;
            font-size: 1.8rem;
            color: var(--text-primary);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            text-align: center;
        }}
        .stat-val {{
            font-size: 2rem;
            font-weight: bold;
            margin-top: 0.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        tr:hover {{
            background-color: rgba(255,255,255,0.02);
        }}
        .badge {{
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            display: inline-block;
        }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-med {{ background: var(--medium); color: black; }}
        .badge-info {{ background: var(--info); color: white; }}
        .status-tag {{
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }}
        .status-currently_present {{ color: var(--high); font-weight: bold; }}
        .status-historical_only {{ color: var(--medium); }}
        .status-deleted_from_scanned_branches {{ color: var(--accent); }}
        .text-muted {{ color: var(--text-secondary); }}
        code {{
            background: var(--bg-primary);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            color: #38bdf8;
            font-size: 0.9em;
        }}
        a {{ color: #38bdf8; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .view-file-link {{
            display: inline-block;
            margin-top: 0.35rem;
            padding: 0.2rem 0.5rem;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.4);
            border-radius: 4px;
            font-size: 0.72rem;
            color: #38bdf8;
            text-decoration: none;
            font-weight: 500;
        }}
        .view-file-link:hover {{
            background: rgba(56, 189, 248, 0.25);
            text-decoration: none;
        }}
        .disclaimer {{
            margin-top: 2rem;
            padding: 1rem;
            background: rgba(255,255,255,0.02);
            border-left: 4px solid var(--info);
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ {APP_NAME} Audit Report</h1>
            <p class="text-muted">Target Account: <strong>{html.escape(target_username)}</strong> | Mode: <strong>{html.escape(str(summary.get("scan_mode", "full")))}</strong></p>
            <p class="text-muted">Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="text-muted">Repositories</div>
                <div class="stat-val">{summary.get("total_repos", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="text-muted">Commits Inspected</div>
                <div class="stat-val">{summary.get("unique_commits", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="text-muted">Total Findings</div>
                <div class="stat-val">{summary.get("total_findings", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="text-muted">High Severity</div>
                <div class="stat-val" style="color: var(--high);">{summary.get("findings_by_severity", {}).get(SEVERITY_HIGH, 0)}</div>
            </div>
        </div>

        <h2>Identified Occurrences</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Repository / Branches</th>
                    <th>File Path & Reason</th>
                    <th>Event</th>
                    <th>Status</th>
                    <th>Commit</th>
                    <th>Author (UTC)</th>
                </tr>
            </thead>
            <tbody>
                {all_rows}
            </tbody>
        </table>

        <div class="disclaimer">
            <strong>Security Scope & Hygiene Disclosure:</strong>
            This defensive hygiene report lists file-path metadata and commit logs for publicly reachable Git objects. No secret values or sensitive file contents are extracted or exported. Commit author metadata is self-reported in git commits and does not cryptographically establish who performed the push to GitHub.
        </div>
    </div>
</body>
</html>
"""

        with open(file_path, mode="w", encoding="utf-8") as f:
            f.write(html_content)

        return file_path
