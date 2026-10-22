"""
Command Line Interface (CLI) and execution orchestration for EnvHunter.
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import signal
import sys
from typing import Any, Dict, List, Optional
import uuid
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from envhunter.auth import (
    AuthenticationError,
    TokenValidationResult,
    change_token_workflow,
    delete_stored_token,
    ensure_authenticated_token,
    get_stored_token,
    get_welcome_banner,
    prompt_for_token,
    run_first_time_setup,
    save_token,
    validate_github_token,
)
from envhunter.config import (
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    SCAN_MODE_CURRENT,
    SCAN_MODE_DEEP,
    SCAN_MODE_FULL,
    TOKEN_FILE,
)
from envhunter.database import Database
from envhunter.detectors import EnvDetector
from envhunter.github_client import GitHubAPIError, GitHubClient, RateLimitExceeded, ResourceNotFoundError
from envhunter.history_scanner import HistoryScanner
from envhunter.reporter import Reporter
from envhunter.repository_scanner import RepositoryScanner
from envhunter.updater import (
    UPSTREAM_REPO_HTTPS,
    check_for_updates,
    get_manual_update_instructions,
    perform_safe_update,
)


class EnvHunterApp:
    """Main orchestrator for EnvHunter CLI workflows."""

    def __init__(self, db_path: Optional[Path] = None, console: Optional[Console] = None):
        self.console = console or Console()
        self.db = Database(db_path)
        self.reporter = Reporter(self.console)
        self.active_scan_id: Optional[str] = None
        self.current_token: Optional[str] = None
        self.current_auth_res: Optional[TokenValidationResult] = None

        # Setup graceful signal handler
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Handles Ctrl+C gracefully without data loss."""
        if self.active_scan_id:
            self.console.print("\n\n[bold yellow][!] Scan interrupted by user (Ctrl+C).[/bold yellow]")
            try:
                self.db.update_scan_status(self.active_scan_id, "INTERRUPTED")
                self.console.print("[green][✓] Current scan progress and completed repositories safely preserved in database.[/green]")
                self.console.print("[cyan][i] You can resume this scan at any time using:[/cyan]")
                self.console.print(f"    [bold white]python envhunter.py scan <USERNAME> --resume[/bold white]\n")
            except Exception:
                pass
            sys.exit(130)
        else:
            raise KeyboardInterrupt

    def run_setup(self) -> None:
        """Runs the interactive token setup and verification wizard."""
        try:
            token, res = run_first_time_setup(console=self.console)
            self.current_token = token
            self.current_auth_res = res
        except AuthenticationError as e:
            self.console.print(f"[bold red][✗] Setup aborted: {e}[/bold red]")

    def run_scan(
        self,
        target_username: str,
        token: Optional[str] = None,
        max_repos: Optional[int] = None,
        scan_mode: str = SCAN_MODE_FULL,
        resume: bool = False,
        fresh: bool = False,
        include_forks: bool = False,
        include_archived: bool = False,
        export_formats: Optional[List[str]] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        """Executes a complete scan against a target GitHub username."""
        self.console.print(get_welcome_banner(), style="bold cyan")

        # 1. Authenticate token
        client_token = token or get_stored_token()
        if not client_token:
            self.console.print("[yellow][!] No saved GitHub token found. Please authenticate.[/yellow]")
            client_token, auth_res = ensure_authenticated_token()
        else:
            auth_res = validate_github_token(client_token)
            if not auth_res.is_valid:
                self.console.print(f"[bold red][✗] Invalid token: {auth_res.error_message}[/bold red]")
                self.console.print("[yellow]Re-authenticating...[/yellow]")
                client_token, auth_res = ensure_authenticated_token(force_prompt=True)

        self.console.print(f"[bold green][✓] Authenticated as: [bold white]{auth_res.username}[/bold white][/bold green]")
        self.console.print(f"[cyan][i] API Rate Limit Remaining: {auth_res.rate_remaining}/{auth_res.rate_limit}[/cyan]")

        # 2. Check fresh or resume state
        if fresh:
            confirm = input(f"Are you sure you want to discard existing scan state for '{target_username}'? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                self.db.reset_user_scans(target_username)
                self.console.print(f"[green][✓] Previous scan records for '{target_username}' cleared.[/green]")
            else:
                self.console.print("[yellow]Continuing without clearing previous records.[/yellow]")

        existing_scan = self.db.get_latest_scan_for_user(target_username)
        if resume and existing_scan and existing_scan.get("status") in ("IN_PROGRESS", "INTERRUPTED"):
            scan_id = existing_scan["scan_id"]
            self.console.print(f"[bold green][✓] Resuming existing scan session: {scan_id}[/bold green]")
            self.db.update_scan_status(scan_id, "IN_PROGRESS")
        else:
            scan_id = f"scan-{uuid.uuid4().hex[:12]}"
            self.db.create_scan(scan_id, target_username, scan_mode)
            self.console.print(f"[cyan][i] Started new scan session: {scan_id}[/cyan]")

        self.active_scan_id = scan_id

        # Initialize clients & scanners
        github_client = GitHubClient(token=client_token)
        repo_scanner = RepositoryScanner(github_client, self.db)
        detector = EnvDetector()
        history_scanner = HistoryScanner(github_client, self.db, detector)

        # 3. Discover Repositories
        try:
            pending_repos = self.db.get_pending_repositories(scan_id)
            if not pending_repos:
                self.console.print(f"\n[bold white]Discovering public repositories for '{target_username}'...[/bold white]")
                all_repos = repo_scanner.discover_repositories(
                    scan_id=scan_id,
                    target_username=target_username,
                    include_forks=include_forks,
                    include_archived=include_archived,
                    max_repos=max_repos,
                    progress_callback=lambda msg: self.console.print(f"  [dim]{msg}[/dim]"),
                )
                pending_repos = self.db.get_pending_repositories(scan_id)
            else:
                self.console.print(f"\n[bold green][✓] Resuming with {len(pending_repos)} pending repositories in queue.[/bold green]")

            if not pending_repos:
                self.console.print(f"[bold yellow][!] No eligible public repositories found for user '{target_username}'.[/bold yellow]")
                self.db.update_scan_status(scan_id, "COMPLETED", total_repos=0)
            else:
                self.console.print(f"[bold cyan]Total repositories to audit: {len(pending_repos)}[/bold cyan]\n")

                # 4. Scan repositories with progress bar
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total} repos)"),
                    TimeElapsedColumn(),
                    console=self.console,
                ) as progress:
                    main_task = progress.add_task("Auditing Repositories", total=len(pending_repos))

                    for repo in pending_repos:
                        progress.update(main_task, description=f"Auditing [bold]{repo['full_name']}[/bold]")
                        self.db.update_repo_status(repo["repo_id"], "IN_PROGRESS")

                        # Discover branches & head trees
                        branches = repo_scanner.discover_repo_branches(
                            scan_id=scan_id,
                            repo=repo,
                            fetch_tree_snapshots=True,
                        )

                        # Historical and snapshot scan
                        history_scanner.scan_repository(
                            scan_id=scan_id,
                            repo=repo,
                            branches=branches,
                            scan_mode=scan_mode,
                        )

                        progress.advance(main_task)

                # Mark scan completed
                all_discovered_repos = self.db.get_all_repositories(scan_id)
                self.db.update_scan_status(scan_id, "COMPLETED", total_repos=len(all_discovered_repos))

        except ResourceNotFoundError:
            self.console.print(f"[bold red][✗] GitHub user '{target_username}' not found.[/bold red]")
            self.db.update_scan_status(scan_id, "FAILED")
            return
        except RateLimitExceeded as e:
            self.console.print(f"\n[bold red][!] GitHub API rate limit reached: {e}[/bold red]")
            self.console.print("[yellow]Scan state was saved. Run again later with --resume to continue.[/yellow]")
            self.db.update_scan_status(scan_id, "INTERRUPTED")
            return
        except Exception as e:
            self.console.print(f"\n[bold red][✗] Error during scan: {e}[/bold red]")
            self.db.record_error(scan_id, None, "UNHANDLED_EXCEPTION", str(e))
            self.db.update_scan_status(scan_id, "INTERRUPTED")
            return

        # 5. Output Summary and Findings Table
        summary = self.db.get_scan_summary(scan_id)
        findings = self.db.get_findings_for_scan(scan_id)

        self.reporter.print_summary_table(summary)
        self.reporter.print_findings_table(findings)

        # 6. Export Reports
        formats = export_formats or ["table", "csv", "json", "html"]
        if "all" in formats:
            formats = ["csv", "json", "html"]

        self.console.print("[bold white]Generated Reports:[/bold white]")
        if "csv" in formats or "all" in formats:
            csv_path = self.reporter.export_csv(target_username, findings, output_dir=output_dir)
            self.console.print(f"  [green]• CSV Report :[/green] [bold white]{csv_path}[/bold white]")

        if "json" in formats or "all" in formats:
            json_path = self.reporter.export_json(target_username, summary, findings, output_dir=output_dir)
            self.console.print(f"  [green]• JSON Report:[/green] [bold white]{json_path}[/bold white]")

        if "html" in formats or "all" in formats:
            html_path = self.reporter.export_html(target_username, summary, findings, output_dir=output_dir)
            self.console.print(f"  [green]• HTML Report:[/green] [bold white]{html_path}[/bold white]")

        # Display remaining rate limit
        if github_client.last_rate_limit:
            rl = github_client.last_rate_limit
            self.console.print(f"\n[cyan][i] GitHub API remaining: {rl.remaining}/{rl.limit} (Resets: {rl.reset_utc})[/cyan]")

    def run_report_export(
        self,
        target_username: str,
        export_format: str = "all",
        output_dir: Optional[str] = None,
    ) -> None:
        """Exports reports from existing scan results stored in SQLite."""
        latest_scan = self.db.get_latest_scan_for_user(target_username)
        if not latest_scan:
            self.console.print(f"[bold red][✗] No existing scan records found for user '{target_username}'.[/bold red]")
            return

        scan_id = latest_scan["scan_id"]
        summary = self.db.get_scan_summary(scan_id)
        findings = self.db.get_findings_for_scan(scan_id)

        self.console.print(f"[bold green][✓] Loaded scan {scan_id} for '{target_username}'.[/bold green]")
        self.reporter.print_summary_table(summary)
        self.reporter.print_findings_table(findings)

        formats = [export_format.lower()] if export_format.lower() != "all" else ["csv", "json", "html"]

        self.console.print("\n[bold white]Generated Reports:[/bold white]")
        if "csv" in formats:
            p = self.reporter.export_csv(target_username, findings, output_dir=output_dir)
            self.console.print(f"  [green]• CSV :[/green] [bold white]{p}[/bold white]")
        if "json" in formats:
            p = self.reporter.export_json(target_username, summary, findings, output_dir=output_dir)
            self.console.print(f"  [green]• JSON:[/green] [bold white]{p}[/bold white]")
        if "html" in formats:
            p = self.reporter.export_html(target_username, summary, findings, output_dir=output_dir)
            self.console.print(f"  [green]• HTML:[/green] [bold white]{p}[/bold white]")

    def _display_menu_header(self, auth_res: Optional[TokenValidationResult], update_status: str) -> None:
        """Renders the standard Rich EnvHunter header and menu options."""
        username = auth_res.username if (auth_res and auth_res.is_valid and auth_res.username) else "Not Authenticated"
        token_status = "Valid" if (auth_res and auth_res.is_valid) else "Invalid"
        version_str = f"v{APP_VERSION}"

        self.console.print("\n[bold cyan]" + "=" * 52 + "[/bold cyan]")
        self.console.print("[bold white]                  ENVHUNTER[/bold white]")
        self.console.print("[dim]           GitHub Repository Auditor[/dim]")
        self.console.print("[bold cyan]" + "=" * 52 + "[/bold cyan]\n")

        self.console.print(f"GitHub Account : [bold white]{username}[/bold white]")
        if token_status == "Valid":
            self.console.print("Token Status   : [bold green]Valid[/bold green]")
        else:
            self.console.print("Token Status   : [bold red]Invalid[/bold red]")
        self.console.print(f"Application    : [bold white]{version_str}[/bold white]")
        update_color = "bold green" if update_status == "Up to date" else ("bold yellow" if "Update" in update_status else "cyan")
        self.console.print(f"Update Status  : [{update_color}]{update_status}[/{update_color}]\n")

        self.console.print("[bold cyan]" + "-" * 52 + "[/bold cyan]")
        self.console.print("[bold white]MAIN MENU[/bold white]")
        self.console.print("[bold cyan]" + "-" * 52 + "[/bold cyan]\n")

        self.console.print("[bold green][1][/bold green] Search GitHub User")
        self.console.print("[bold green][2][/bold green] Audit GitHub User")
        self.console.print("[bold green][3][/bold green] Check for Updates")
        self.console.print("[bold green][4][/bold green] Change GitHub Token")
        self.console.print("[bold green][5][/bold green] Exit\n")

    def run_search_user(self) -> None:
        """Option 1: Search public profile and public repositories of a GitHub user."""
        self.console.print("\n[bold cyan]----------------------------------------------------[/bold cyan]")
        self.console.print("[bold white]            [1] SEARCH GITHUB USER[/bold white]")
        self.console.print("[bold cyan]----------------------------------------------------[/bold cyan]")
        try:
            username = input("Enter GitHub username to search: ").strip()
        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[dim]Search cancelled.[/dim]")
            return

        if not username:
            self.console.print("[bold red][!] Username cannot be empty.[/bold red]")
            return

        client = GitHubClient(token=self.current_token)
        self.console.print(f"[dim]Querying public profile for '{username}'...[/dim]")
        try:
            user_info = client.get_user(username)
        except ResourceNotFoundError:
            self.console.print(f"[bold red][✗] GitHub user '{username}' does not exist.[/bold red]")
            return
        except RateLimitExceeded as e:
            self.console.print(f"[bold red][!] GitHub API rate limit reached: {e}[/bold red]")
            return
        except GitHubAPIError as e:
            self.console.print(f"[bold red][✗] Error querying GitHub API: {e}[/bold red]")
            return

        # Display public profile summary card
        profile_table = Table(show_header=False, box=None, padding=(0, 2))
        profile_table.add_column("Property", style="bold cyan")
        profile_table.add_column("Detail", style="bold white")

        profile_table.add_row("Username", user_info.get("login", username))
        if user_info.get("name"):
            profile_table.add_row("Name", user_info.get("name"))
        profile_table.add_row("Public Profile URL", user_info.get("html_url", f"https://github.com/{username}"))
        profile_table.add_row("Public Repositories", str(user_info.get("public_repos", 0)))
        if user_info.get("bio"):
            profile_table.add_row("Bio", user_info.get("bio").strip())
        if user_info.get("company"):
            profile_table.add_row("Company", user_info.get("company"))
        if user_info.get("location"):
            profile_table.add_row("Location", user_info.get("location"))
        if user_info.get("created_at"):
            profile_table.add_row("Joined GitHub", str(user_info.get("created_at"))[:10])

        self.console.print(Panel(profile_table, title=f"GitHub Profile: {username}", border_style="cyan"))

        # Enumerate repositories with pagination
        self.console.print(f"\n[dim]Enumerating public repositories for '{username}'...[/dim]")
        try:
            repos = client.get_user_public_repos(username, include_forks=True, include_archived=True)
        except Exception as e:
            self.console.print(f"[bold red][!] Failed to list repositories: {e}[/bold red]")
            repos = []

        if repos:
            repo_table = Table(title=f"Public Repositories for '{username}' ({len(repos)} found)", show_lines=False)
            repo_table.add_column("#", style="dim", width=4)
            repo_table.add_column("Repository Name", style="bold white")
            repo_table.add_column("Default Branch", style="cyan")
            repo_table.add_column("Type", style="yellow")
            repo_table.add_column("Archived", style="magenta")
            repo_table.add_column("Size (KB)", justify="right", style="green")
            repo_table.add_column("Repository URL", style="blue")

            for idx, r in enumerate(repos, 1):
                repo_type = "Fork" if r.get("is_fork") else "Original"
                is_archived = "Yes" if r.get("is_archived") else "No"
                repo_table.add_row(
                    str(idx),
                    r.get("name", ""),
                    r.get("default_branch", "main"),
                    repo_type,
                    is_archived,
                    f"{r.get('size_kb', 0):,}",
                    r.get("url", ""),
                )
            self.console.print(repo_table)
        else:
            self.console.print(f"[yellow][i] No public repositories found for '{username}'.[/yellow]")

        # Offer to start an audit
        try:
            audit_choice = input(f"\nWould you like to start an audit of '{username}'? [y/N]: ").strip().lower()
            if audit_choice in ("y", "yes"):
                self.run_audit_user_wizard(target_username=username)
        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[dim]Returning to main menu.[/dim]")

    def run_audit_user_wizard(self, target_username: Optional[str] = None) -> None:
        """Option 2: Interactive wizard to configure and audit a GitHub user."""
        self.console.print("\n[bold cyan]----------------------------------------------------[/bold cyan]")
        self.console.print("[bold white]            [2] AUDIT GITHUB USER[/bold white]")
        self.console.print("[bold cyan]----------------------------------------------------[/bold cyan]")
        if not target_username:
            try:
                target_username = input("Enter target GitHub username to audit: ").strip()
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[dim]Audit cancelled.[/dim]")
                return

        if not target_username:
            self.console.print("[bold red][!] Target username cannot be empty.[/bold red]")
            return

        # Pre-validate account
        client = GitHubClient(token=self.current_token)
        try:
            client.get_user(target_username)
        except ResourceNotFoundError:
            self.console.print(f"[bold red][✗] GitHub user '{target_username}' does not exist.[/bold red]")
            return
        except Exception as e:
            self.console.print(f"[yellow][!] Notice: Could not verify user profile: {e}[/yellow]")

        # Scan modes
        self.console.print("\nSupported Scan Modes:")
        self.console.print("  [1] full    - Inspect current snapshots and reachable commit history (Recommended)")
        self.console.print("  [2] current - Inspect current branch snapshots only (Fastest)")
        self.console.print("  [3] deep    - Full reachable history + extra ref inspection")
        try:
            depth_choice = input("Select scan mode [1/2/3, default: 1]: ").strip()
        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[dim]Audit cancelled.[/dim]")
            return

        scan_mode_map = {"1": SCAN_MODE_FULL, "2": SCAN_MODE_CURRENT, "3": SCAN_MODE_DEEP}
        scan_mode = scan_mode_map.get(depth_choice, SCAN_MODE_FULL)

        try:
            limit_input = input("Limit number of repositories to scan (leave blank for all): ").strip()
            max_repos = int(limit_input) if limit_input.isdigit() and int(limit_input) > 0 else None

            forks_choice = input("Include forked repositories in audit? [y/N]: ").strip().lower()
            include_forks = forks_choice in ("y", "yes")

            archived_choice = input("Include archived repositories in audit? [y/N]: ").strip().lower()
            include_archived = archived_choice in ("y", "yes")

            existing = self.db.get_latest_scan_for_user(target_username)
            resume = False
            fresh = False
            if existing and existing.get("status") in ("IN_PROGRESS", "INTERRUPTED"):
                res_choice = input(f"An interrupted scan ({existing['scan_id']}) was found. Resume it? [Y/n]: ").strip().lower()
                if res_choice not in ("n", "no"):
                    resume = True
                else:
                    fresh = True
        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[dim]Audit cancelled.[/dim]")
            return

        # Summary of selected configuration
        self.console.print("\n[bold yellow]Scan Configuration Review:[/bold yellow]")
        self.console.print(f"  • Target User       : [bold white]{target_username}[/bold white]")
        self.console.print(f"  • Scan Mode         : [bold white]{scan_mode}[/bold white]")
        self.console.print(f"  • Max Repositories  : [bold white]{max_repos or 'All public repositories'}[/bold white]")
        self.console.print(f"  • Include Forks     : [bold white]{'Yes' if include_forks else 'No'}[/bold white]")
        self.console.print(f"  • Include Archived  : [bold white]{'Yes' if include_archived else 'No'}[/bold white]")
        self.console.print(f"  • Session Mode      : [bold white]{'Resume previous' if resume else 'New session'}[/bold white]")
        self.console.print("  • Security Boundary : Public repository metadata only. No secret exfiltration.")

        try:
            confirm = input("\nProceed with the live scan? [Y/n]: ").strip().lower()
            if confirm in ("n", "no"):
                self.console.print("[yellow]Scan aborted by user.[/yellow]")
                return
        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[dim]Scan cancelled.[/dim]")
            return

        # Run scan
        self.run_scan(
            target_username=target_username,
            token=self.current_token,
            max_repos=max_repos,
            scan_mode=scan_mode,
            resume=resume,
            fresh=fresh,
            include_forks=include_forks,
            include_archived=include_archived,
            export_formats=["csv", "json", "html"],
        )

    def run_update_check(self) -> str:
        """Option 3: Check for updates against upstream repository and safely update."""
        self.console.print("\n[bold cyan]----------------------------------------------------[/bold cyan]")
        self.console.print("[bold white]            [3] CHECK FOR UPDATES[/bold white]")
        self.console.print("[bold cyan]----------------------------------------------------[/bold cyan]")
        self.console.print(f"[dim]Checking upstream repository ({UPSTREAM_REPO_HTTPS})...[/dim]")

        check_res = check_for_updates(token=self.current_token)

        self.console.print(f"\n  • Local Application Version : [bold white]v{check_res.current_version}[/bold white]")
        if check_res.current_commit:
            self.console.print(f"  • Local Commit Revision     : [dim]{check_res.current_commit[:10]}[/dim]")
        if check_res.remote_commit:
            self.console.print(f"  • Remote Commit Revision    : [dim]{check_res.remote_commit[:10]}[/dim]")
        self.console.print(f"  • Update Status             : [bold cyan]{check_res.status_text}[/bold cyan]\n")

        if not check_res.is_git_repo:
            self.console.print("[yellow][!] EnvHunter is not installed as a Git repository checkout.[/yellow]")
            self.console.print(get_manual_update_instructions())
            return "Manual installation"

        if not check_res.is_remote_valid:
            self.console.print(f"[bold red][✗] {check_res.error_message}[/bold red]")
            self.console.print(f"[yellow]Expected upstream: {UPSTREAM_REPO_HTTPS}[/yellow]")
            return "Invalid remote"

        if check_res.is_dirty:
            self.console.print("[bold yellow][!] Uncommitted local changes detected in working tree.[/bold yellow]")
            self.console.print("To preserve your changes, commit or stash them before updating:\n"
                               "    git status\n"
                               "    git stash")
            return "Dirty working tree"

        if not check_res.is_update_available:
            self.console.print("[bold green]You are already using the latest version.[/bold green]")
            return "Up to date"

        # Newer version available
        self.console.print("[bold yellow]A new version is available. Updating EnvHunter...[/bold yellow]")
        try:
            confirm = input("Proceed with safe Git fast-forward update? [Y/n]: ").strip().lower()
            if confirm in ("n", "no"):
                self.console.print("[dim]Update deferred by user.[/dim]")
                return "Update available"
        except (KeyboardInterrupt, EOFError):
            self.console.print("\n[dim]Update cancelled.[/dim]")
            return "Update available"

        success, msg = perform_safe_update()
        if success:
            self.console.print(f"[bold green][✓] {msg}[/bold green]")
            return "Up to date"
        else:
            self.console.print(f"[bold red][✗] {msg}[/bold red]")
            return "Update failed"

    def run_change_token(self) -> None:
        """Option 4: Change GitHub Personal Access Token."""
        new_token, new_res = change_token_workflow(
            console=self.console,
            current_token=self.current_token,
        )
        if new_token and new_res and new_res.is_valid:
            self.current_token = new_token
            self.current_auth_res = new_res
            self.console.print("[bold green][✓] Active token successfully updated for this session.[/bold green]")

    def run_exit(self) -> None:
        """Option 5: Clean exit."""
        self.console.print("\n[bold cyan]Thank you for using EnvHunter. Exiting cleanly.[/bold cyan]")
        sys.exit(0)

    def run_main_menu(self) -> None:
        """Main persistent startup loop displaying the interactive menu."""
        # Ensure authenticated token on startup
        self.current_token = get_stored_token()
        if not self.current_token:
            try:
                self.current_token, self.current_auth_res = run_first_time_setup(console=self.console)
            except AuthenticationError as e:
                self.console.print(f"\n[bold red][✗] Setup aborted: {e}[/bold red]")
                return
        else:
            self.current_auth_res = validate_github_token(self.current_token)
            if not self.current_auth_res.is_valid:
                self.console.print(f"[bold red][!] Stored token is invalid: {self.current_auth_res.error_message}[/bold red]")
                try:
                    self.current_token, self.current_auth_res = run_first_time_setup(console=self.console)
                except AuthenticationError as e:
                    self.console.print(f"\n[bold red][✗] Setup aborted: {e}[/bold red]")
                    return

        update_status = "Up to date"

        while True:
            try:
                self._display_menu_header(self.current_auth_res, update_status)
                choice = input("Select an option: ").strip()

                if not choice:
                    continue

                if choice in ("1", "search"):
                    self.run_search_user()
                elif choice in ("2", "audit", "scan"):
                    self.run_audit_user_wizard()
                elif choice in ("3", "update"):
                    update_status = self.run_update_check()
                elif choice in ("4", "token", "auth"):
                    self.run_change_token()
                elif choice in ("5", "exit", "quit", "q"):
                    self.run_exit()
                else:
                    self.console.print(f"[bold red][!] Invalid option '{choice}'. Please select an option between 1 and 5.[/bold red]")

                try:
                    input("\nPress Enter to return to the main menu...")
                except (KeyboardInterrupt, EOFError):
                    pass
            except KeyboardInterrupt:
                self.console.print("\n")
                try:
                    confirm = input("Exit EnvHunter? [y/N]: ").strip().lower()
                    if confirm in ("y", "yes"):
                        self.run_exit()
                except (KeyboardInterrupt, EOFError):
                    self.run_exit()
            except EOFError:
                self.run_exit()

    def run_interactive_wizard(self) -> None:
        """Interactive entry point - launches the main menu loop."""
        self.run_main_menu()


def main() -> None:
    """Entry point for CLI argument parsing and dispatching."""
    parser = argparse.ArgumentParser(
        prog="envhunter",
        description=f"{APP_NAME}: {APP_DESCRIPTION} (Kali Linux defensive hygiene auditing tool)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # menu subcommand (also default)
    subparsers.add_parser("menu", help="Launch the interactive startup menu")

    # setup subcommand
    subparsers.add_parser("setup", help="Configure and validate GitHub Personal Access Token")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan public repositories of a target GitHub username")
    scan_parser.add_argument("username", help="Target GitHub username to audit")
    scan_parser.add_argument("--max-repos", type=int, default=None, help="Maximum number of repositories to scan")
    scan_parser.add_argument(
        "--history",
        choices=[SCAN_MODE_CURRENT, SCAN_MODE_FULL, SCAN_MODE_DEEP],
        default=SCAN_MODE_FULL,
        help="Scanning depth: 'current' (snapshots only), 'full' (reachable history, default), or 'deep'",
    )
    scan_parser.add_argument("--resume", action="store_true", help="Resume interrupted scan from SQLite state")
    scan_parser.add_argument("--fresh", action="store_true", help="Discard previous scan state for this user")
    scan_parser.add_argument("--include-forks", action="store_true", help="Include forked repositories in audit")
    scan_parser.add_argument("--include-archived", action="store_true", help="Include archived repositories in audit")
    scan_parser.add_argument(
        "--format",
        default="all",
        help="Report export format: csv, json, html, or all (default: all)",
    )
    scan_parser.add_argument("--output-dir", default=None, help="Custom output directory for exported reports")
    scan_parser.add_argument("--db-path", default=None, help="Custom path to SQLite database")

    # report subcommand
    report_parser = subparsers.add_parser("report", help="Export reports from previous scan records")
    report_parser.add_argument("username", help="Target GitHub username")
    report_parser.add_argument(
        "--format",
        choices=["csv", "json", "html", "all"],
        default="all",
        help="Export format (csv, json, html, all)",
    )
    report_parser.add_argument("--output-dir", default=None, help="Custom output directory for reports")
    report_parser.add_argument("--db-path", default=None, help="Custom path to SQLite database")

    args = parser.parse_args()

    # Determine custom db_path
    db_path = getattr(args, "db_path", None)
    app = EnvHunterApp(db_path=Path(db_path) if db_path else None)

    if args.command == "setup":
        app.run_setup()
    elif args.command == "scan":
        export_formats = [fmt.strip().lower() for fmt in args.format.split(",")]
        app.run_scan(
            target_username=args.username,
            max_repos=args.max_repos,
            scan_mode=args.history,
            resume=args.resume,
            fresh=args.fresh,
            include_forks=args.include_forks,
            include_archived=args.include_archived,
            export_formats=export_formats,
            output_dir=args.output_dir,
        )
    elif args.command == "report":
        app.run_report_export(
            target_username=args.username,
            export_format=args.format,
            output_dir=args.output_dir,
        )
    else:
        # Default with no arguments or 'menu' -> Main Startup Menu
        app.run_main_menu()


if __name__ == "__main__":
    main()

