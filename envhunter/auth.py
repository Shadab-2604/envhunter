"""
Authentication and secure token management for EnvHunter.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import getpass
import os
from pathlib import Path
from typing import Optional, Tuple
import requests
from rich.console import Console

from envhunter.config import (
    CONFIG_DIR,
    DEFAULT_TIMEOUT,
    DIR_PERMISSIONS,
    FILE_PERMISSIONS,
    GITHUB_API_BASE,
    TOKEN_FILE,
    USER_AGENT,
    redact_token,
)


@dataclass
class TokenValidationResult:
    """Result of a GitHub token validation check."""
    is_valid: bool
    status_code: int
    username: Optional[str] = None
    rate_limit: int = 0
    rate_remaining: int = 0
    rate_reset_utc: Optional[str] = None
    scopes: str = ""
    error_message: Optional[str] = None


class AuthenticationError(Exception):
    """Raised when token authentication or validation fails."""
    pass


def get_welcome_banner() -> str:
    """Returns the ASCII welcome banner for EnvHunter."""
    banner = r"""
  ███████╗███╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██╔════╝████╗  ██║██║   ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ██╔██╗ ██║██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗██║ ╚████║ ╚████╔╝ ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
              [ Defensive GitHub Repository Hygiene & File Auditor ]
    """
    return banner


def validate_github_token(token: str) -> TokenValidationResult:
    """
    Validates a GitHub token by making an authenticated request to GET /user.
    Never raises an exception with the token.
    """
    if not token or not token.strip():
        return TokenValidationResult(
            is_valid=False,
            status_code=400,
            error_message="Token is empty or contains only whitespace.",
        )

    clean_token = token.strip()
    headers = {
        "Authorization": f"Bearer {clean_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": USER_AGENT,
    }

    try:
        response = requests.get(
            f"{GITHUB_API_BASE}/user",
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.exceptions.SSLError as e:
        return TokenValidationResult(
            is_valid=False,
            status_code=0,
            error_message=f"TLS/SSL certificate verification failed: {redact_token(str(e), clean_token)}",
        )
    except requests.exceptions.ConnectionError as e:
        return TokenValidationResult(
            is_valid=False,
            status_code=0,
            error_message="Network connection error. Check DNS or internet connectivity.",
        )
    except requests.exceptions.Timeout:
        return TokenValidationResult(
            is_valid=False,
            status_code=0,
            error_message="Request timed out while validating token with api.github.com.",
        )
    except Exception as e:
        return TokenValidationResult(
            is_valid=False,
            status_code=0,
            error_message=f"Unexpected error: {redact_token(str(e), clean_token)}",
        )

    # Parse headers for rate limits
    rate_limit = int(response.headers.get("X-RateLimit-Limit", 0))
    rate_remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
    reset_epoch = response.headers.get("X-RateLimit-Reset")
    reset_utc = None
    if reset_epoch:
        try:
            reset_utc = datetime.fromtimestamp(int(reset_epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError):
            reset_utc = str(reset_epoch)

    scopes = response.headers.get("X-OAuth-Scopes", "")

    if response.status_code == 200:
        data = response.json()
        username = data.get("login")
        return TokenValidationResult(
            is_valid=True,
            status_code=200,
            username=username,
            rate_limit=rate_limit,
            rate_remaining=rate_remaining,
            rate_reset_utc=reset_utc,
            scopes=scopes,
        )
    elif response.status_code == 401:
        return TokenValidationResult(
            is_valid=False,
            status_code=401,
            rate_limit=rate_limit,
            rate_remaining=rate_remaining,
            error_message="HTTP 401 Unauthorized: Invalid, expired, or revoked GitHub token.",
        )
    elif response.status_code == 403:
        retry_after = response.headers.get("Retry-After")
        error_info = "HTTP 403 Forbidden: Insufficient permissions or rate limit exceeded."
        if rate_remaining == 0 and reset_utc:
            error_info += f" Rate limit will reset at {reset_utc}."
        if retry_after:
            error_info += f" Secondary rate limit active. Retry after {retry_after} seconds."
        return TokenValidationResult(
            is_valid=False,
            status_code=403,
            rate_limit=rate_limit,
            rate_remaining=rate_remaining,
            rate_reset_utc=reset_utc,
            error_message=error_info,
        )
    elif response.status_code == 429:
        retry_after = response.headers.get("Retry-After", "60")
        return TokenValidationResult(
            is_valid=False,
            status_code=429,
            rate_limit=rate_limit,
            rate_remaining=rate_remaining,
            error_message=f"HTTP 429 Too Many Requests: Rate limit exceeded. Retry after {retry_after} seconds.",
        )
    else:
        return TokenValidationResult(
            is_valid=False,
            status_code=response.status_code,
            error_message=f"GitHub API returned unexpected HTTP {response.status_code}.",
        )


def get_stored_token(token_file: Optional[Path] = None) -> Optional[str]:
    """
    Retrieves the GitHub token from the environment or secure local storage.
    Order of precedence:
      1. GITHUB_TOKEN environment variable
      2. Secure local token file (~/.config/envhunter/token with 0600 permissions)
    """
    env_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if env_token:
        return env_token

    target = token_file or TOKEN_FILE
    if target.is_file():
        try:
            # Check file permissions on POSIX systems
            if hasattr(os, "stat"):
                st = os.stat(target)
                mode = st.st_mode & 0o777
                if mode & 0o077 != 0:
                    try:
                        os.chmod(target, FILE_PERMISSIONS)
                    except OSError:
                        pass
            content = target.read_text(encoding="utf-8").strip()
            if content:
                return content
        except OSError:
            return None

    return None


def save_token(
    token: str,
    config_dir: Optional[Path] = None,
    token_file: Optional[Path] = None,
) -> bool:
    """
    Securely saves the token to ~/.config/envhunter/token with 0600 permissions.
    The directory is created with 0700 permissions.
    """
    clean_token = token.strip()
    if not clean_token:
        return False

    target_dir = config_dir or CONFIG_DIR
    target_file = token_file or TOKEN_FILE

    try:
        # Create config directory with 0700 permissions
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(target_dir, DIR_PERMISSIONS)
        except OSError:
            pass

        # Write token file
        target_file.write_text(clean_token, encoding="utf-8")
        try:
            os.chmod(target_file, FILE_PERMISSIONS)
        except OSError:
            pass
        return True
    except OSError:
        return False


def delete_stored_token(token_file: Optional[Path] = None) -> bool:
    """Deletes the locally stored token file if present."""
    target = token_file or TOKEN_FILE
    try:
        if target.exists():
            target.unlink()
        return True
    except OSError:
        return False


def prompt_for_token() -> str:
    """
    Prompts the user interactively for a GitHub token using getpass (hidden input).
    """
    try:
        token = getpass.getpass("Enter GitHub Personal Access Token (hidden): ").strip()
        return token
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
def run_first_time_setup(console: Optional[Console] = None) -> Tuple[str, TokenValidationResult]:
    """
    Executes the interactive first-time setup wizard with step-by-step guidance.
    Returns (valid_token, TokenValidationResult).
    Raises AuthenticationError if cancelled or aborted.
    """
    c = console or Console()
    c.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
    c.print("[bold white]            ENVHUNTER — FIRST-TIME SETUP WIZARD[/bold white]")
    c.print("[dim]        GitHub Personal Access Token Configuration[/dim]")
    c.print("[bold cyan]" + "=" * 60 + "[/bold cyan]\n")

    c.print("[bold yellow]Step 1 — Open GitHub Token Settings[/bold yellow]")
    c.print("  Generate a fine-grained personal access token on GitHub:")
    c.print("  Clickable Link : [bold cyan][link=https://github.com/settings/personal-access-tokens]https://github.com/settings/personal-access-tokens[/link][/bold cyan]")
    c.print("  Plain Text URL : [bold white]https://github.com/settings/personal-access-tokens[/bold white]\n")

    c.print("[bold yellow]Step 2 — Generate a Fine-Grained Token[/bold yellow]")
    c.print("  • [white]Token Name[/white]       : EnvHunter Auditor (or custom name)")
    c.print("  • [white]Expiration[/white]       : 30, 60, or 90 days recommended")
    c.print("  • [white]Repository Access[/white]: [bold green]Public Repositories (read-only)[/bold green]")
    c.print("  • [white]Permissions[/white]      : [bold green]Public repository information only[/bold green]")
    c.print("    [dim]Security Notice: EnvHunter audits public repositories only.[/dim]")
    c.print("    [dim]Do NOT grant repository write access, private repository access, or org admin.[/dim]\n")

    while True:
        c.print("[bold yellow]Step 3 — Enter Your Token[/bold yellow]")
        c.print("  [dim]Input is hidden using getpass and will not appear on screen.[/dim]")
        token_input = prompt_for_token()
        if not token_input:
            raise AuthenticationError("Setup aborted: No token provided.")

        c.print("\n[bold yellow]Step 4 — Validating Token[/bold yellow]")
        c.print("  [dim]Connecting to https://api.github.com/user...[/dim]")
        val_result = validate_github_token(token_input)

        if val_result.is_valid:
            c.print(f"  [bold green][✓] Token valid! Authenticated as: [bold white]{val_result.username}[/bold white][/bold green]")
            c.print(f"  [cyan][i] API Rate Limit: {val_result.rate_remaining}/{val_result.rate_limit} requests remaining.[/cyan]")
            if val_result.rate_reset_utc:
                c.print(f"  [dim]Rate limit reset: {val_result.rate_reset_utc}[/dim]\n")

            c.print("[bold yellow]Step 5 — Save Securely[/bold yellow]")
            c.print(f"  EnvHunter can save your token securely to:")
            c.print(f"    [bold white]{TOKEN_FILE}[/bold white]")
            c.print("  Permissions: [bold green]0600 (owner read/write only)[/bold green], directory [bold green]0700[/bold green].")
            c.print("  [dim]Guaranteed: Never saved in project's .env, source code, SQLite, or Git repo.[/dim]")

            save_choice = input("\nDo you want to securely save this token for future use? [Y/n]: ").strip().lower()
            if save_choice not in ("n", "no"):
                if save_token(token_input):
                    c.print(f"  [bold green][✓] Token securely saved to {TOKEN_FILE} (0600).[/bold green]\n")
                else:
                    c.print(f"  [bold red][!] Warning: Could not write token file. Retained in memory only.[/bold red]\n")
            else:
                c.print("  [dim]Token retained in memory for this session only.[/dim]\n")

            return token_input, val_result
        else:
            c.print(f"  [bold red][✗] Token validation failed: {val_result.error_message}[/bold red]")
            retry = input("\nWould you like to try entering the token again? [Y/n]: ").strip().lower()
            if retry in ("n", "no"):
                raise AuthenticationError(f"Setup aborted: {val_result.error_message}")


def change_token_workflow(
    console: Optional[Console] = None,
    current_token: Optional[str] = None,
) -> Tuple[Optional[str], Optional[TokenValidationResult]]:
    """
    Executes the interactive workflow to change the stored or active GitHub token.
    Preserves the previous valid token if replacement validation fails.
    Returns (new_token_or_current, validation_result_or_None).
    """
    c = console or Console()
    c.print("\n[bold cyan]" + "-" * 56 + "[/bold cyan]")
    c.print("[bold white]            CHANGE GITHUB PERSONAL ACCESS TOKEN[/bold white]")
    c.print("[bold cyan]" + "-" * 56 + "[/bold cyan]")
    c.print("[dim]Your active token remains in use until a replacement validates successfully.[/dim]")
    c.print("[dim]Revocation notice: GitHub token revocation is managed via GitHub settings.[/dim]")
    c.print("[dim]EnvHunter will not revoke your previous token automatically.[/dim]\n")

    new_token = prompt_for_token()
    if not new_token:
        c.print("[yellow][!] Token change aborted. Previous token remains active.[/yellow]")
        return current_token, None

    c.print("[dim]Validating replacement token with api.github.com/user...[/dim]")
    val_result = validate_github_token(new_token)

    if not val_result.is_valid:
        c.print(f"[bold red][✗] Replacement token validation failed: {val_result.error_message}[/bold red]")
        c.print("[yellow][!] Previous token remains active. No changes were made.[/yellow]")
        return current_token, None

    c.print(f"[bold green][✓] Replacement token is valid! Authenticated as: [bold white]{val_result.username}[/bold white][/bold green]")
    c.print(f"[cyan][i] API Quota: {val_result.rate_remaining}/{val_result.rate_limit} requests remaining.[/cyan]")

    replace_choice = input("\nDo you want to save this replacement token to secure storage? [Y/n]: ").strip().lower()
    if replace_choice not in ("n", "no"):
        if save_token(new_token):
            c.print(f"[bold green][✓] Replacement token securely saved to {TOKEN_FILE} (permissions 0600).[/bold green]")
        else:
            c.print("[bold red][!] Warning: Could not write token file. Retained in memory only.[/bold red]")
    else:
        c.print("[dim]Replacement token will be active in memory for this session only.[/dim]")

    return new_token, val_result


def ensure_authenticated_token(
    force_prompt: bool = False,
    allow_interactive: bool = True,
    allow_save: bool = True,
    console: Optional[Console] = None,
) -> Tuple[str, TokenValidationResult]:
    """
    Resolves and validates a token.
    If no valid token is found or force_prompt is True, starts setup wizard.
    Returns (valid_token, TokenValidationResult).
    Raises AuthenticationError if authentication cannot be completed.
    """
    token = None
    if not force_prompt:
        token = get_stored_token()

    if token:
        val_result = validate_github_token(token)
        if val_result.is_valid:
            return token, val_result
        if not allow_interactive:
            raise AuthenticationError(f"Configured token is invalid: {val_result.error_message}")

    if not allow_interactive:
        raise AuthenticationError("No GitHub token found in environment or local storage, and interactive prompts are disabled.")

    # Use first-time setup wizard
    return run_first_time_setup(console=console)

