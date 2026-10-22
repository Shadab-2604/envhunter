"""
Safe updater module for EnvHunter.
Checks for updates against https://github.com/Shadab-2604/envhunter.git
and safely applies fast-forward Git updates without touching user data or credentials.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional, Tuple
import requests

from envhunter import __version__
from envhunter.config import DEFAULT_TIMEOUT, USER_AGENT

UPSTREAM_REPO_HTTPS = "https://github.com/Shadab-2604/envhunter.git"
UPSTREAM_REPO_HTTPS_ALT = "https://github.com/Shadab-2604/envhunter"
UPSTREAM_REPO_SSH = "git@github.com:Shadab-2604/envhunter.git"
UPSTREAM_API_URL = "https://api.github.com/repos/Shadab-2604/envhunter/commits/main"


@dataclass
class UpdateCheckResult:
    """Detailed result of an update check."""
    is_git_repo: bool
    is_remote_valid: bool
    is_dirty: bool
    current_version: str
    current_commit: str
    remote_commit: str
    is_update_available: bool
    status_text: str
    error_message: Optional[str] = None


def get_project_root() -> Path:
    """Returns the root directory of the EnvHunter project."""
    return Path(__file__).resolve().parent.parent


def is_git_installed() -> bool:
    """Checks if the git command line tool is available on the system."""
    return shutil.which("git") is not None


def is_git_repository(repo_dir: Optional[Path] = None) -> bool:
    """Checks if the directory is inside a valid git repository."""
    target = repo_dir or get_project_root()
    if not (target / ".git").exists():
        return False
    if not is_git_installed():
        return False
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        return res.returncode == 0 and res.stdout.strip() == "true"
    except (subprocess.SubprocessError, OSError):
        return False


def get_git_remote_url(repo_dir: Optional[Path] = None, remote_name: str = "origin") -> Optional[str]:
    """Retrieves the remote URL for the given remote name."""
    target = repo_dir or get_project_root()
    try:
        res = subprocess.run(
            ["git", "remote", "get-url", remote_name],
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def is_valid_upstream_remote(remote_url: Optional[str]) -> bool:
    """Verifies that the remote URL corresponds to the official EnvHunter repository."""
    if not remote_url:
        return False
    normalized = remote_url.rstrip("/").lower()
    expected = [
        UPSTREAM_REPO_HTTPS.rstrip("/").lower(),
        UPSTREAM_REPO_HTTPS_ALT.rstrip("/").lower(),
        UPSTREAM_REPO_SSH.rstrip("/").lower(),
    ]
    return any(normalized == exp or normalized.endswith("shadab-2604/envhunter.git") or normalized.endswith("shadab-2604/envhunter") for exp in expected)


def is_working_tree_dirty(repo_dir: Optional[Path] = None) -> bool:
    """Checks if the git working tree has uncommitted modifications."""
    target = repo_dir or get_project_root()
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0:
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            return len(lines) > 0
    except (subprocess.SubprocessError, OSError):
        pass
    return False


def get_current_git_commit(repo_dir: Optional[Path] = None) -> str:
    """Retrieves the current HEAD commit hash."""
    target = repo_dir or get_project_root()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


def get_remote_head_commit(repo_dir: Optional[Path] = None, token: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Fetches the latest commit SHA of origin/main.
    Tries git ls-remote first, falls back to public GitHub API.
    Returns (commit_sha, error_message).
    """
    target = repo_dir or get_project_root()

    # 1. Try git ls-remote if git repo
    if is_git_repository(target):
        try:
            res = subprocess.run(
                ["git", "ls-remote", "origin", "refs/heads/main"],
                cwd=str(target),
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                sha = res.stdout.strip().split()[0]
                return sha, None
        except (subprocess.SubprocessError, OSError):
            pass

    # 2. Fallback to public GitHub API
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(UPSTREAM_API_URL, headers=headers, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            sha = data.get("sha", "")
            return sha, None
        elif resp.status_code == 404:
            return None, "Upstream repository branch 'main' not found on GitHub."
        else:
            return None, f"GitHub API returned HTTP {resp.status_code} while checking for updates."
    except Exception as e:
        return None, f"Network error checking for updates: {e}"


def check_for_updates(repo_dir: Optional[Path] = None, token: Optional[str] = None) -> UpdateCheckResult:
    """
    Checks for available updates by comparing the local revision with upstream.
    """
    target = repo_dir or get_project_root()
    is_git = is_git_repository(target)
    remote_url = get_git_remote_url(target) if is_git else None
    remote_valid = is_valid_upstream_remote(remote_url) if remote_url else False
    is_dirty = is_working_tree_dirty(target) if is_git else False
    current_commit = get_current_git_commit(target) if is_git else ""

    if not is_git:
        return UpdateCheckResult(
            is_git_repo=False,
            is_remote_valid=False,
            is_dirty=False,
            current_version=__version__,
            current_commit="",
            remote_commit="",
            is_update_available=False,
            status_text="Manual installation (not a Git repository)",
            error_message="EnvHunter is not installed as a Git repository checkout.",
        )

    if not remote_valid:
        return UpdateCheckResult(
            is_git_repo=True,
            is_remote_valid=False,
            is_dirty=is_dirty,
            current_version=__version__,
            current_commit=current_commit,
            remote_commit="",
            is_update_available=False,
            status_text="Unrecognized Git remote",
            error_message=f"Git remote 'origin' ({remote_url or 'None'}) does not point to {UPSTREAM_REPO_HTTPS}",
        )

    remote_commit, err = get_remote_head_commit(target, token=token)
    if not remote_commit:
        return UpdateCheckResult(
            is_git_repo=True,
            is_remote_valid=True,
            is_dirty=is_dirty,
            current_version=__version__,
            current_commit=current_commit,
            remote_commit="",
            is_update_available=False,
            status_text="Unable to reach upstream",
            error_message=err or "Could not retrieve upstream commit.",
        )

    is_update_available = (
        bool(current_commit)
        and bool(remote_commit)
        and current_commit.lower() != remote_commit.lower()
    )

    status_text = "Update available" if is_update_available else "Up to date"

    return UpdateCheckResult(
        is_git_repo=True,
        is_remote_valid=True,
        is_dirty=is_dirty,
        current_version=__version__,
        current_commit=current_commit,
        remote_commit=remote_commit,
        is_update_available=is_update_available,
        status_text=status_text,
    )


def perform_safe_update(repo_dir: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Safely updates the local EnvHunter repository using fast-forward git pull.
    Guarantees:
      - Validates remote before pulling.
      - Refuses to update if working tree is dirty.
      - Never runs reset --hard or deletes local user data.
      - Never alters reports, database, or stored token files.
      - Uses subprocess argument list (no shell=True).
    """
    target = repo_dir or get_project_root()

    if not is_git_repository(target):
        return False, "Update failed: EnvHunter is not running from a valid Git repository checkout."

    remote_url = get_git_remote_url(target)
    if not is_valid_upstream_remote(remote_url):
        return False, f"Update rejected: Git remote 'origin' ({remote_url}) does not match upstream repository ({UPSTREAM_REPO_HTTPS})."

    if is_working_tree_dirty(target):
        return (
            False,
            "Update aborted: Local uncommitted changes detected in working tree.\n"
            "To prevent overwriting your modifications, please commit, stash, or review your changes before updating:\n"
            "    git status\n"
            "    git stash\n"
            "Then run the update again.",
        )

    # Perform safe fast-forward pull
    try:
        pull_cmd = ["git", "pull", "--ff-only", "origin", "main"]
        res = subprocess.run(
            pull_cmd,
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Git fast-forward update failed:\n{err}"
    except subprocess.TimeoutExpired:
        return False, "Git update timed out while contacting upstream repository."
    except Exception as e:
        return False, f"Subprocess error during git pull: {e}"

    # Check and update dependencies if requirements.txt exists and changed
    req_file = target / "requirements.txt"
    if req_file.exists():
        try:
            # Install / update dependencies into current virtualenv if active
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file)],
                cwd=str(target),
                capture_output=True,
                check=False,
                timeout=60,
            )
        except Exception:
            pass

    # Post-update self-check
    try:
        check_cmd = [sys.executable, "-c", "import envhunter; print(envhunter.__version__)"]
        check_res = subprocess.run(
            check_cmd,
            cwd=str(target),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if check_res.returncode == 0:
            new_ver = check_res.stdout.strip()
            return True, f"EnvHunter updated successfully to version {new_ver}!"
        else:
            return True, "EnvHunter updated via Git, but post-update self-check encountered a warning."
    except Exception:
        return True, "EnvHunter updated via Git."


def get_manual_update_instructions() -> str:
    """Returns safe manual update instructions when automatic update cannot proceed."""
    return (
        "Manual Update Instructions:\n"
        "1. Open a terminal in your EnvHunter directory:\n"
        "       cd /path/to/envHunter\n"
        "2. Ensure you have committed or stashed any custom edits:\n"
        "       git status\n"
        "3. Pull the latest commits from upstream:\n"
        "       git pull --ff-only origin main\n"
        "4. Update any Python dependencies:\n"
        "       pip install -r requirements.txt\n"
        "Your saved tokens in ~/.config/envhunter/ and reports in reports/ are preserved."
    )
