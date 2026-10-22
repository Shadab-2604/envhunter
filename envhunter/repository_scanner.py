"""
Repository and branch discovery for EnvHunter.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from envhunter.database import Database
from envhunter.github_client import GitHubAPIError, GitHubClient, ResourceNotFoundError


@dataclass
class DiscoveredBranch:
    """Represents a discovered branch and its HEAD snapshot files."""
    branch_id: int
    name: str
    head_sha: str
    current_files: Set[str]


@dataclass
class DiscoveredRepository:
    """Represents a discovered repository with its metadata and branches."""
    repo_id: int
    owner: str
    name: str
    full_name: str
    url: str
    default_branch: str
    is_fork: bool
    is_archived: bool
    size_kb: int
    branches: List[DiscoveredBranch]


class RepositoryScanner:
    """
    Handles discovery of public repositories and branches for a target username.
    """

    def __init__(self, github_client: GitHubClient, database: Database):
        self.client = github_client
        self.db = database

    def discover_repositories(
        self,
        scan_id: str,
        target_username: str,
        include_forks: bool = False,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Queries GitHub API for all public repositories belonging to the target username.
        Persists them in SQLite database.
        """
        if progress_callback:
            progress_callback(f"Discovering public repositories for '{target_username}'...")

        try:
            repos_data = self.client.get_user_public_repos(
                username=target_username,
                include_forks=include_forks,
                include_archived=include_archived,
                max_repos=max_repos,
            )
        except ResourceNotFoundError:
            self.db.record_error(scan_id, None, "USER_NOT_FOUND", f"GitHub user '{target_username}' does not exist.")
            raise
        except GitHubAPIError as e:
            self.db.record_error(scan_id, None, "DISCOVERY_ERROR", str(e))
            raise

        # Save to database
        self.db.save_repositories(scan_id, repos_data)
        all_repos = self.db.get_all_repositories(scan_id)

        if progress_callback:
            progress_callback(f"Discovered {len(all_repos)} public repositories.")

        return all_repos

    def discover_repo_branches(
        self,
        scan_id: str,
        repo: Dict[str, Any],
        fetch_tree_snapshots: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[DiscoveredBranch]:
        """
        Enumerates all branches for a given repository and optionally inspects
        the branch HEAD tree snapshot to determine current files.
        """
        owner = repo["owner"]
        repo_name = repo["name"]
        repo_id = repo["repo_id"]

        if progress_callback:
            progress_callback(f"[{repo['full_name']}] Discovering branches...")

        try:
            branches_api = self.client.get_repo_branches(owner, repo_name)
        except GitHubAPIError as e:
            self.db.record_error(scan_id, repo["full_name"], "BRANCH_ERROR", f"Failed to list branches: {e}")
            branches_api = []

        discovered_branches: List[DiscoveredBranch] = []

        for b in branches_api:
            b_name = b["name"]
            head_sha = b["head_sha"]
            b_id = self.db.save_branch(repo_id, b_name, head_sha)

            current_files: Set[str] = set()
            if fetch_tree_snapshots and head_sha:
                try:
                    current_files = self.client.get_branch_tree_paths(owner, repo_name, head_sha)
                except Exception as e:
                    self.db.record_error(
                        scan_id,
                        repo["full_name"],
                        "TREE_ERROR",
                        f"Failed to fetch tree for branch '{b_name}': {e}",
                    )

            discovered_branches.append(
                DiscoveredBranch(
                    branch_id=b_id,
                    name=b_name,
                    head_sha=head_sha,
                    current_files=current_files,
                )
            )

        return discovered_branches
