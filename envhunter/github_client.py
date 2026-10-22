"""
GitHub REST API v3 client with connection reuse, pagination, and rate-limit handling.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import random
import time
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from envhunter.config import (
    API_PER_PAGE,
    DEFAULT_TIMEOUT,
    GITHUB_API_BASE,
    INITIAL_BACKOFF_SECONDS,
    MAX_BACKOFF_SECONDS,
    MAX_RETRIES,
    USER_AGENT,
    redact_token,
)


class GitHubAPIError(Exception):
    """Base exception for GitHub API errors."""
    def __init__(self, message: str, status_code: int = 0, response: Optional[requests.Response] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class RateLimitExceeded(GitHubAPIError):
    """Raised when GitHub API rate limit is exceeded and cannot be retried immediately."""
    def __init__(self, message: str, reset_timestamp: Optional[int] = None, retry_after: Optional[int] = None):
        super().__init__(message, status_code=403)
        self.reset_timestamp = reset_timestamp
        self.retry_after = retry_after


class ResourceNotFoundError(GitHubAPIError):
    """Raised when a repository or user is not found (HTTP 404)."""
    pass


@dataclass
class RateLimitStatus:
    """Current rate limit status from response headers."""
    limit: int
    remaining: int
    reset_epoch: int
    reset_utc: str
    used: int


class GitHubClient:
    """
    Client for interacting with the GitHub REST API v3.
    Enforces security boundaries: public data only, no secret exfiltration.
    """

    def __init__(self, token: Optional[str] = None):
        self.token = token.strip() if token else None
        self.session = requests.Session()

        # Configure connection pool with retry for connection drops
        retries = Retry(
            total=MAX_RETRIES,
            backoff_factor=INITIAL_BACKOFF_SECONDS,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Standard headers
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": USER_AGENT,
        })
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"

        self.last_rate_limit: Optional[RateLimitStatus] = None

    def _update_rate_limit_from_headers(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Extracts and stores rate limit status from response headers."""
        limit = int(headers.get("X-RateLimit-Limit", 0))
        remaining = int(headers.get("X-RateLimit-Remaining", 0))
        reset_epoch = int(headers.get("X-RateLimit-Reset", 0))
        used = int(headers.get("X-RateLimit-Used", 0))

        reset_utc = ""
        if reset_epoch > 0:
            try:
                reset_utc = datetime.fromtimestamp(reset_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError):
                reset_utc = str(reset_epoch)

        if limit > 0:
            self.last_rate_limit = RateLimitStatus(
                limit=limit,
                remaining=remaining,
                reset_epoch=reset_epoch,
                reset_utc=reset_utc,
                used=used,
            )

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        max_rate_wait_seconds: int = 60,
    ) -> requests.Response:
        """
        Executes an HTTP request to the GitHub REST API with rate limit monitoring,
        jittered backoff, and error sanitization.
        """
        url = endpoint if endpoint.startswith("http") else f"{GITHUB_API_BASE}/{endpoint.lstrip('/')}"
        retries = 0

        while retries <= MAX_RETRIES:
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    timeout=DEFAULT_TIMEOUT,
                )
            except requests.exceptions.RequestException as e:
                sanitized = redact_token(str(e), self.token)
                if retries >= MAX_RETRIES:
                    raise GitHubAPIError(f"Network error: {sanitized}")
                retries += 1
                backoff = min(MAX_BACKOFF_SECONDS, (INITIAL_BACKOFF_SECONDS * (2 ** retries)) + random.uniform(0.1, 0.5))
                time.sleep(backoff)
                continue

            self._update_rate_limit_from_headers(response.headers)

            # Success
            if response.status_code in (200, 201, 204):
                return response

            # 404 Not Found
            if response.status_code == 404:
                raise ResourceNotFoundError(f"Resource not found: {endpoint}", status_code=404, response=response)

            # Rate Limit or Secondary Rate Limit (403 or 429)
            if response.status_code in (403, 429):
                retry_after_hdr = response.headers.get("Retry-After")
                rate_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
                reset_epoch = int(response.headers.get("X-RateLimit-Reset", 0))

                wait_seconds = 0
                if retry_after_hdr:
                    try:
                        wait_seconds = int(retry_after_hdr)
                    except ValueError:
                        wait_seconds = 60
                elif rate_remaining == 0 and reset_epoch > 0:
                    current_epoch = int(time.time())
                    wait_seconds = max(1, reset_epoch - current_epoch)

                # Check if it's a rate limit issue vs a permission issue
                resp_text = response.text.lower()
                is_rate_limit = (
                    "rate limit" in resp_text
                    or "secondary rate limit" in resp_text
                    or response.status_code == 429
                    or rate_remaining == 0
                )

                if is_rate_limit:
                    if 0 < wait_seconds <= max_rate_wait_seconds:
                        time.sleep(wait_seconds + random.uniform(0.5, 1.5))
                        retries += 1
                        continue
                    else:
                        raise RateLimitExceeded(
                            f"GitHub API rate limit exceeded. Retry after {wait_seconds} seconds.",
                            reset_timestamp=reset_epoch,
                            retry_after=wait_seconds,
                        )
                else:
                    sanitized_msg = redact_token(response.text[:200], self.token)
                    raise GitHubAPIError(f"HTTP 403 Forbidden: {sanitized_msg}", status_code=403, response=response)

            # 401 Unauthorized
            if response.status_code == 401:
                raise GitHubAPIError("HTTP 401 Unauthorized: Invalid or expired GitHub token.", status_code=401)

            # Server errors (5xx)
            if response.status_code in (500, 502, 503, 504):
                retries += 1
                if retries > MAX_RETRIES:
                    raise GitHubAPIError(f"GitHub server error: HTTP {response.status_code}", status_code=response.status_code)
                backoff = min(MAX_BACKOFF_SECONDS, (INITIAL_BACKOFF_SECONDS * (2 ** retries)) + random.uniform(0.1, 0.5))
                time.sleep(backoff)
                continue

            # Other permanent client errors
            sanitized_msg = redact_token(response.text[:200], self.token)
            raise GitHubAPIError(f"HTTP {response.status_code}: {sanitized_msg}", status_code=response.status_code)

        raise GitHubAPIError(f"Failed request to {endpoint} after {MAX_RETRIES} retries.")

    def paginate(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Paginates through GitHub API endpoints yielding each item.
        Handles both GitHub 'Link: <url>; rel="next"' headers and numeric page increments.
        """
        request_params = dict(params or {})
        request_params.setdefault("per_page", API_PER_PAGE)
        current_page = request_params.get("page", 1)

        while True:
            request_params["page"] = current_page
            resp = self.request("GET", endpoint, params=request_params)
            items = resp.json()

            if not items or not isinstance(items, list):
                break

            for item in items:
                yield item

            # Check Link header
            link_hdr = resp.headers.get("Link", "")
            has_next = 'rel="next"' in link_hdr

            if len(items) < request_params["per_page"] and not has_next:
                break

            if has_next:
                # Can increment page
                current_page += 1
            elif len(items) == request_params["per_page"]:
                current_page += 1
            else:
                break

    # --- Public API Domain Methods ---

    def get_user(self, username: Optional[str] = None) -> Dict[str, Any]:
        """Fetches public user profile information."""
        endpoint = f"users/{username}" if username else "user"
        return self.request("GET", endpoint).json()

    def get_user_public_repos(
        self,
        username: str,
        include_forks: bool = False,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Discovers all public repositories for a username using pagination.
        Filters forks and archived repositories according to parameters.
        """
        endpoint = f"users/{username}/repos"
        repos: List[Dict[str, Any]] = []

        for repo_data in self.paginate(endpoint, params={"type": "public"}):
            # Enforce public repositories only
            if repo_data.get("private", False):
                continue

            is_fork = repo_data.get("fork", False)
            is_archived = repo_data.get("archived", False)

            if is_fork and not include_forks:
                continue
            if is_archived and not include_archived:
                continue

            owner = repo_data.get("owner", {}).get("login", username)
            repo_name = repo_data.get("name", "")
            full_name = repo_data.get("full_name", f"{owner}/{repo_name}")
            html_url = repo_data.get("html_url", f"https://github.com/{full_name}")
            default_branch = repo_data.get("default_branch", "main")
            size_kb = repo_data.get("size", 0)

            repos.append({
                "owner": owner,
                "name": repo_name,
                "full_name": full_name,
                "url": html_url,
                "default_branch": default_branch,
                "is_fork": is_fork,
                "is_archived": is_archived,
                "size_kb": size_kb,
            })

            if max_repos and len(repos) >= max_repos:
                break

        return repos

    def get_repo_branches(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Enumerates all branches for a repository, handling pagination."""
        endpoint = f"repos/{owner}/{repo}/branches"
        branches: List[Dict[str, Any]] = []

        for b in self.paginate(endpoint):
            name = b.get("name", "")
            head_sha = b.get("commit", {}).get("sha", "")
            if name and head_sha:
                branches.append({"name": name, "head_sha": head_sha})

        return branches

    def get_branch_commits(
        self,
        owner: str,
        repo: str,
        sha: str,
        max_commits: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Enumerates commit history reachable from a branch head SHA.
        """
        endpoint = f"repos/{owner}/{repo}/commits"
        commits: List[Dict[str, Any]] = []

        for c in self.paginate(endpoint, params={"sha": sha}):
            commit_sha = c.get("sha")
            if not commit_sha:
                continue

            commit_info = c.get("commit", {})
            author_info = commit_info.get("author", {})
            committer_info = commit_info.get("committer", {})
            parents = [p.get("sha") for p in c.get("parents", []) if p.get("sha")]

            commits.append({
                "sha": commit_sha,
                "short_sha": commit_sha[:7],
                "author_name": author_info.get("name", ""),
                "author_email": author_info.get("email", ""),
                "author_date": author_info.get("date", ""),
                "committer_name": committer_info.get("name", ""),
                "committer_email": committer_info.get("email", ""),
                "committer_date": committer_info.get("date", ""),
                "parents": parents,
                "html_url": c.get("html_url", f"https://github.com/{owner}/{repo}/commit/{commit_sha}"),
            })

            if max_commits and len(commits) >= max_commits:
                break

        return commits

    def get_commit_detail(self, owner: str, repo: str, commit_sha: str) -> Dict[str, Any]:
        """
        Fetches commit metadata including the list of changed files and event types.
        """
        endpoint = f"repos/{owner}/{repo}/commits/{commit_sha}"
        resp = self.request("GET", endpoint)
        data = resp.json()

        files: List[Dict[str, Any]] = []
        for f in data.get("files", []):
            files.append({
                "filename": f.get("filename", ""),
                "status": f.get("status", "modified"),  # added, modified, removed, renamed
                "previous_filename": f.get("previous_filename"),
            })

        commit_info = data.get("commit", {})
        author_info = commit_info.get("author", {})
        committer_info = commit_info.get("committer", {})
        parents = [p.get("sha") for p in data.get("parents", []) if p.get("sha")]

        return {
            "sha": commit_sha,
            "short_sha": commit_sha[:7],
            "author_name": author_info.get("name", ""),
            "author_email": author_info.get("email", ""),
            "author_date": author_info.get("date", ""),
            "committer_name": committer_info.get("name", ""),
            "committer_email": committer_info.get("email", ""),
            "committer_date": committer_info.get("date", ""),
            "parents": parents,
            "html_url": data.get("html_url", f"https://github.com/{owner}/{repo}/commit/{commit_sha}"),
            "files": files,
        }

    def get_branch_tree_paths(self, owner: str, repo: str, tree_sha: str) -> Set[str]:
        """
        Efficiently fetches all file paths in a branch HEAD commit tree snapshot
        using the recursive Git Trees API.
        """
        endpoint = f"repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1"
        try:
            resp = self.request("GET", endpoint)
            tree_data = resp.json()
            paths = set()
            for item in tree_data.get("tree", []):
                if item.get("type") == "blob":
                    paths.add(item.get("path", ""))
            return paths
        except GitHubAPIError:
            # If tree is too large or fails, return empty set (will fall back to other checks)
            return set()
