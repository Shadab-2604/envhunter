"""
Unit tests for EnvHunter GitHub REST API client.
Uses mocked requests; does not make real network requests.
"""

import unittest
from unittest.mock import MagicMock, patch
import requests

from envhunter.github_client import (
    GitHubAPIError,
    GitHubClient,
    RateLimitExceeded,
    ResourceNotFoundError,
)


class TestGitHubClient(unittest.TestCase):
    """Tests for GitHubClient methods, pagination, and rate limit handling."""

    def setUp(self):
        self.client = GitHubClient(token="ghp_mocktesttoken12345678901234567890")

    @patch.object(requests.Session, "request")
    def test_get_user_public_repos_pagination_and_filtering(self, mock_request):
        # Mock 2 pages of repositories
        page1_repos = [
            {
                "name": "repo1",
                "full_name": "octocat/repo1",
                "html_url": "https://github.com/octocat/repo1",
                "owner": {"login": "octocat"},
                "fork": False,
                "archived": False,
                "private": False,
                "default_branch": "main",
                "size": 50,
            },
            {
                "name": "repo-forked",
                "full_name": "octocat/repo-forked",
                "html_url": "https://github.com/octocat/repo-forked",
                "owner": {"login": "octocat"},
                "fork": True,
                "archived": False,
                "private": False,
                "default_branch": "main",
                "size": 120,
            },
        ]
        page2_repos = [
            {
                "name": "repo-archived",
                "full_name": "octocat/repo-archived",
                "html_url": "https://github.com/octocat/repo-archived",
                "owner": {"login": "octocat"},
                "fork": False,
                "archived": True,
                "private": False,
                "default_branch": "master",
                "size": 80,
            },
        ]

        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.json.return_value = page1_repos
        resp1.headers = {
            "Link": '<https://api.github.com/users/octocat/repos?page=2>; rel="next"',
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4990",
        }

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.json.return_value = page2_repos
        resp2.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4989",
        }

        mock_request.side_effect = [resp1, resp2]

        # Default filter: no forks, no archived
        repos = self.client.get_user_public_repos("octocat", include_forks=False, include_archived=False)
        self.assertEqual(len(repos), 1)
        self.assertEqual(repos[0]["name"], "repo1")

    @patch.object(requests.Session, "request")
    def test_get_repo_branches(self, mock_request):
        branches_data = [
            {"name": "main", "commit": {"sha": "sha_main_123"}},
            {"name": "dev", "commit": {"sha": "sha_dev_456"}},
        ]
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = branches_data
        resp.headers = {"X-RateLimit-Remaining": "4950"}
        mock_request.return_value = resp

        branches = self.client.get_repo_branches("octocat", "repo1")
        self.assertEqual(len(branches), 2)
        self.assertEqual(branches[0]["name"], "main")
        self.assertEqual(branches[0]["head_sha"], "sha_main_123")
        self.assertEqual(branches[1]["name"], "dev")

    @patch.object(requests.Session, "request")
    def test_get_commit_detail(self, mock_request):
        commit_data = {
            "sha": "1234567890abcdef1234567890abcdef12345678",
            "commit": {
                "author": {"name": "Alice", "email": "alice@example.com", "date": "2024-01-01T10:00:00Z"},
                "committer": {"name": "Bob", "email": "bob@example.com", "date": "2024-01-01T11:00:00Z"},
            },
            "parents": [{"sha": "parentsha123"}],
            "html_url": "https://github.com/octocat/repo1/commit/1234567890abcdef1234567890abcdef12345678",
            "files": [
                {"filename": ".env", "status": "added"},
                {"filename": "README.md", "status": "modified"},
            ],
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = commit_data
        resp.headers = {"X-RateLimit-Remaining": "4900"}
        mock_request.return_value = resp

        detail = self.client.get_commit_detail("octocat", "repo1", "1234567890abcdef1234567890abcdef12345678")
        self.assertEqual(detail["author_name"], "Alice")
        self.assertEqual(detail["committer_name"], "Bob")
        self.assertEqual(len(detail["files"]), 2)
        self.assertEqual(detail["files"][0]["filename"], ".env")
        self.assertEqual(detail["files"][0]["status"], "added")

    @patch.object(requests.Session, "request")
    def test_rate_limit_exceeded(self, mock_request):
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "API rate limit exceeded for user ID"
        resp.headers = {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1730000000",
            "Retry-After": "120",
        }
        mock_request.return_value = resp

        with self.assertRaises(RateLimitExceeded):
            self.client.request("GET", "users/octocat", max_rate_wait_seconds=5)

    @patch.object(requests.Session, "request")
    def test_resource_not_found_404(self, mock_request):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        mock_request.return_value = resp

        with self.assertRaises(ResourceNotFoundError):
            self.client.request("GET", "users/nonexistentuser999")


if __name__ == "__main__":
    unittest.main()
