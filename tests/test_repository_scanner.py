"""
Unit tests for EnvHunter repository and branch discovery.
"""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock

from envhunter.database import Database
from envhunter.github_client import GitHubClient
from envhunter.repository_scanner import RepositoryScanner


class TestRepositoryScanner(unittest.TestCase):
    """Tests for discovering repos, branches, and tree snapshots."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp_dir.name) / "test.db")
        self.mock_client = MagicMock(spec=GitHubClient)
        self.scanner = RepositoryScanner(self.mock_client, self.db)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_discover_repositories(self):
        scan_id = "test-scan-disc"
        self.db.create_scan(scan_id, "testuser", "full")

        self.mock_client.get_user_public_repos.return_value = [
            {
                "owner": "testuser",
                "name": "project1",
                "full_name": "testuser/project1",
                "url": "https://github.com/testuser/project1",
                "default_branch": "main",
                "is_fork": False,
                "is_archived": False,
                "size_kb": 120,
            }
        ]

        repos = self.scanner.discover_repositories(scan_id, "testuser")
        self.assertEqual(len(repos), 1)
        self.assertEqual(repos[0]["name"], "project1")

        # Database verification
        db_repos = self.db.get_all_repositories(scan_id)
        self.assertEqual(len(db_repos), 1)
        self.assertEqual(db_repos[0]["full_name"], "testuser/project1")

    def test_discover_repo_branches_with_trees(self):
        scan_id = "test-scan-branches"
        self.db.create_scan(scan_id, "testuser", "full")
        self.db.save_repositories(
            scan_id,
            [{
                "owner": "testuser",
                "name": "project1",
                "full_name": "testuser/project1",
                "url": "https://github.com/testuser/project1",
                "default_branch": "main",
            }],
        )
        repos = self.db.get_all_repositories(scan_id)
        repo = repos[0]

        self.mock_client.get_repo_branches.return_value = [
            {"name": "main", "head_sha": "sha_main_head"},
            {"name": "feature", "head_sha": "sha_feature_head"},
        ]
        self.mock_client.get_branch_tree_paths.side_effect = [
            {".env", "README.md", "package.json"},
            {"README.md"},
        ]

        discovered = self.scanner.discover_repo_branches(scan_id, repo)
        self.assertEqual(len(discovered), 2)
        self.assertEqual(discovered[0].name, "main")
        self.assertIn(".env", discovered[0].current_files)
        self.assertNotIn(".env", discovered[1].current_files)


if __name__ == "__main__":
    unittest.main()
