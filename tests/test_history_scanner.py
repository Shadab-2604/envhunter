"""
Unit tests for EnvHunter history scanner.
Tests both REST API commit history scanning and local Git CLI history inspection.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock

from envhunter.config import (
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_MEDIUM,
    STATUS_CURRENTLY_PRESENT,
    STATUS_DELETED,
    STATUS_HISTORICAL_ONLY,
)
from envhunter.database import Database
from envhunter.detectors import EnvDetector
from envhunter.github_client import GitHubClient
from envhunter.history_scanner import HistoryScanner
from envhunter.repository_scanner import DiscoveredBranch


class TestHistoryScanner(unittest.TestCase):
    """Tests for commit deduplication and exposure status classification."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp_dir.name) / "test.db")
        self.mock_client = MagicMock(spec=GitHubClient)
        self.detector = EnvDetector()
        self.scanner = HistoryScanner(self.mock_client, self.db, self.detector)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_api_history_scan_and_deduplication(self):
        scan_id = "test-hist-scan"
        self.db.create_scan(scan_id, "octocat", "full")
        self.db.save_repositories(
            scan_id,
            [{
                "owner": "octocat",
                "name": "myrepo",
                "full_name": "octocat/myrepo",
                "url": "https://github.com/octocat/myrepo",
                "default_branch": "main",
            }],
        )
        repo = self.db.get_all_repositories(scan_id)[0]

        # Branches: main and dev both have commit_1
        b_main_id = self.db.save_branch(repo["repo_id"], "main", "sha_main")
        b_dev_id = self.db.save_branch(repo["repo_id"], "dev", "sha_dev")

        b_main = DiscoveredBranch(
            branch_id=b_main_id,
            name="main",
            head_sha="sha_main",
            current_files={".env", "README.md"},  # .env is present currently
        )
        b_dev = DiscoveredBranch(
            branch_id=b_dev_id,
            name="dev",
            head_sha="sha_dev",
            current_files={"README.md"},
        )

        shared_commit_sha = "aabbcc112233445566778899aabbcc1122334455"
        self.mock_client.get_branch_commits.side_effect = [
            [{"sha": shared_commit_sha, "short_sha": "aabbcc1"}],  # for main
            [{"sha": shared_commit_sha, "short_sha": "aabbcc1"}],  # for dev
        ]

        self.mock_client.get_commit_detail.return_value = {
            "sha": shared_commit_sha,
            "short_sha": "aabbcc1",
            "author_name": "Dev Alice",
            "author_email": "alice@example.com",
            "author_date": "2024-02-01T10:00:00Z",
            "committer_name": "Dev Alice",
            "committer_email": "alice@example.com",
            "committer_date": "2024-02-01T10:00:00Z",
            "parents": ["parent123"],
            "html_url": f"https://github.com/octocat/myrepo/commit/{shared_commit_sha}",
            "files": [
                {"filename": ".env", "status": "added"},
            ],
        }

        findings = self.scanner.scan_repository(
            scan_id=scan_id,
            repo=repo,
            branches=[b_main, b_dev],
            scan_mode="full",
        )

        # get_commit_detail should be called only ONCE because of deduplication across branches!
        self.assertEqual(self.mock_client.get_commit_detail.call_count, 1)

        # Filter finding corresponding to the historical commit
        hist_findings = [f for f in findings if f.commit_sha == shared_commit_sha]
        self.assertEqual(len(hist_findings), 1)
        self.assertEqual(hist_findings[0].file_path, ".env")
        self.assertIn("blob/aabbcc112233445566778899aabbcc1122334455/.env", hist_findings[0].file_url)
        self.assertEqual(hist_findings[0].current_status, STATUS_CURRENTLY_PRESENT)
        self.assertEqual(hist_findings[0].severity, SEVERITY_HIGH)


class TestLocalGitCLIInspection(unittest.TestCase):
    """
    Integration tests using a real temporary Git repository and Git CLI.
    Tests additions, modifications, renames, deletions, and samples.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name) / "test_git_repo"
        self.repo_dir.mkdir()

        # Initialize git repo and configure user
        subprocess.check_call(["git", "init", "-b", "main"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "config", "user.name", "Test Committer"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "config", "user.email", "committer@example.com"], cwd=str(self.repo_dir))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_git_cli_lifecycle(self):
        # 1. Commit 1: add README
        readme_file = self.repo_dir / "README.md"
        readme_file.write_text("# Test Repo\n", encoding="utf-8")
        subprocess.check_call(["git", "add", "README.md"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_dir))

        # 2. Commit 2: add .env
        env_file = self.repo_dir / ".env"
        env_file.write_text("API_KEY=dummy_value_for_test\n", encoding="utf-8")
        subprocess.check_call(["git", "add", ".env"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "commit", "-m", "Add .env file"], cwd=str(self.repo_dir))

        # 3. Commit 3: modify .env
        env_file.write_text("API_KEY=dummy_value_modified\nDEBUG=true\n", encoding="utf-8")
        subprocess.check_call(["git", "add", ".env"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "commit", "-m", "Update .env config"], cwd=str(self.repo_dir))

        # 4. Commit 4: rename .env to .env.backup
        subprocess.check_call(["git", "mv", ".env", ".env.backup"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "commit", "-m", "Rename .env to .env.backup"], cwd=str(self.repo_dir))

        # 5. Commit 5: delete .env.backup
        backup_file = self.repo_dir / ".env.backup"
        backup_file.unlink()
        subprocess.check_call(["git", "rm", ".env.backup"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "commit", "-m", "Remove .env.backup"], cwd=str(self.repo_dir))

        # 6. Commit 6: add .env.example (sample file)
        sample_file = self.repo_dir / ".env.example"
        sample_file.write_text("API_KEY=your_key_here\n", encoding="utf-8")
        subprocess.check_call(["git", "add", ".env.example"], cwd=str(self.repo_dir))
        subprocess.check_call(["git", "commit", "-m", "Add .env.example"], cwd=str(self.repo_dir))

        # Run inspect_local_git_repo
        findings = HistoryScanner.inspect_local_git_repo(
            repo_path=self.repo_dir,
            scan_id="test-git-cli",
            repo_owner="testuser",
            repo_name="test_git_repo",
            repo_url="https://github.com/testuser/test_git_repo",
        )

        # Inspect results
        paths_found = [f.file_path for f in findings]
        event_types = [f.event_type for f in findings]

        self.assertIn(".env", paths_found)
        self.assertIn(".env.backup", paths_found)
        self.assertIn(".env.example", paths_found)

        # Verify sample file classification
        sample_findings = [f for f in findings if f.file_path == ".env.example"]
        self.assertTrue(len(sample_findings) >= 1)
        self.assertEqual(sample_findings[0].severity, SEVERITY_INFORMATIONAL)

        # Verify historical deletion status of .env.backup
        del_findings = [f for f in findings if f.file_path == ".env.backup" and f.event_type == "deleted"]
        self.assertTrue(len(del_findings) >= 1)
        self.assertEqual(del_findings[0].current_status, STATUS_DELETED)

        # Verify author & committer attribution and exact file_url is captured
        for f in findings:
            self.assertEqual(f.committer_name, "Test Committer")
            self.assertEqual(f.committer_email, "committer@example.com")
            self.assertTrue(len(f.commit_sha) == 40)
            self.assertTrue(f.file_url.startswith("https://github.com/testuser/test_git_repo/blob/"))
            self.assertIn(f.file_path, f.file_url)


if __name__ == "__main__":
    unittest.main()
