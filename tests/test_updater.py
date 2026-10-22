"""
Unit tests for EnvHunter safe updater module.
Tests git repository checks, remote validation, dirty tree refusal, and update detection.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from envhunter.updater import (
    UPSTREAM_REPO_HTTPS,
    UPSTREAM_REPO_HTTPS_ALT,
    check_for_updates,
    get_manual_update_instructions,
    is_git_installed,
    is_git_repository,
    is_valid_upstream_remote,
    is_working_tree_dirty,
    perform_safe_update,
)


class TestUpdater(unittest.TestCase):
    """Test suite for update checker and safe Git updater."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _init_git_repo(self, set_upstream: bool = True) -> None:
        """Helper to create a minimal local git repo for testing."""
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(self.repo_dir), check=True, capture_output=True)

        # Create dummy file and commit
        dummy_file = self.repo_dir / "version.txt"
        dummy_file.write_text("1.0.0\n", encoding="utf-8")
        subprocess.run(["git", "add", "version.txt"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_dir), check=True, capture_output=True)

        if set_upstream:
            subprocess.run(["git", "remote", "add", "origin", UPSTREAM_REPO_HTTPS], cwd=str(self.repo_dir), check=True, capture_output=True)

    def test_is_git_repository_false_for_empty_dir(self):
        self.assertFalse(is_git_repository(self.repo_dir))

    def test_is_git_repository_true_for_git_dir(self):
        self._init_git_repo()
        self.assertTrue(is_git_repository(self.repo_dir))

    def test_missing_git_installation(self):
        with patch("envhunter.updater.is_git_installed", return_value=False):
            self.assertFalse(is_git_repository(self.repo_dir))
            res = check_for_updates(repo_dir=self.repo_dir)
            self.assertFalse(res.is_git_repo)

    def test_is_valid_upstream_remote(self):
        self.assertTrue(is_valid_upstream_remote(UPSTREAM_REPO_HTTPS))
        self.assertTrue(is_valid_upstream_remote(UPSTREAM_REPO_HTTPS_ALT))
        self.assertTrue(is_valid_upstream_remote("git@github.com:Shadab-2604/envhunter.git"))
        self.assertFalse(is_valid_upstream_remote("https://github.com/attacker/malicious-repo.git"))
        self.assertFalse(is_valid_upstream_remote(""))
        self.assertFalse(is_valid_upstream_remote(None))

    def test_is_working_tree_dirty(self):
        self._init_git_repo()
        # Clean
        self.assertFalse(is_working_tree_dirty(self.repo_dir))

        # Modify file -> dirty
        (self.repo_dir / "version.txt").write_text("1.0.1-dirty\n", encoding="utf-8")
        self.assertTrue(is_working_tree_dirty(self.repo_dir))

    @patch("envhunter.updater.get_remote_head_commit")
    def test_check_for_updates_already_up_to_date(self, mock_get_remote_head):
        self._init_git_repo()
        # Get local commit
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(self.repo_dir), check=True, capture_output=True, text=True)
        local_sha = res.stdout.strip()
        mock_get_remote_head.return_value = (local_sha, None)

        check_res = check_for_updates(repo_dir=self.repo_dir)
        self.assertTrue(check_res.is_git_repo)
        self.assertTrue(check_res.is_remote_valid)
        self.assertFalse(check_res.is_update_available)
        self.assertEqual(check_res.status_text, "Up to date")

    @patch("envhunter.updater.get_remote_head_commit")
    def test_check_for_updates_newer_available(self, mock_get_remote_head):
        self._init_git_repo()
        remote_sha = "9999999999999999999999999999999999999999"
        mock_get_remote_head.return_value = (remote_sha, None)

        check_res = check_for_updates(repo_dir=self.repo_dir)
        self.assertTrue(check_res.is_git_repo)
        self.assertTrue(check_res.is_remote_valid)
        self.assertTrue(check_res.is_update_available)
        self.assertEqual(check_res.status_text, "Update available")

    def test_perform_safe_update_refuses_when_dirty(self):
        self._init_git_repo()
        (self.repo_dir / "version.txt").write_text("uncommitted changes\n", encoding="utf-8")

        success, msg = perform_safe_update(repo_dir=self.repo_dir)
        self.assertFalse(success)
        self.assertIn("Local uncommitted changes detected", msg)

    def test_perform_safe_update_refuses_when_invalid_remote(self):
        self._init_git_repo(set_upstream=False)
        subprocess.run(["git", "remote", "add", "origin", "https://github.com/random/other.git"], cwd=str(self.repo_dir), check=True, capture_output=True)

        success, msg = perform_safe_update(repo_dir=self.repo_dir)
        self.assertFalse(success)
        self.assertIn("does not match upstream", msg)

    def test_perform_safe_update_refuses_when_not_git_repo(self):
        empty_dir = self.repo_dir / "not_git"
        empty_dir.mkdir()
        success, msg = perform_safe_update(repo_dir=empty_dir)
        self.assertFalse(success)
        self.assertIn("not running from a valid Git repository", msg)

    def test_manual_update_instructions(self):
        instructions = get_manual_update_instructions()
        self.assertIn("git pull --ff-only", instructions)
        self.assertIn("pip install -r requirements.txt", instructions)


if __name__ == "__main__":
    unittest.main()
