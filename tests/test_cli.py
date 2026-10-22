"""
Unit tests for EnvHunter CLI commands, options, and workflows.
"""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from envhunter.cli import EnvHunterApp, main
from envhunter.config import SEVERITY_HIGH, STATUS_CURRENTLY_PRESENT
from envhunter.database import Database, FindingRecord


class TestCLI(unittest.TestCase):
    """Tests for CLI options and workflows."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "cli_test.db"
        self.app = EnvHunterApp(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("envhunter.cli.ensure_authenticated_token")
    @patch("envhunter.cli.RepositoryScanner")
    @patch("envhunter.cli.HistoryScanner")
    def test_run_scan_flow(self, mock_hist_scanner_cls, mock_repo_scanner_cls, mock_ensure_auth):
        mock_auth_res = MagicMock()
        mock_auth_res.is_valid = True
        mock_auth_res.username = "test_auth_user"
        mock_auth_res.rate_limit = 5000
        mock_auth_res.rate_remaining = 4999
        mock_ensure_auth.return_value = ("ghp_mock_token_123", mock_auth_res)

        mock_repo_scanner = MagicMock()
        mock_repo_scanner.discover_repositories.return_value = [
            {
                "owner": "targetuser",
                "name": "webapp",
                "full_name": "targetuser/webapp",
                "url": "https://github.com/targetuser/webapp",
                "default_branch": "main",
                "is_fork": False,
                "is_archived": False,
                "size_kb": 100,
            }
        ]
        mock_repo_scanner_cls.return_value = mock_repo_scanner

        mock_hist_scanner = MagicMock()
        mock_hist_scanner.scan_repository.return_value = []
        mock_hist_scanner_cls.return_value = mock_hist_scanner

        self.app.run_scan(
            target_username="targetuser",
            token="ghp_mock_token_123",
            export_formats=["csv"],
            output_dir=self.temp_dir.name,
        )

        # Verify scan in database
        latest = self.app.db.get_latest_scan_for_user("targetuser")
        self.assertIsNotNone(latest)
        self.assertEqual(latest["status"], "COMPLETED")

    def test_run_report_export(self):
        # Create scan and finding
        scan_id = "scan-report-test"
        self.app.db.create_scan(scan_id, "testuser", "full")
        finding = FindingRecord(
            scan_id=scan_id,
            repo_owner="testuser",
            repo_name="myrepo",
            repo_url="https://github.com/testuser/myrepo",
            branch_names="main",
            file_path=".env",
            event_type="added",
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            short_sha="abcdef1",
            commit_url="https://github.com/testuser/myrepo/commit/abcdef1",
            author_name="Dev",
            author_email="dev@example.com",
            author_date="2024-01-01T00:00:00Z",
            committer_name="Dev",
            committer_email="dev@example.com",
            committer_date="2024-01-01T00:00:00Z",
            parent_shas="",
            current_status=STATUS_CURRENTLY_PRESENT,
            severity=SEVERITY_HIGH,
            detection_reason="Primary environment configuration file (.env)",
            scan_timestamp="2024-01-01T12:00:00Z",
        )
        self.app.db.save_finding(finding)

        # Run report export
        self.app.run_report_export(
            target_username="testuser",
            export_format="csv",
            output_dir=self.temp_dir.name,
        )

        csv_files = list(Path(self.temp_dir.name).glob("*.csv"))
        self.assertTrue(len(csv_files) >= 1)

    @patch("builtins.input")
    @patch("envhunter.cli.GitHubClient")
    def test_search_github_user(self, mock_client_cls, mock_input):
        mock_client = MagicMock()
        mock_client.get_user.return_value = {
            "login": "octocat",
            "name": "The Octocat",
            "html_url": "https://github.com/octocat",
            "public_repos": 2,
            "bio": "GitHub Mascot",
            "created_at": "2011-01-25T18:44:36Z",
        }
        mock_client.get_user_public_repos.return_value = [
            {
                "name": "Hello-World",
                "default_branch": "master",
                "is_fork": False,
                "is_archived": False,
                "size_kb": 12,
                "url": "https://github.com/octocat/Hello-World",
            }
        ]
        mock_client_cls.return_value = mock_client
        mock_input.side_effect = ["octocat", "n"]  # search octocat, decline audit

        self.app.current_token = "mock_token"
        self.app.run_search_user()

        mock_client.get_user.assert_called_with("octocat")
        mock_client.get_user_public_repos.assert_called_with("octocat", include_forks=True, include_archived=True)

    @patch("builtins.input")
    @patch.object(EnvHunterApp, "run_scan")
    @patch("envhunter.cli.GitHubClient")
    def test_audit_user_wizard(self, mock_client_cls, mock_run_scan, mock_input):
        mock_client = MagicMock()
        mock_client.get_user.return_value = {"login": "targetuser"}
        mock_client_cls.return_value = mock_client
        # target username, depth 1 (full), max repos "", forks "n", archived "n", confirm "y"
        mock_input.side_effect = ["targetuser", "1", "", "n", "n", "y"]

        self.app.current_token = "mock_token"
        self.app.run_audit_user_wizard()

        mock_run_scan.assert_called_once()
        self.assertEqual(mock_run_scan.call_args[1]["target_username"], "targetuser")
        self.assertEqual(mock_run_scan.call_args[1]["scan_mode"], "full")

    @patch("builtins.input")
    @patch("envhunter.auth.prompt_for_token")
    @patch("envhunter.auth.validate_github_token")
    @patch("envhunter.auth.save_token")
    def test_change_token_success(self, mock_save, mock_val, mock_prompt, mock_input):
        mock_prompt.return_value = "new_valid_token"
        mock_val_res = MagicMock()
        mock_val_res.is_valid = True
        mock_val_res.username = "new_user"
        mock_val_res.rate_limit = 5000
        mock_val_res.rate_remaining = 5000
        mock_val.return_value = mock_val_res
        mock_save.return_value = True
        mock_input.return_value = "y"  # save token choice

        self.app.current_token = "old_token"
        self.app.run_change_token()

        self.assertEqual(self.app.current_token, "new_valid_token")
        mock_save.assert_called_with("new_valid_token")

    @patch("envhunter.auth.prompt_for_token")
    @patch("envhunter.auth.validate_github_token")
    def test_change_token_failure_preserves_old(self, mock_val, mock_prompt):
        mock_prompt.return_value = "bad_token"
        mock_val_res = MagicMock()
        mock_val_res.is_valid = False
        mock_val_res.error_message = "Invalid token"
        mock_val.return_value = mock_val_res

        self.app.current_token = "old_valid_token"
        self.app.run_change_token()

        self.assertEqual(self.app.current_token, "old_valid_token")

    @patch("builtins.input")
    def test_run_exit(self, mock_input):
        with self.assertRaises(SystemExit) as cm:
            self.app.run_exit()
        self.assertEqual(cm.exception.code, 0)

    @patch("envhunter.cli.get_stored_token", return_value="existing_token")
    @patch("envhunter.cli.validate_github_token")
    @patch("builtins.input")
    def test_main_menu_exit_option(self, mock_input, mock_val, mock_get_token):
        mock_val_res = MagicMock()
        mock_val_res.is_valid = True
        mock_val_res.username = "menu_tester"
        mock_val.return_value = mock_val_res
        mock_input.side_effect = ["5"]  # Option 5 = exit

        with self.assertRaises(SystemExit) as cm:
            self.app.run_main_menu()
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()

