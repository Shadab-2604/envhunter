"""
Unit tests for EnvHunter SQLite database persistence, state management, and deduplication.
"""

from pathlib import Path
import tempfile
import unittest

from envhunter.config import (
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    STATUS_CURRENTLY_PRESENT,
    STATUS_HISTORICAL_ONLY,
)
from envhunter.database import Database, FindingRecord


class TestDatabase(unittest.TestCase):
    """Tests for SQLite database schema and operations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_envhunter.db"
        self.db = Database(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_lifecycle(self):
        scan_id = "scan-test-123"
        self.db.create_scan(scan_id, "testuser", "full")

        latest = self.db.get_latest_scan_for_user("testuser")
        self.assertIsNotNone(latest)
        self.assertEqual(latest["scan_id"], scan_id)
        self.assertEqual(latest["status"], "IN_PROGRESS")

        self.db.update_scan_status(scan_id, "COMPLETED", total_repos=3)
        updated = self.db.get_latest_scan_for_user("testuser")
        self.assertEqual(updated["status"], "COMPLETED")
        self.assertIsNotNone(updated["finished_at"])

    def test_repo_management_and_resumability(self):
        scan_id = "scan-test-456"
        self.db.create_scan(scan_id, "testuser", "full")

        repos = [
            {
                "owner": "testuser",
                "name": "repo1",
                "full_name": "testuser/repo1",
                "url": "https://github.com/testuser/repo1",
                "default_branch": "main",
                "is_fork": False,
                "is_archived": False,
                "size_kb": 100,
            },
            {
                "owner": "testuser",
                "name": "repo2",
                "full_name": "testuser/repo2",
                "url": "https://github.com/testuser/repo2",
                "default_branch": "master",
                "is_fork": True,
                "is_archived": False,
                "size_kb": 200,
            },
        ]
        self.db.save_repositories(scan_id, repos)

        pending = self.db.get_pending_repositories(scan_id)
        self.assertEqual(len(pending), 2)

        # Mark repo1 as completed
        self.db.update_repo_status(pending[0]["repo_id"], "COMPLETED")
        pending_after = self.db.get_pending_repositories(scan_id)
        self.assertEqual(len(pending_after), 1)
        self.assertEqual(pending_after[0]["name"], "repo2")

    def test_branch_commit_deduplication(self):
        scan_id = "scan-test-789"
        self.db.create_scan(scan_id, "testuser", "full")
        self.db.save_repositories(
            scan_id,
            [{
                "owner": "testuser",
                "name": "repo1",
                "full_name": "testuser/repo1",
                "url": "https://github.com/testuser/repo1",
                "default_branch": "main",
            }],
        )
        repos = self.db.get_all_repositories(scan_id)
        repo_id = repos[0]["repo_id"]

        # Save branches
        b1_id = self.db.save_branch(repo_id, "main", "sha_head_1")
        b2_id = self.db.save_branch(repo_id, "feature", "sha_head_2")

        # Shared commit between main and feature
        shared_sha = "c0ffee1234567890abcdef1234567890abcdef12"
        self.assertFalse(self.db.commit_exists(shared_sha))

        self.db.record_commit(
            repo_id=repo_id,
            commit_sha=shared_sha,
            short_sha="c0ffee1",
            author_name="Alice",
            author_email="alice@example.com",
            author_date="2024-01-01T00:00:00Z",
            committer_name="Alice",
            committer_email="alice@example.com",
            committer_date="2024-01-01T00:00:00Z",
            parent_shas=[],
            commit_url=f"https://github.com/testuser/repo1/commit/{shared_sha}",
            inspected=True,
        )

        self.assertTrue(self.db.commit_exists(shared_sha))

        # Associate with both branches
        self.db.associate_branch_commit(b1_id, shared_sha)
        self.db.associate_branch_commit(b2_id, shared_sha)

        branches = self.db.get_branches_for_commit(shared_sha)
        self.assertIn("main", branches)
        self.assertIn("feature", branches)
        self.assertEqual(len(branches), 2)

    def test_finding_deduplication(self):
        scan_id = "scan-finding-test"
        self.db.create_scan(scan_id, "testuser", "full")

        finding = FindingRecord(
            scan_id=scan_id,
            repo_owner="testuser",
            repo_name="repo1",
            repo_url="https://github.com/testuser/repo1",
            branch_names="main, dev",
            file_path=".env",
            event_type="added",
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            short_sha="abcdef1",
            commit_url="https://github.com/testuser/repo1/commit/abcdef1",
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

        inserted1 = self.db.save_finding(finding)
        self.assertTrue(inserted1)

        # Duplicate insert should return False and not create a duplicate row
        inserted2 = self.db.save_finding(finding)
        self.assertFalse(inserted2)

        findings = self.db.get_findings_for_scan(scan_id)
        self.assertEqual(len(findings), 1)

    def test_scan_summary(self):
        scan_id = "scan-summary-test"
        self.db.create_scan(scan_id, "testuser", "full")
        self.db.save_repositories(
            scan_id,
            [{
                "owner": "testuser",
                "name": "repo1",
                "full_name": "testuser/repo1",
                "url": "https://github.com/testuser/repo1",
                "default_branch": "main",
            }],
        )
        repos = self.db.get_all_repositories(scan_id)
        self.db.update_repo_status(repos[0]["repo_id"], "COMPLETED")

        finding = FindingRecord(
            scan_id=scan_id,
            repo_owner="testuser",
            repo_name="repo1",
            repo_url="https://github.com/testuser/repo1",
            branch_names="main",
            file_path=".env.backup",
            event_type="added",
            commit_sha="1111222233334444555566667777888899990000",
            short_sha="1111222",
            commit_url="https://github.com/testuser/repo1/commit/1111222",
            author_name="Dev",
            author_email="dev@example.com",
            author_date="2024-01-01T00:00:00Z",
            committer_name="Dev",
            committer_email="dev@example.com",
            committer_date="2024-01-01T00:00:00Z",
            parent_shas="",
            current_status=STATUS_HISTORICAL_ONLY,
            severity=SEVERITY_MEDIUM,
            detection_reason="Backup environment file (.env.backup)",
            scan_timestamp="2024-01-01T12:00:00Z",
        )
        self.db.save_finding(finding)

        summary = self.db.get_scan_summary(scan_id)
        self.assertEqual(summary["total_repos"], 1)
        self.assertEqual(summary["completed_repos"], 1)
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["findings_by_severity"].get(SEVERITY_MEDIUM), 1)


if __name__ == "__main__":
    unittest.main()
