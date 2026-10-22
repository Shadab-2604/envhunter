"""
Unit tests for EnvHunter reporter and export formats (CSV, JSON, HTML).
"""

import csv
import json
from pathlib import Path
import tempfile
import unittest

from envhunter.config import SEVERITY_HIGH, STATUS_CURRENTLY_PRESENT
from envhunter.reporter import Reporter


class TestReporter(unittest.TestCase):
    """Tests for report rendering and file exports."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.reporter = Reporter()
        self.sample_findings = [
            {
                "repo_owner": "victimorg",
                "repo_name": "webapp<script>alert(1)</script>",
                "repo_url": "https://github.com/victimorg/webapp",
                "branch_names": "main, staging",
                "file_path": ".env.production",
                "event_type": "added",
                "commit_sha": "1234567890abcdef1234567890abcdef12345678",
                "short_sha": "1234567",
                "commit_url": "https://github.com/victimorg/webapp/commit/1234567",
                "file_url": "https://github.com/victimorg/webapp/blob/1234567890abcdef1234567890abcdef12345678/.env.production",
                "author_name": "Dev <bad>",
                "author_email": "dev@example.com",
                "author_date": "2024-03-01T12:00:00Z",
                "committer_name": "Dev <bad>",
                "committer_email": "dev@example.com",
                "committer_date": "2024-03-01T12:00:00Z",
                "parent_shas": "parent1",
                "current_status": STATUS_CURRENTLY_PRESENT,
                "severity": SEVERITY_HIGH,
                "detection_reason": "Production environment configuration (.env.production)",
                "scan_timestamp": "2024-03-01T12:30:00Z",
                "verification_status": "VERIFIED_AT_HEAD",
            }
        ]
        self.sample_summary = {
            "target_username": "victimorg",
            "scan_mode": "full",
            "status": "COMPLETED",
            "total_repos": 1,
            "completed_repos": 1,
            "total_branches": 2,
            "unique_commits": 10,
            "findings_by_severity": {SEVERITY_HIGH: 1},
            "total_findings": 1,
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_csv(self):
        csv_file = self.reporter.export_csv(
            "victimorg",
            self.sample_findings,
            output_dir=self.temp_dir.name,
        )
        self.assertTrue(csv_file.is_file())

        with open(csv_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["file_path"], ".env.production")
            self.assertEqual(rows[0]["file_url"], "https://github.com/victimorg/webapp/blob/1234567890abcdef1234567890abcdef12345678/.env.production")
            self.assertEqual(rows[0]["severity"], SEVERITY_HIGH)
            self.assertEqual(rows[0]["current_status"], STATUS_CURRENTLY_PRESENT)

    def test_export_json(self):
        json_file = self.reporter.export_json(
            "victimorg",
            self.sample_summary,
            self.sample_findings,
            output_dir=self.temp_dir.name,
        )
        self.assertTrue(json_file.is_file())

        with open(json_file, mode="r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["metadata"]["target_username"], "victimorg")
            self.assertEqual(data["summary"]["total_findings"], 1)
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"][0]["file_path"], ".env.production")
            self.assertEqual(data["findings"][0]["file_url"], "https://github.com/victimorg/webapp/blob/1234567890abcdef1234567890abcdef12345678/.env.production")

    def test_export_html_escapes_xss(self):
        html_file = self.reporter.export_html(
            "victimorg",
            self.sample_summary,
            self.sample_findings,
            output_dir=self.temp_dir.name,
        )
        self.assertTrue(html_file.is_file())

        content = html_file.read_text(encoding="utf-8")
        # Ensure malicious input was escaped
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertIn("Dev &lt;bad&gt;", content)
        self.assertIn("HIGH", content)
        self.assertIn(".env.production", content)
        self.assertIn("View File ↗", content)
        self.assertIn("https://github.com/victimorg/webapp/blob/1234567890abcdef1234567890abcdef12345678/.env.production", content)


if __name__ == "__main__":
    unittest.main()
