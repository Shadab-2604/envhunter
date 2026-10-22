"""
Unit tests for EnvHunter file detectors and classification.
"""

import unittest

from envhunter.config import (
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_MEDIUM,
    SEVERITY_UNKNOWN,
    STATUS_CURRENTLY_PRESENT,
    STATUS_DELETED,
    STATUS_HISTORICAL_ONLY,
    STATUS_INCOMPLETE,
)
from envhunter.detectors import EnvDetector


class TestEnvDetector(unittest.TestCase):
    """Tests for environment file path detection and sample classification."""

    def setUp(self):
        self.detector = EnvDetector()

    def test_standard_env_files(self):
        paths = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.staging",
            ".env.test",
            ".env.backup",
            ".env.production.local",
            "config/.env",
            "backend/src/.env",
            "api/secrets/.env.production",
            ".ENV",
            "server/.Env.Local",
        ]
        for path in paths:
            res = self.detector.classify_path(path)
            self.assertTrue(res.is_match, f"Failed to match: {path}")
            self.assertFalse(res.is_sample, f"Erroneously marked as sample: {path}")

    def test_sample_and_template_files(self):
        samples = [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.default",
            ".env.local.example",
            "config/.env.sample",
            "example.env",
            "sample.env",
        ]
        for path in samples:
            res = self.detector.classify_path(path)
            self.assertTrue(res.is_match, f"Sample file not matched: {path}")
            self.assertTrue(res.is_sample, f"Not classified as sample: {path}")
            self.assertEqual(res.suggested_severity, SEVERITY_INFORMATIONAL)

    def test_benign_non_env_files(self):
        benign = [
            "README.md",
            "package.json",
            "src/index.js",
            "environment.py",
            "env_loader.go",
            "docs/.env_guide.md",
            "Makefile",
        ]
        for path in benign:
            res = self.detector.classify_path(path)
            self.assertFalse(res.is_match, f"Erroneously matched: {path}")

    def test_severity_calculation(self):
        # Sample file is always INFORMATIONAL regardless of status
        self.assertEqual(
            EnvDetector.calculate_severity(is_sample=True, exposure_status=STATUS_CURRENTLY_PRESENT),
            SEVERITY_INFORMATIONAL,
        )

        # Real env file currently present -> HIGH
        self.assertEqual(
            EnvDetector.calculate_severity(is_sample=False, exposure_status=STATUS_CURRENTLY_PRESENT),
            SEVERITY_HIGH,
        )

        # Real env file historical only -> MEDIUM
        self.assertEqual(
            EnvDetector.calculate_severity(is_sample=False, exposure_status=STATUS_HISTORICAL_ONLY),
            SEVERITY_MEDIUM,
        )

        # Real env file deleted from branches -> MEDIUM
        self.assertEqual(
            EnvDetector.calculate_severity(is_sample=False, exposure_status=STATUS_DELETED),
            SEVERITY_MEDIUM,
        )

        # Incomplete scan -> UNKNOWN
        self.assertEqual(
            EnvDetector.calculate_severity(is_sample=False, exposure_status=STATUS_INCOMPLETE),
            SEVERITY_UNKNOWN,
        )


if __name__ == "__main__":
    unittest.main()
