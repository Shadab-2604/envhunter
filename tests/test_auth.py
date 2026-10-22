"""
Unit tests for EnvHunter authentication and token validation.
Uses mocked HTTP requests and temporary files; never touches real API credentials.
"""

import os
from pathlib import Path
import stat
import unittest
from unittest.mock import MagicMock, patch
import requests

from envhunter.auth import (
    AuthenticationError,
    TokenValidationResult,
    delete_stored_token,
    ensure_authenticated_token,
    get_stored_token,
    save_token,
    validate_github_token,
)
from envhunter.config import redact_token


class TestAuthValidation(unittest.TestCase):
    """Tests for validate_github_token and error handling."""

    @patch("requests.get")
    def test_valid_token(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"login": "octocat", "id": 1}
        mock_resp.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": "1730000000",
            "X-OAuth-Scopes": "public_repo",
        }
        mock_get.return_value = mock_resp

        res = validate_github_token("ghp_validtokentest12345678901234567890")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.username, "octocat")
        self.assertEqual(res.rate_limit, 5000)
        self.assertEqual(res.rate_remaining, 4999)
        self.assertIn("UTC", str(res.rate_reset_utc) or "")

    @patch("requests.get")
    def test_invalid_token_401(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "50"}
        mock_get.return_value = mock_resp

        res = validate_github_token("ghp_badtoken123")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status_code, 401)
        self.assertIn("401", res.error_message or "")

    @patch("requests.get")
    def test_forbidden_rate_limit_403(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1730000000",
            "Retry-After": "120",
        }
        mock_get.return_value = mock_resp

        res = validate_github_token("ghp_testtoken123")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status_code, 403)
        self.assertIn("Retry after 120", res.error_message or "")

    @patch("requests.get")
    def test_too_many_requests_429(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.headers = {"Retry-After": "45"}
        mock_get.return_value = mock_resp

        res = validate_github_token("ghp_testtoken123")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status_code, 429)
        self.assertIn("45 seconds", res.error_message or "")

    @patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused"))
    def test_connection_error(self, mock_get):
        res = validate_github_token("ghp_testtoken123")
        self.assertFalse(res.is_valid)
        self.assertIn("Network connection error", res.error_message or "")

    def test_empty_token(self):
        res = validate_github_token("   ")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status_code, 400)


class TestTokenStorage(unittest.TestCase):
    """Tests for secure token storage and permissions."""

    def setUp(self):
        self.test_dir = Path("/tmp/envhunter_test_auth")
        if self.test_dir.exists():
            for f in self.test_dir.glob("*"):
                f.unlink()
            self.test_dir.rmdir()
        self.test_token_path = self.test_dir / "token"

    def tearDown(self):
        if self.test_dir.exists():
            for f in self.test_dir.glob("*"):
                f.unlink()
            self.test_dir.rmdir()

    def test_save_and_get_token(self):
        # Test save
        success = save_token(
            "test_secret_token_123",
            config_dir=self.test_dir,
            token_file=self.test_token_path,
        )
        self.assertTrue(success)
        self.assertTrue(self.test_token_path.is_file())

        # Check permissions (0600)
        mode = stat.S_IMODE(os.stat(self.test_token_path).st_mode)
        self.assertEqual(mode, 0o600)

        # Check dir permissions (0700)
        dir_mode = stat.S_IMODE(os.stat(self.test_dir).st_mode)
        self.assertEqual(dir_mode, 0o700)

        # Test get stored
        with patch.dict(os.environ, {}, clear=True):
            loaded = get_stored_token(token_file=self.test_token_path)
            self.assertEqual(loaded, "test_secret_token_123")

        # Test delete
        delete_stored_token(token_file=self.test_token_path)
        self.assertFalse(self.test_token_path.exists())

    def test_env_var_precedence(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_from_environment_var"}):
            self.assertEqual(get_stored_token(), "ghp_from_environment_var")


class TestRedaction(unittest.TestCase):
    """Tests for token redaction."""

    def test_redact_github_pat(self):
        raw = "Error authenticating with token ghp_ABC123456789012345678901234567890xyz and bearer 1234567890123456789012"
        redacted = redact_token(raw)
        self.assertNotIn("ghp_ABC123456789012345678901234567890xyz", redacted)
        self.assertIn("[REDACTED_CREDENTIAL]", redacted)

    def test_redact_custom_token(self):
        token = "my_custom_secret_val_9988"
        raw = f"Exception occurred with {token} while fetching repo"
        redacted = redact_token(raw, token)
        self.assertNotIn(token, redacted)
        self.assertIn("[REDACTED_TOKEN]", redacted)


if __name__ == "__main__":
    unittest.main()
