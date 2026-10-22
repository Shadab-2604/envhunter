"""
Automated security and pre-push verification tests for EnvHunter.
Verifies gitignore exclusions, safe .env.example placeholders, and absence of hardcoded secrets.
"""

from pathlib import Path
import re
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
GITIGNORE_FILE = ROOT_DIR / ".gitignore"
ENV_EXAMPLE_FILE = ROOT_DIR / ".env.example"


class TestSecuritySafeguards(unittest.TestCase):
    """Verifies that sensitive files, tokens, and databases are strictly excluded."""

    def test_gitignore_exists_and_covers_sensitive_files(self):
        self.assertTrue(GITIGNORE_FILE.exists(), ".gitignore file must exist")
        content = GITIGNORE_FILE.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]

        # Mandatory ignore patterns
        self.assertIn(".env", lines)
        self.assertIn(".env.*", lines)
        self.assertIn("!.env.example", lines)
        self.assertIn(".venv/", lines)
        self.assertIn("venv/", lines)
        self.assertIn("__pycache__/", lines)
        self.assertIn("*.db", lines)
        self.assertIn("*.sqlite", lines)
        self.assertIn("reports/", lines)

    def test_env_example_contains_only_placeholders(self):
        self.assertTrue(ENV_EXAMPLE_FILE.exists(), ".env.example must exist")
        content = ENV_EXAMPLE_FILE.read_text(encoding="utf-8")

        # Must not contain real GitHub PATs
        pat_pattern = re.compile(r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})")
        self.assertIsNone(pat_pattern.search(content), "Real GitHub token found in .env.example!")

        # Must contain safe placeholder
        self.assertIn("your_github_personal_access_token_here", content)

    def test_production_code_and_docs_have_no_hardcoded_pats(self):
        """Scans all production python files and documentation for accidentally embedded secrets."""
        pat_pattern = re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b")

        scanned_count = 0
        production_paths = [
            ROOT_DIR / "envhunter.py",
            ROOT_DIR / "README.md",
            ROOT_DIR / "requirements.txt",
            ROOT_DIR / ".env.example",
        ] + list((ROOT_DIR / "envhunter").rglob("*.py")) + list((ROOT_DIR / "docs").rglob("*.md"))

        for p in production_paths:
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            match = pat_pattern.search(text)
            self.assertIsNone(
                match,
                f"Accidentally committed secret found in production file {p}: {match.group(0)[:15]}..." if match else "",
            )
            scanned_count += 1

        self.assertTrue(scanned_count >= 8, f"Should have scanned production files (scanned {scanned_count})")



if __name__ == "__main__":
    unittest.main()
