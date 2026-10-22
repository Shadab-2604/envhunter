"""
Environment file detection and classification for EnvHunter.
"""

from dataclasses import dataclass
import os
import re
from typing import Optional, Set

from envhunter.config import (
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_MEDIUM,
    SEVERITY_UNKNOWN,
    STATUS_CURRENTLY_PRESENT,
    STATUS_DELETED,
    STATUS_HISTORICAL_ONLY,
    STATUS_INCOMPLETE,
    STATUS_UNKNOWN,
)


@dataclass
class DetectionResult:
    """Represents a matched file path and its preliminary classification."""
    is_match: bool
    is_sample: bool
    matched_pattern: str
    detection_reason: str
    suggested_severity: str


class EnvDetector:
    """
    Dedicated path-based detector for environment and configuration file patterns.
    Distinguishes real environment files from sample/template files.
    """

    # Suffixes and names that denote template or example files
    SAMPLE_SUFFIXES: Set[str] = {
        ".example",
        ".sample",
        ".template",
        ".dist",
        ".default",
        ".tmpl",
        ".skel",
        ".bak.example",
    }

    # Core base filenames to check
    ENV_BASE_PATTERNS = [
        r"^\.env$",
        r"^\.env\..+$",
        r"^env$",
        r"^\.environment$",
        r"^environment\.env$",
    ]

    # Additional sensitive configuration files (optional)
    OPTIONAL_CONFIG_PATTERNS = [
        r"^database\.ya?ml$",
        r"^settings\.py$",
        r"^secrets\.ya?ml$",
        r"^credentials\.json$",
    ]

    def __init__(self, check_optional_configs: bool = False, case_insensitive: bool = True):
        self.check_optional_configs = check_optional_configs
        self.case_insensitive = case_insensitive
        self._flags = re.IGNORECASE if case_insensitive else 0

        self._env_regexes = [re.compile(p, self._flags) for p in self.ENV_BASE_PATTERNS]
        self._config_regexes = [re.compile(p, self._flags) for p in self.OPTIONAL_CONFIG_PATTERNS]

    def is_sample_file(self, filename: str) -> bool:
        """
        Determines whether the filename is an example, sample, or template.
        Examples: .env.example, .env.sample, .env.local.example, example.env
        """
        lower = filename.lower()
        if lower.startswith("example.") or lower.startswith("sample."):
            return True

        for suffix in self.SAMPLE_SUFFIXES:
            if lower.endswith(suffix):
                return True

        if ".example." in lower or ".sample." in lower or ".template." in lower:
            return True

        return False

    def classify_path(self, file_path: str) -> DetectionResult:
        """
        Analyzes a file path (including directory components) to see if it matches
        any .env pattern or sensitive config pattern.
        """
        if not file_path or not file_path.strip():
            return DetectionResult(
                is_match=False,
                is_sample=False,
                matched_pattern="",
                detection_reason="",
                suggested_severity=SEVERITY_UNKNOWN,
            )

        # Normalize path separators
        normalized = file_path.replace("\\", "/").strip("/")
        parts = normalized.split("/")
        filename = parts[-1]

        # Check sample/template first
        if self.is_sample_file(filename):
            # Check if it's an env-like sample file
            for regex in self._env_regexes:
                # Remove sample suffix to see if base matches .env
                base = filename
                for sfx in self.SAMPLE_SUFFIXES:
                    if base.lower().endswith(sfx):
                        base = base[:-len(sfx)]
                        break
                if regex.match(base) or regex.match(filename) or "env" in filename.lower():
                    return DetectionResult(
                        is_match=True,
                        is_sample=True,
                        matched_pattern=filename,
                        detection_reason=f"Sample/template environment file ({filename})",
                        suggested_severity=SEVERITY_INFORMATIONAL,
                    )

        # Check standard .env patterns
        for regex in self._env_regexes:
            if regex.match(filename):
                # Classify specific env variant
                lower = filename.lower()
                if lower == ".env":
                    reason = "Primary environment configuration file (.env)"
                elif "prod" in lower:
                    reason = f"Production environment configuration ({filename})"
                elif "local" in lower:
                    reason = f"Local environment configuration ({filename})"
                elif "stage" in lower or "staging" in lower:
                    reason = f"Staging environment configuration ({filename})"
                elif "dev" in lower:
                    reason = f"Development environment configuration ({filename})"
                elif "test" in lower:
                    reason = f"Test environment configuration ({filename})"
                elif "backup" in lower or "bak" in lower:
                    reason = f"Backup environment file ({filename})"
                else:
                    reason = f"Environment configuration variant ({filename})"

                if len(parts) > 1:
                    reason += f" in directory '{'/'.join(parts[:-1])}'"

                return DetectionResult(
                    is_match=True,
                    is_sample=False,
                    matched_pattern=filename,
                    detection_reason=reason,
                    suggested_severity=SEVERITY_HIGH,  # Pending exposure status check
                )

        # Check optional config files if enabled
        if self.check_optional_configs:
            for regex in self._config_regexes:
                if regex.match(filename):
                    return DetectionResult(
                        is_match=True,
                        is_sample=False,
                        matched_pattern=filename,
                        detection_reason=f"Configuration file ({filename})",
                        suggested_severity=SEVERITY_MEDIUM,
                    )

        return DetectionResult(
            is_match=False,
            is_sample=False,
            matched_pattern="",
            detection_reason="",
            suggested_severity=SEVERITY_UNKNOWN,
        )

    @staticmethod
    def calculate_severity(
        is_sample: bool,
        exposure_status: str,
    ) -> str:
        """
        Calculates the finding severity based on whether it is a sample file
        and its current vs historical presence in repository branches.
        """
        if is_sample:
            return SEVERITY_INFORMATIONAL

        if exposure_status == STATUS_CURRENTLY_PRESENT:
            return SEVERITY_HIGH

        if exposure_status in (STATUS_HISTORICAL_ONLY, STATUS_DELETED):
            return SEVERITY_MEDIUM

        if exposure_status == STATUS_INCOMPLETE:
            return SEVERITY_UNKNOWN

        return SEVERITY_UNKNOWN
