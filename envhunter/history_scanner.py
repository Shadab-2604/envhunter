"""
Hybrid history scanning engine for EnvHunter.
Audits current branch snapshots and reachable historical commits for environment files.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Set

from envhunter.config import (
    SCAN_MODE_CURRENT,
    SCAN_MODE_DEEP,
    SCAN_MODE_FULL,
    STATUS_CURRENTLY_PRESENT,
    STATUS_DELETED,
    STATUS_HISTORICAL_ONLY,
    STATUS_UNKNOWN,
)
from envhunter.database import Database, FindingRecord
from envhunter.detectors import EnvDetector
from envhunter.github_client import GitHubAPIError, GitHubClient
from envhunter.repository_scanner import DiscoveredBranch


class HistoryScanner:
    """
    Scans repository history and current snapshots for environment configuration files.
    Deduplicates commits across branches and determines exposure status.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        database: Database,
        detector: Optional[EnvDetector] = None,
        use_git_cli_fallback: bool = True,
    ):
        self.client = github_client
        self.db = database
        self.detector = detector or EnvDetector()
        self.use_git_cli_fallback = use_git_cli_fallback

    def scan_repository(
        self,
        scan_id: str,
        repo: Dict[str, Any],
        branches: List[DiscoveredBranch],
        scan_mode: str = SCAN_MODE_FULL,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> List[FindingRecord]:
        """
        Scans a single repository based on the specified scan mode (current, full, deep).
        Returns a list of created FindingRecords.
        """
        owner = repo["owner"]
        repo_name = repo["name"]
        repo_url = repo["url"]
        repo_id = repo["repo_id"]
        findings: List[FindingRecord] = []

        if not branches:
            if progress_callback:
                progress_callback(f"[{repo['full_name']}] No accessible branches found. Marking completed.")
            self.db.update_repo_status(repo_id, "COMPLETED")
            return findings

        # Create a lookup for current files across all branches
        all_current_files: Set[str] = set()
        branch_current_files_map: Dict[str, Set[str]] = {}
        for b in branches:
            all_current_files.update(b.current_files)
            branch_current_files_map[b.name] = b.current_files

        scan_timestamp = datetime.now(timezone.utc).isoformat()

        # 1. First, check current snapshots directly across all branch HEADs
        if progress_callback:
            progress_callback(f"[{repo['full_name']}] Checking current branch snapshots...")

        for b in branches:
            for file_path in b.current_files:
                detection = self.detector.classify_path(file_path)
                if detection.is_match:
                    severity = self.detector.calculate_severity(
                        is_sample=detection.is_sample,
                        exposure_status=STATUS_CURRENTLY_PRESENT,
                    )
                    finding = FindingRecord(
                        scan_id=scan_id,
                        repo_owner=owner,
                        repo_name=repo_name,
                        repo_url=repo_url,
                        branch_names=b.name,
                        file_path=file_path,
                        event_type="present_in_snapshot",
                        commit_sha=b.head_sha,
                        short_sha=b.head_sha[:7] if b.head_sha else "",
                        commit_url=f"https://github.com/{owner}/{repo_name}/commit/{b.head_sha}",
                        file_url=f"https://github.com/{owner}/{repo_name}/blob/{b.head_sha}/{file_path}",
                        author_name="HEAD",
                        author_email="",
                        author_date=scan_timestamp,
                        committer_name="HEAD",
                        committer_email="",
                        committer_date=scan_timestamp,
                        parent_shas="",
                        current_status=STATUS_CURRENTLY_PRESENT,
                        severity=severity,
                        detection_reason=detection.detection_reason,
                        scan_timestamp=scan_timestamp,
                        verification_status="VERIFIED_AT_HEAD",
                    )
                    if self.db.save_finding(finding):
                        findings.append(finding)

        # If scan mode is 'current', we are done with this repo
        if scan_mode == SCAN_MODE_CURRENT:
            self.db.update_repo_status(repo_id, "COMPLETED")
            return findings

        # 2. Historical commit scan (full / deep)
        # Attempt fast bare mirror clone first (hybrid engine)
        if self.use_git_cli_fallback:
            bare_findings = self._scan_via_git_bare_clone(
                scan_id=scan_id,
                repo=repo,
                branches=branches,
                all_current_files=all_current_files,
                scan_timestamp=scan_timestamp,
                progress_callback=progress_callback,
            )
            if bare_findings is not None:
                findings.extend(bare_findings)
                return findings

        # Fallback to GitHub REST API commit enumeration
        if progress_callback:
            progress_callback(f"[{repo['full_name']}] Enumerating and deduplicating commit history via API...")

        # Collect commits across all branches, tracking associations
        unique_commits_to_inspect: Dict[str, Dict[str, Any]] = {}

        for b in branches:
            if not b.head_sha:
                continue
            try:
                branch_commits = self.client.get_branch_commits(owner, repo_name, b.head_sha)
            except GitHubAPIError as e:
                self.db.record_error(scan_id, repo["full_name"], "COMMIT_ENUM_ERROR", f"Branch '{b.name}': {e}")
                continue

            for c in branch_commits:
                c_sha = c["sha"]
                # Record commit entry first so foreign key in branch_commits is satisfied
                if not self.db.commit_exists(c_sha):
                    self.db.record_commit(
                        repo_id=repo_id,
                        commit_sha=c_sha,
                        short_sha=c.get("short_sha", c_sha[:7]),
                        author_name=c.get("author_name", ""),
                        author_email=c.get("author_email", ""),
                        author_date=c.get("author_date", ""),
                        committer_name=c.get("committer_name", ""),
                        committer_email=c.get("committer_email", ""),
                        committer_date=c.get("committer_date", ""),
                        parent_shas=c.get("parents", []),
                        commit_url=c.get("html_url", ""),
                        inspected=False,
                    )
                    unique_commits_to_inspect[c_sha] = c

                # Associate branch with commit
                self.db.associate_branch_commit(b.branch_id, c_sha)

        if progress_callback:
            progress_callback(
                f"[{repo['full_name']}] Found {len(unique_commits_to_inspect)} unique uninspected commits."
            )

        # Inspect changed files for each unique commit
        inspected_count = 0
        for c_sha, c_meta in unique_commits_to_inspect.items():
            inspected_count += 1
            if progress_callback and inspected_count % 10 == 0:
                progress_callback(
                    f"[{repo['full_name']}] Inspecting commit {inspected_count}/{len(unique_commits_to_inspect)}..."
                )

            try:
                commit_detail = self.client.get_commit_detail(owner, repo_name, c_sha)
            except GitHubAPIError as e:
                self.db.record_error(scan_id, repo["full_name"], "COMMIT_DETAIL_ERROR", f"Commit {c_sha[:7]}: {e}")
                continue

            # Record commit in DB
            self.db.record_commit(
                repo_id=repo_id,
                commit_sha=c_sha,
                short_sha=c_meta["short_sha"],
                author_name=commit_detail["author_name"],
                author_email=commit_detail["author_email"],
                author_date=commit_detail["author_date"],
                committer_name=commit_detail["committer_name"],
                committer_email=commit_detail["committer_email"],
                committer_date=commit_detail["committer_date"],
                parent_shas=commit_detail["parents"],
                commit_url=commit_detail["html_url"],
                inspected=True,
            )

            # Get branches containing this commit
            containing_branches = self.db.get_branches_for_commit(c_sha)
            branch_names_str = ", ".join(containing_branches) if containing_branches else "unknown"

            # Inspect files
            for file_entry in commit_detail["files"]:
                file_path = file_entry["filename"]
                raw_status = file_entry.get("status", "modified").lower()
                event_type = raw_status  # added, modified, removed, renamed, copied

                detection = self.detector.classify_path(file_path)
                if detection.is_match:
                    # Determine exposure status
                    is_currently_present = file_path in all_current_files
                    if is_currently_present:
                        current_status = STATUS_CURRENTLY_PRESENT
                    elif event_type in ("removed", "deleted"):
                        current_status = STATUS_DELETED
                    else:
                        current_status = STATUS_HISTORICAL_ONLY

                    severity = self.detector.calculate_severity(
                        is_sample=detection.is_sample,
                        exposure_status=current_status,
                    )

                    finding = FindingRecord(
                        scan_id=scan_id,
                        repo_owner=owner,
                        repo_name=repo_name,
                        repo_url=repo_url,
                        branch_names=branch_names_str,
                        file_path=file_path,
                        event_type=event_type,
                        commit_sha=c_sha,
                        short_sha=c_meta["short_sha"],
                        commit_url=commit_detail["html_url"],
                        file_url=f"https://github.com/{owner}/{repo_name}/blob/{c_sha}/{file_path}",
                        author_name=commit_detail["author_name"],
                        author_email=commit_detail["author_email"],
                        author_date=commit_detail["author_date"],
                        committer_name=commit_detail["committer_name"],
                        committer_email=commit_detail["committer_email"],
                        committer_date=commit_detail["committer_date"],
                        parent_shas=" ".join(commit_detail["parents"]),
                        current_status=current_status,
                        severity=severity,
                        detection_reason=detection.detection_reason,
                        scan_timestamp=scan_timestamp,
                        verification_status="VERIFIED_HISTORICAL",
                    )
                    if self.db.save_finding(finding):
                        findings.append(finding)

        # Mark repository completed
        self.db.update_repo_status(repo_id, "COMPLETED")
        return findings

    def _scan_via_git_bare_clone(
        self,
        scan_id: str,
        repo: Dict[str, Any],
        branches: List[DiscoveredBranch],
        all_current_files: Set[str],
        scan_timestamp: str,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[List[FindingRecord]]:
        """
        Attempts to scan commit history by creating a temporary bare mirror clone with --filter=blob:none.
        Runs locally in seconds without consuming API rate limit quota.
        Returns List[FindingRecord] on success, or None to fall back to REST API.
        """
        owner = repo["owner"]
        repo_name = repo["name"]
        repo_url = repo["url"]
        repo_id = repo["repo_id"]
        clone_url = repo_url + ".git"
        findings: List[FindingRecord] = []

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                if progress_callback:
                    progress_callback(f"[{repo['full_name']}] Cloning bare metadata mirror (blobless)...")

                cmd = ["git", "clone", "--bare", "--filter=blob:none", "--quiet", clone_url, temp_dir]
                proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
                if proc.returncode != 0:
                    return None

                log_format = "COMMIT:%H|%h|%an|%ae|%aI|%cn|%ce|%cI|%P"
                log_proc = subprocess.run(
                    ["git", "log", "--all", "--full-history", f"--pretty=format:{log_format}", "--name-status"],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if log_proc.returncode != 0:
                    return None

                current_commit: Optional[Dict[str, Any]] = None
                commit_count = 0

                for line in log_proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    if line.startswith("COMMIT:"):
                        parts = line[len("COMMIT:"):].split("|")
                        if len(parts) >= 8:
                            commit_sha = parts[0]
                            short_sha = parts[1]
                            current_commit = {
                                "sha": commit_sha,
                                "short_sha": short_sha,
                                "author_name": parts[2],
                                "author_email": parts[3],
                                "author_date": parts[4],
                                "committer_name": parts[5],
                                "committer_email": parts[6],
                                "committer_date": parts[7],
                                "parent_shas": parts[8] if len(parts) > 8 else "",
                                "commit_url": f"https://github.com/{owner}/{repo_name}/commit/{commit_sha}",
                            }
                            commit_count += 1
                            if not self.db.commit_exists(commit_sha):
                                self.db.record_commit(
                                    repo_id=repo_id,
                                    commit_sha=commit_sha,
                                    short_sha=short_sha,
                                    author_name=parts[2],
                                    author_email=parts[3],
                                    author_date=parts[4],
                                    committer_name=parts[5],
                                    committer_email=parts[6],
                                    committer_date=parts[7],
                                    parent_shas=parts[8].split() if len(parts) > 8 and parts[8] else [],
                                    commit_url=f"https://github.com/{owner}/{repo_name}/commit/{commit_sha}",
                                    inspected=True,
                                )
                        continue

                    if current_commit and ("\t" in line or " " in line):
                        tokens = line.split()
                        if len(tokens) >= 2:
                            raw_status = tokens[0]
                            file_path = tokens[-1]

                            status_map = {
                                "A": "added",
                                "M": "modified",
                                "D": "deleted",
                                "R": "renamed",
                                "C": "copied",
                            }
                            event_type = status_map.get(raw_status[0].upper(), "modified")

                            detection = self.detector.classify_path(file_path)
                            if detection.is_match:
                                is_present = file_path in all_current_files
                                if is_present:
                                    current_status = STATUS_CURRENTLY_PRESENT
                                elif event_type in ("deleted", "removed"):
                                    current_status = STATUS_DELETED
                                else:
                                    current_status = STATUS_HISTORICAL_ONLY

                                severity = self.detector.calculate_severity(
                                    is_sample=detection.is_sample,
                                    exposure_status=current_status,
                                )

                                branch_names_str = "all_reachable"
                                try:
                                    branch_proc = subprocess.run(
                                        ["git", "for-each-ref", f"--contains={current_commit['sha']}", "--format=%(refname:short)", "refs/heads"],
                                        cwd=temp_dir,
                                        capture_output=True,
                                        text=True,
                                        timeout=5,
                                    )
                                    if branch_proc.returncode == 0 and branch_proc.stdout.strip():
                                        branch_names_str = ", ".join(branch_proc.stdout.strip().splitlines())
                                except Exception:
                                    pass

                                finding = FindingRecord(
                                    scan_id=scan_id,
                                    repo_owner=owner,
                                    repo_name=repo_name,
                                    repo_url=repo_url,
                                    branch_names=branch_names_str,
                                    file_path=file_path,
                                    event_type=event_type,
                                    commit_sha=current_commit["sha"],
                                    short_sha=current_commit["short_sha"],
                                    commit_url=current_commit["commit_url"],
                                    file_url=f"https://github.com/{owner}/{repo_name}/blob/{current_commit['sha']}/{file_path}",
                                    author_name=current_commit["author_name"],
                                    author_email=current_commit["author_email"],
                                    author_date=current_commit["author_date"],
                                    committer_name=current_commit["committer_name"],
                                    committer_email=current_commit["committer_email"],
                                    committer_date=current_commit["committer_date"],
                                    parent_shas=current_commit["parent_shas"],
                                    current_status=current_status,
                                    severity=severity,
                                    detection_reason=detection.detection_reason,
                                    scan_timestamp=scan_timestamp,
                                    verification_status="VERIFIED_HISTORICAL",
                                )
                                if self.db.save_finding(finding):
                                    findings.append(finding)

                if progress_callback:
                    progress_callback(f"[{repo['full_name']}] Inspected {commit_count} commits via fast git mirror.")

                self.db.update_repo_status(repo_id, "COMPLETED")
                return findings
        except Exception:
            return None

    @staticmethod
    def inspect_local_git_repo(
        repo_path: Path,
        scan_id: str,
        repo_owner: str,
        repo_name: str,
        repo_url: str,
        detector: Optional[EnvDetector] = None,
    ) -> List[FindingRecord]:
        """
        Inspects a local Git repository using Git CLI subprocess calls.
        Safe list arguments are used (never shell=True).
        Extracts commit logs, file status changes, and checks HEAD branch files.
        """
        det = detector or EnvDetector()
        findings: List[FindingRecord] = []
        scan_timestamp = datetime.now(timezone.utc).isoformat()

        # Get current files at HEAD
        current_files: Set[str] = set()
        try:
            tree_output = subprocess.check_output(
                ["git", "ls-tree", "-r", "--name-only", "HEAD"],
                cwd=str(repo_path),
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in tree_output.splitlines():
                if line.strip():
                    current_files.add(line.strip())
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Inspect git log --all --name-status
        log_format = "COMMIT:%H|%h|%an|%ae|%aI|%cn|%ce|%cI|%P"
        try:
            log_output = subprocess.check_output(
                ["git", "log", "--all", "--full-history", f"--pretty=format:{log_format}", "--name-status"],
                cwd=str(repo_path),
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return findings

        current_commit: Optional[Dict[str, Any]] = None

        for line in log_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("COMMIT:"):
                parts = line[len("COMMIT:"):].split("|")
                if len(parts) >= 8:
                    current_commit = {
                        "sha": parts[0],
                        "short_sha": parts[1],
                        "author_name": parts[2],
                        "author_email": parts[3],
                        "author_date": parts[4],
                        "committer_name": parts[5],
                        "committer_email": parts[6],
                        "committer_date": parts[7],
                        "parent_shas": parts[8] if len(parts) > 8 else "",
                    }
                continue

            if current_commit and ("\t" in line or " " in line):
                tokens = line.split()
                if len(tokens) >= 2:
                    raw_status = tokens[0]
                    file_path = tokens[-1]  # In renames, last token is the new path

                    # Map git status letter to event type
                    status_map = {
                        "A": "added",
                        "M": "modified",
                        "D": "deleted",
                        "R": "renamed",
                        "C": "copied",
                    }
                    event_type = status_map.get(raw_status[0].upper(), "modified")

                    detection = det.classify_path(file_path)
                    if detection.is_match:
                        is_present = file_path in current_files
                        if is_present:
                            current_status = STATUS_CURRENTLY_PRESENT
                        elif event_type == "deleted":
                            current_status = STATUS_DELETED
                        else:
                            current_status = STATUS_HISTORICAL_ONLY

                        severity = det.calculate_severity(
                            is_sample=detection.is_sample,
                            exposure_status=current_status,
                        )

                        finding = FindingRecord(
                            scan_id=scan_id,
                            repo_owner=repo_owner,
                            repo_name=repo_name,
                            repo_url=repo_url,
                            branch_names="all_reachable",
                            file_path=file_path,
                            event_type=event_type,
                            commit_sha=current_commit["sha"],
                            short_sha=current_commit["short_sha"],
                            commit_url=f"{repo_url}/commit/{current_commit['sha']}",
                            file_url=f"{repo_url}/blob/{current_commit['sha']}/{file_path}",
                            author_name=current_commit["author_name"],
                            author_email=current_commit["author_email"],
                            author_date=current_commit["author_date"],
                            committer_name=current_commit["committer_name"],
                            committer_email=current_commit["committer_email"],
                            committer_date=current_commit["committer_date"],
                            parent_shas=current_commit["parent_shas"],
                            current_status=current_status,
                            severity=severity,
                            detection_reason=detection.detection_reason,
                            scan_timestamp=scan_timestamp,
                            verification_status="VERIFIED_GIT_CLI",
                        )
                        findings.append(finding)

        return findings
