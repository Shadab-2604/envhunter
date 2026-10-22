"""
SQLite persistence, deduplication, and resumable scan state management for EnvHunter.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple

from envhunter.config import (
    CONFIG_DIR,
    DEFAULT_DB_PATH,
    DIR_PERMISSIONS,
    FILE_PERMISSIONS,
    STATUS_UNKNOWN,
)


@dataclass
class FindingRecord:
    """Represents a security/hygiene audit finding to be stored and exported."""
    scan_id: str
    repo_owner: str
    repo_name: str
    repo_url: str
    branch_names: str  # Comma-separated or JSON list
    file_path: str
    event_type: str    # added, modified, renamed, deleted, snapshot
    commit_sha: str
    short_sha: str
    commit_url: str
    author_name: str
    author_email: str
    author_date: str
    committer_name: str
    committer_email: str
    committer_date: str
    parent_shas: str
    current_status: str  # CURRENTLY_PRESENT, HISTORICAL_ONLY, DELETED_FROM_SCANNED_BRANCHES
    severity: str        # HIGH, MEDIUM, INFORMATIONAL, UNKNOWN
    detection_reason: str
    scan_timestamp: str
    file_url: str = ""   # Exact URL pointing to the file at this commit/snapshot on GitHub
    verification_status: str = "VERIFIED"


class Database:
    """
    Manages SQLite database connections, tables, and transactional state
    for repos, branches, commits, file events, and findings.
    """

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            try:
                import os
                os.chmod(CONFIG_DIR, DIR_PERMISSIONS)
            except OSError:
                pass
            self.db_path = DEFAULT_DB_PATH
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides a context-managed sqlite3 connection with foreign keys enabled."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes tables and indexes if they do not exist."""
        with self.get_connection() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_username TEXT NOT NULL,
                scan_mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                total_repos INTEGER DEFAULT 0,
                completed_repos INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS repositories (
                repo_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                full_name TEXT NOT NULL,
                url TEXT NOT NULL,
                default_branch TEXT,
                is_fork INTEGER DEFAULT 0,
                is_archived INTEGER DEFAULT 0,
                size_kb INTEGER DEFAULT 0,
                status TEXT DEFAULT 'PENDING',
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                UNIQUE(scan_id, full_name)
            );

            CREATE TABLE IF NOT EXISTS branches (
                branch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                FOREIGN KEY(repo_id) REFERENCES repositories(repo_id) ON DELETE CASCADE,
                UNIQUE(repo_id, name)
            );

            CREATE TABLE IF NOT EXISTS commits (
                commit_sha TEXT PRIMARY KEY,
                repo_id INTEGER NOT NULL,
                short_sha TEXT NOT NULL,
                author_name TEXT,
                author_email TEXT,
                author_date TEXT,
                committer_name TEXT,
                committer_email TEXT,
                committer_date TEXT,
                parent_shas TEXT,
                commit_url TEXT,
                inspected INTEGER DEFAULT 0,
                FOREIGN KEY(repo_id) REFERENCES repositories(repo_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS branch_commits (
                branch_id INTEGER NOT NULL,
                commit_sha TEXT NOT NULL,
                PRIMARY KEY(branch_id, commit_sha),
                FOREIGN KEY(branch_id) REFERENCES branches(branch_id) ON DELETE CASCADE,
                FOREIGN KEY(commit_sha) REFERENCES commits(commit_sha) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS file_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                commit_sha TEXT NOT NULL,
                repo_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT DEFAULT 'RECORDED',
                FOREIGN KEY(commit_sha) REFERENCES commits(commit_sha) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES repositories(repo_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                repo_owner TEXT NOT NULL,
                repo_name TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                branch_names TEXT NOT NULL,
                file_path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                short_sha TEXT NOT NULL,
                commit_url TEXT NOT NULL,
                file_url TEXT DEFAULT '',
                author_name TEXT,
                author_email TEXT,
                author_date TEXT,
                committer_name TEXT,
                committer_email TEXT,
                committer_date TEXT,
                parent_shas TEXT,
                current_status TEXT NOT NULL,
                severity TEXT NOT NULL,
                detection_reason TEXT,
                scan_timestamp TEXT NOT NULL,
                verification_status TEXT DEFAULT 'VERIFIED',
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
                UNIQUE(scan_id, repo_owner, repo_name, commit_sha, file_path, event_type)
            );

            CREATE TABLE IF NOT EXISTS scan_errors (
                error_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                repo_name TEXT,
                error_type TEXT NOT NULL,
                error_message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_repos_scan ON repositories(scan_id);
            CREATE INDEX IF NOT EXISTS idx_commits_repo ON commits(repo_id);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            """)

            # Safe migration: ensure file_url column exists in existing databases
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN file_url TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass

    # --- Scan Management ---

    def create_scan(self, scan_id: str, target_username: str, scan_mode: str) -> None:
        """Records a new scan session."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (scan_id, target_username, scan_mode, status, started_at)
                VALUES (?, ?, ?, 'IN_PROGRESS', ?)
                """,
                (scan_id, target_username, scan_mode, now),
            )

    def get_latest_scan_for_user(self, target_username: str) -> Optional[Dict[str, Any]]:
        """Returns the most recent scan record for the username."""
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM scans 
                WHERE LOWER(target_username) = LOWER(?)
                ORDER BY started_at DESC LIMIT 1
                """,
                (target_username,),
            ).fetchone()
            return dict(row) if row else None

    def update_scan_status(self, scan_id: str, status: str, total_repos: Optional[int] = None) -> None:
        """Updates scan status (e.g. COMPLETED, INTERRUPTED)."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            if status in ("COMPLETED", "INTERRUPTED", "FAILED"):
                if total_repos is not None:
                    conn.execute(
                        """
                        UPDATE scans 
                        SET status = ?, finished_at = ?, total_repos = ?
                        WHERE scan_id = ?
                        """,
                        (status, now, total_repos, scan_id),
                    )
                else:
                    conn.execute(
                        "UPDATE scans SET status = ?, finished_at = ? WHERE scan_id = ?",
                        (status, now, scan_id),
                    )
            else:
                conn.execute("UPDATE scans SET status = ? WHERE scan_id = ?", (status, scan_id))

    def reset_user_scans(self, target_username: str) -> None:
        """Removes previous scans for a user for a fresh start."""
        with self.get_connection() as conn:
            conn.execute(
                "DELETE FROM scans WHERE LOWER(target_username) = LOWER(?)",
                (target_username,),
            )

    # --- Repository Management ---

    def save_repositories(self, scan_id: str, repos: List[Dict[str, Any]]) -> None:
        """Inserts discovered repositories for a scan, ignoring duplicates."""
        with self.get_connection() as conn:
            for r in repos:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO repositories (
                        scan_id, owner, name, full_name, url, default_branch, 
                        is_fork, is_archived, size_kb, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
                    """,
                    (
                        scan_id,
                        r["owner"],
                        r["name"],
                        r["full_name"],
                        r["url"],
                        r.get("default_branch", "main"),
                        1 if r.get("is_fork") else 0,
                        1 if r.get("is_archived") else 0,
                        r.get("size_kb", 0),
                    ),
                )

    def get_pending_repositories(self, scan_id: str) -> List[Dict[str, Any]]:
        """Returns repositories in this scan that are not yet COMPLETED."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM repositories 
                WHERE scan_id = ? AND status != 'COMPLETED'
                ORDER BY repo_id ASC
                """,
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_all_repositories(self, scan_id: str) -> List[Dict[str, Any]]:
        """Returns all repositories recorded for the scan."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM repositories WHERE scan_id = ? ORDER BY repo_id ASC",
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def update_repo_status(self, repo_id: int, status: str) -> None:
        """Marks repository status (e.g. IN_PROGRESS, COMPLETED, SKIPPED, FAILED)."""
        with self.get_connection() as conn:
            conn.execute("UPDATE repositories SET status = ? WHERE repo_id = ?", (status, repo_id))
            if status == "COMPLETED":
                # Increment completed_repos counter in scans
                conn.execute(
                    """
                    UPDATE scans SET completed_repos = (
                        SELECT COUNT(*) FROM repositories 
                        WHERE scan_id = scans.scan_id AND status = 'COMPLETED'
                    ) WHERE scan_id = (SELECT scan_id FROM repositories WHERE repo_id = ?)
                    """,
                    (repo_id,),
                )

    # --- Branches ---

    def save_branch(self, repo_id: int, name: str, head_sha: str) -> int:
        """Saves or updates a branch for a repository."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO branches (repo_id, name, head_sha)
                VALUES (?, ?, ?)
                ON CONFLICT(repo_id, name) DO UPDATE SET head_sha=excluded.head_sha
                """,
                (repo_id, name, head_sha),
            )
            # Fetch branch_id
            row = conn.execute(
                "SELECT branch_id FROM branches WHERE repo_id = ? AND name = ?",
                (repo_id, name),
            ).fetchone()
            return row["branch_id"]

    def get_repo_branches(self, repo_id: int) -> List[Dict[str, Any]]:
        """Returns branches for a given repository."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM branches WHERE repo_id = ?",
                (repo_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # --- Commits and Deduplication ---

    def commit_exists(self, commit_sha: str) -> bool:
        """Checks if a commit is already stored and inspected."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT inspected FROM commits WHERE commit_sha = ?",
                (commit_sha,),
            ).fetchone()
            return row is not None and bool(row["inspected"])

    def record_commit(
        self,
        repo_id: int,
        commit_sha: str,
        short_sha: str,
        author_name: str,
        author_email: str,
        author_date: str,
        committer_name: str,
        committer_email: str,
        committer_date: str,
        parent_shas: List[str],
        commit_url: str,
        inspected: bool = True,
    ) -> None:
        """Records a unique commit in the database."""
        parents_str = " ".join(parent_shas) if parent_shas else ""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO commits (
                    commit_sha, repo_id, short_sha, author_name, author_email,
                    author_date, committer_name, committer_email, committer_date,
                    parent_shas, commit_url, inspected
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    commit_sha,
                    repo_id,
                    short_sha,
                    author_name,
                    author_email,
                    author_date,
                    committer_name,
                    committer_email,
                    committer_date,
                    parents_str,
                    commit_url,
                    1 if inspected else 0,
                ),
            )

    def associate_branch_commit(self, branch_id: int, commit_sha: str) -> None:
        """Records that a commit belongs to a specific branch."""
        with self.get_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO branch_commits (branch_id, commit_sha) VALUES (?, ?)",
                (branch_id, commit_sha),
            )

    def get_branches_for_commit(self, commit_sha: str) -> List[str]:
        """Returns names of all branches that contain the given commit."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT b.name FROM branches b
                JOIN branch_commits bc ON b.branch_id = bc.branch_id
                WHERE bc.commit_sha = ?
                """,
                (commit_sha,),
            ).fetchall()
            return [r["name"] for r in rows]

    # --- Findings ---

    def save_finding(self, finding: FindingRecord) -> bool:
        """
        Saves a security finding with deduplication.
        Returns True if inserted, False if duplicate.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO findings (
                    scan_id, repo_owner, repo_name, repo_url, branch_names,
                    file_path, event_type, commit_sha, short_sha, commit_url, file_url,
                    author_name, author_email, author_date, committer_name,
                    committer_email, committer_date, parent_shas, current_status,
                    severity, detection_reason, scan_timestamp, verification_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.scan_id,
                    finding.repo_owner,
                    finding.repo_name,
                    finding.repo_url,
                    finding.branch_names,
                    finding.file_path,
                    finding.event_type,
                    finding.commit_sha,
                    finding.short_sha,
                    finding.commit_url,
                    finding.file_url,
                    finding.author_name,
                    finding.author_email,
                    finding.author_date,
                    finding.committer_name,
                    finding.committer_email,
                    finding.committer_date,
                    finding.parent_shas,
                    finding.current_status,
                    finding.severity,
                    finding.detection_reason,
                    finding.scan_timestamp,
                    finding.verification_status,
                ),
            )
            inserted = cursor.rowcount > 0
            if inserted:
                conn.execute(
                    "UPDATE scans SET total_findings = total_findings + 1 WHERE scan_id = ?",
                    (finding.scan_id,),
                )
            return inserted

    def get_findings_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Returns all findings for a given scan."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY finding_id ASC",
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_findings_for_user(self, target_username: str) -> List[Dict[str, Any]]:
        """Returns all findings for the latest scan of a target username."""
        latest = self.get_latest_scan_for_user(target_username)
        if not latest:
            return []
        return self.get_findings_for_scan(latest["scan_id"])

    # --- Errors and Summary ---

    def record_error(self, scan_id: str, repo_name: Optional[str], error_type: str, message: str) -> None:
        """Logs a scan error in the database."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scan_errors (scan_id, repo_name, error_type, error_message, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, repo_name, error_type, message, now),
            )

    def get_scan_summary(self, scan_id: str) -> Dict[str, Any]:
        """Calculates a comprehensive summary for a scan."""
        with self.get_connection() as conn:
            scan = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if not scan:
                return {}

            total_repos = conn.execute(
                "SELECT COUNT(*) as count FROM repositories WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()["count"]

            completed_repos = conn.execute(
                "SELECT COUNT(*) as count FROM repositories WHERE scan_id = ? AND status = 'COMPLETED'",
                (scan_id,),
            ).fetchone()["count"]

            total_branches = conn.execute(
                """
                SELECT COUNT(*) as count FROM branches b
                JOIN repositories r ON b.repo_id = r.repo_id
                WHERE r.scan_id = ?
                """,
                (scan_id,),
            ).fetchone()["count"]

            unique_commits = conn.execute(
                """
                SELECT COUNT(DISTINCT c.commit_sha) as count FROM commits c
                JOIN repositories r ON c.repo_id = r.repo_id
                WHERE r.scan_id = ?
                """,
                (scan_id,),
            ).fetchone()["count"]

            findings_by_severity = dict(
                conn.execute(
                    """
                    SELECT severity, COUNT(*) as count FROM findings
                    WHERE scan_id = ? GROUP BY severity
                    """,
                    (scan_id,),
                ).fetchall()
            )

            total_findings = sum(findings_by_severity.values())

            return {
                "scan_id": scan["scan_id"],
                "target_username": scan["target_username"],
                "scan_mode": scan["scan_mode"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "finished_at": scan["finished_at"],
                "total_repos": total_repos,
                "completed_repos": completed_repos,
                "total_branches": total_branches,
                "unique_commits": unique_commits,
                "findings_by_severity": findings_by_severity,
                "total_findings": total_findings,
            }
