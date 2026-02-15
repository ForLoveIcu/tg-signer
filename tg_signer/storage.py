"""
PostgreSQL-based file synchronization for persistent storage.

Syncs the workdir (session files, configs, records) to a PostgreSQL
database so that ephemeral containers (e.g. Hugging Face Spaces)
can restore state on restart.

Requires: DATABASE_URL environment variable (PostgreSQL connection string).
Optional: SYNC_INTERVAL (seconds between periodic syncs, default 60).
"""

import asyncio
import hashlib
import logging
import os
import signal
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger("tg-signer.storage")

# Patterns to sync – covers all critical persistent data
SYNC_PATTERNS = [
    "**/*.session",
    "**/*.session_string",
    "**/*.json",
]

# Patterns to exclude
EXCLUDE_PATTERNS = {
    "__pycache__",
    ".git",
    "node_modules",
}

DDL = """
CREATE TABLE IF NOT EXISTS file_store (
    path       TEXT PRIMARY KEY,
    content    BYTEA NOT NULL,
    md5        TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _should_sync(path: Path) -> bool:
    """Check if a path matches sync patterns and not excluded."""
    parts = path.parts
    for exc in EXCLUDE_PATTERNS:
        if exc in parts:
            return False
    for pattern in SYNC_PATTERNS:
        if path.match(pattern):
            return True
    return False


def _collect_files(base_dirs: list[Path]) -> dict[str, bytes]:
    """Collect all syncable files from multiple base directories."""
    files = {}
    for base in base_dirs:
        if not base.exists():
            continue
        for pattern in SYNC_PATTERNS:
            for fpath in base.rglob(pattern.lstrip("**/")):
                if not fpath.is_file():
                    continue
                if not _should_sync(fpath):
                    continue
                try:
                    rel = str(fpath.relative_to(base.parent))
                    files[rel] = fpath.read_bytes()
                except (OSError, ValueError):
                    continue
    return files


class FileSync:
    """Manages bidirectional file sync with PostgreSQL."""

    def __init__(
        self,
        database_url: str,
        sync_dirs: list[Path],
        interval: int = 60,
    ):
        self.database_url = database_url
        self.sync_dirs = sync_dirs
        self.interval = interval
        self._conn = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _get_conn(self):
        if self._conn is None or self._conn.closed:
            try:
                import psycopg2
            except ImportError:
                raise ImportError(
                    "psycopg2 is required for database sync. "
                    "Install it with: pip install psycopg2-binary"
                )
            self._conn = psycopg2.connect(self.database_url)
            self._conn.autocommit = True
        return self._conn

    def init_db(self):
        """Create the file_store table if it doesn't exist."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(DDL)
        logger.info("Database initialized")

    def restore(self):
        """Download all files from the database to local filesystem."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT path, content FROM file_store")
            rows = cur.fetchall()

        if not rows:
            logger.info("No files to restore from database")
            return 0

        count = 0
        for rel_path, content in rows:
            # content is a memoryview from psycopg2, convert to bytes
            if isinstance(content, memoryview):
                content = bytes(content)
            target = Path(rel_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            count += 1
            logger.debug("Restored: %s", rel_path)

        logger.info("Restored %d files from database", count)
        return count

    def upload(self) -> int:
        """Upload all local syncable files to the database."""
        files = _collect_files(self.sync_dirs)
        if not files:
            logger.debug("No files to upload")
            return 0

        conn = self._get_conn()
        count = 0

        with conn.cursor() as cur:
            for rel_path, content in files.items():
                md5 = _md5(content)
                cur.execute(
                    """
                    INSERT INTO file_store (path, content, md5, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (path) DO UPDATE
                    SET content = EXCLUDED.content,
                        md5 = EXCLUDED.md5,
                        updated_at = NOW()
                    WHERE file_store.md5 != EXCLUDED.md5
                    """,
                    (rel_path, content, md5),
                )
                count += 1

        logger.debug("Uploaded %d files to database", count)
        return count

    def cleanup_deleted(self):
        """Remove database entries for files that no longer exist locally."""
        files = _collect_files(self.sync_dirs)
        local_paths = set(files.keys())

        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT path FROM file_store")
            db_paths = {row[0] for row in cur.fetchall()}

        deleted = db_paths - local_paths
        if deleted:
            conn = self._get_conn()
            with conn.cursor() as cur:
                for path in deleted:
                    cur.execute("DELETE FROM file_store WHERE path = %s", (path,))
            logger.info("Cleaned up %d deleted files from database", len(deleted))

    def _sync_loop(self):
        """Background thread that periodically syncs files."""
        while not self._stop_event.is_set():
            try:
                self.upload()
            except Exception:
                logger.exception("Sync upload failed")
            self._stop_event.wait(self.interval)

        # Final sync on shutdown
        try:
            logger.info("Final sync before shutdown...")
            self.upload()
        except Exception:
            logger.exception("Final sync failed")
        finally:
            if self._conn and not self._conn.closed:
                self._conn.close()

    def start_background_sync(self):
        """Start periodic background sync in a daemon thread."""
        self._thread = threading.Thread(
            target=self._sync_loop, daemon=True, name="file-sync"
        )
        self._thread.start()
        logger.info(
            "Background sync started (interval=%ds, dirs=%s)",
            self.interval,
            [str(d) for d in self.sync_dirs],
        )

    def stop(self, timeout: float = 10):
        """Signal the background sync to stop and wait for final sync."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)


# Global instance
_file_sync: Optional[FileSync] = None


def get_file_sync() -> Optional[FileSync]:
    return _file_sync


def init_file_sync(
    sync_dirs: list[Path] = None,
    database_url: str = None,
    interval: int = None,
) -> Optional[FileSync]:
    """
    Initialize file sync if DATABASE_URL is set.
    Call this at application startup.

    Returns None if DATABASE_URL is not configured (local mode).
    """
    global _file_sync

    database_url = database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        logger.info("DATABASE_URL not set, file sync disabled (local mode)")
        return None

    interval = interval or int(os.environ.get("SYNC_INTERVAL", "60"))

    if sync_dirs is None:
        workdir = Path(os.environ.get("TG_SIGNER_WORKDIR", ".signer"))
        session_dir = Path(".")
        sync_dirs = [workdir, session_dir]

    _file_sync = FileSync(
        database_url=database_url,
        sync_dirs=sync_dirs,
        interval=interval,
    )

    _file_sync.init_db()
    _file_sync.restore()
    _file_sync.start_background_sync()

    # Register shutdown handler
    def _shutdown_handler(signum, frame):
        logger.info("Received signal %d, stopping sync...", signum)
        _file_sync.stop()
        raise SystemExit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _shutdown_handler)

    return _file_sync
