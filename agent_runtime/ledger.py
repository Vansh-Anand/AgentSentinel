"""SQLite request reservation for at-most-once tool dispatch across restarts."""

from __future__ import annotations

from pathlib import Path
from contextlib import closing
import sqlite3
import threading
import time


class DurableRequestLedger:
    """A duplicate is never re-executed, even if the prior outcome is unknown.

    The ledger does not store tool output. A retry after process restart receives
    a denial; it cannot replay a result without re-reading sensitive content.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        with closing(self._connect()) as db, db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_ns INTEGER NOT NULL
                )
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def claim(self, request_id: str, fingerprint: str) -> str:
        """Return NEW, DUPLICATE, or REUSED; reserve NEW durably first."""
        with self._lock, closing(self._connect()) as db, db:
            cursor = db.execute(
                "INSERT OR IGNORE INTO requests(request_id,fingerprint,state,created_ns) VALUES(?,?,?,?)",
                (request_id, fingerprint, "RESERVED", time.time_ns()),
            )
            if cursor.rowcount == 1:
                return "NEW"
            row = db.execute("SELECT fingerprint FROM requests WHERE request_id=?", (request_id,)).fetchone()
            if row is None:
                raise sqlite3.DatabaseError("request ledger row vanished")
            return "DUPLICATE" if row[0] == fingerprint else "REUSED"

    def complete(self, request_id: str) -> None:
        with self._lock, closing(self._connect()) as db, db:
            cursor = db.execute("UPDATE requests SET state='COMPLETE' WHERE request_id=? AND state='RESERVED'",
                                (request_id,))
            if cursor.rowcount != 1:
                raise sqlite3.DatabaseError("request ledger state changed unexpectedly")
