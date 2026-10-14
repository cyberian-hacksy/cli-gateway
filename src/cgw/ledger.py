"""Replay ledger for the remote bridge.

Every authenticated (kid, rid) is recorded durably before the request is forwarded, so a
replayed envelope never reaches upstream, including after a restart. The ledger fails
closed: a missing, corrupt or full ledger refuses every request.
"""
import os
import sqlite3
import threading
import time
from pathlib import Path

DEFAULT_MAX_ROWS = 100_000
RID_BYTES = 32

_APPLICATION_ID = 0x43475731  # "CGW1": marks a file as this ledger and nothing else
_SCHEMA_VERSION = 1
_COLUMNS = [("kid", "TEXT"), ("rid", "BLOB"), ("consumed_at", "INTEGER")]


class LedgerError(Exception):
    """The ledger cannot vouch for a request. Callers must refuse the request."""


class LedgerFull(LedgerError):
    """The row ceiling is reached. New requests are refused until the key is rotated."""


class Ledger:
    def __init__(self, path, max_rows=DEFAULT_MAX_ROWS):
        """Open an existing ledger. Never creates one: a missing ledger is an error."""
        self._path = Path(path)
        self._max_rows = max_rows
        self._lock = threading.Lock()
        self._conn = None
        if not self._path.is_file():
            raise LedgerError("ledger is missing")
        try:
            conn = sqlite3.connect(
                self._path.resolve().as_uri() + "?mode=rw", uri=True,
                isolation_level=None, check_same_thread=False, timeout=5)
            conn.execute("PRAGMA synchronous=FULL")
            application_id = conn.execute("PRAGMA application_id").fetchone()[0]
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
            columns = [(row[1], row[2].upper()) for row in conn.execute("PRAGMA table_info(consumed)")]
        except sqlite3.Error:
            raise LedgerError("ledger is unusable") from None
        if (application_id, version, integrity, columns) != (_APPLICATION_ID, _SCHEMA_VERSION, "ok", _COLUMNS):
            conn.close()
            raise LedgerError("ledger is not valid")
        self._conn = conn

    @classmethod
    def create(cls, path):
        """Explicit first-time setup for a fresh key. Refuses to replace an existing file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            raise LedgerError("ledger already exists") from None
        conn = sqlite3.connect(path, isolation_level=None)
        try:
            conn.execute("PRAGMA application_id = %d" % _APPLICATION_ID)
            conn.execute("PRAGMA user_version = %d" % _SCHEMA_VERSION)
            conn.execute(
                "CREATE TABLE consumed ("
                "kid TEXT NOT NULL, rid BLOB NOT NULL, consumed_at INTEGER NOT NULL, "
                "PRIMARY KEY (kid, rid)) WITHOUT ROWID")
        finally:
            conn.close()

    def consume(self, kid, rid):
        """Record (kid, rid). True if it was new and is now committed; False if already used."""
        if not isinstance(rid, bytes) or len(rid) != RID_BYTES:
            raise LedgerError("invalid request id")
        with self._lock:
            conn = self._require_open()
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    if conn.execute("SELECT 1 FROM consumed WHERE kid = ? AND rid = ?", (kid, rid)).fetchone():
                        conn.execute("ROLLBACK")
                        return False
                    if conn.execute("SELECT COUNT(*) FROM consumed").fetchone()[0] >= self._max_rows:
                        conn.execute("ROLLBACK")
                        raise LedgerFull("ledger is full")
                    conn.execute("INSERT INTO consumed (kid, rid, consumed_at) VALUES (?, ?, ?)",
                                 (kid, rid, int(time.time())))
                    conn.execute("COMMIT")
                    return True
                except sqlite3.Error:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
            except sqlite3.Error:
                raise LedgerError("ledger is unusable") from None

    def count(self):
        with self._lock:
            try:
                return self._require_open().execute("SELECT COUNT(*) FROM consumed").fetchone()[0]
            except sqlite3.Error:
                raise LedgerError("ledger is unusable") from None

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _require_open(self):
        if self._conn is None:
            raise LedgerError("ledger is closed")
        return self._conn
