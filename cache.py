"""
SQLite cache for IOC Hunter results.
Keyed on (url, report_type) with a 7-day TTL.
"""

import sqlite3
import json
import datetime
import os

DB_PATH = os.environ.get("IOC_HUNTER_DB", "ioc_hunter_cache.db")
CACHE_TTL_DAYS = 7


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                url          TEXT NOT NULL,
                report_type  TEXT NOT NULL,
                result_json  TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                UNIQUE(url, report_type)
            )
        """)
        conn.commit()


def get_cached(url: str, report_type: str) -> dict | None:
    """Return cached result if it exists and hasn't expired, else None."""
    init_db()
    now = datetime.datetime.utcnow().isoformat()
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json, expires_at FROM cache WHERE url=? AND report_type=?",
            (url, report_type),
        ).fetchone()
    if row and row["expires_at"] > now:
        return json.loads(row["result_json"])
    return None


def save_cache(url: str, report_type: str, result: dict):
    """Insert or replace a cache entry with a fresh 7-day TTL."""
    init_db()
    now = datetime.datetime.utcnow()
    expires = (now + datetime.timedelta(days=CACHE_TTL_DAYS)).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO cache (url, report_type, result_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url, report_type) DO UPDATE SET
                result_json = excluded.result_json,
                created_at  = excluded.created_at,
                expires_at  = excluded.expires_at
            """,
            (url, report_type, json.dumps(result), now.isoformat(), expires),
        )
        conn.commit()


def delete_entry(entry_id: int):
    """Delete a single cache entry by ID."""
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM cache WHERE id=?", (entry_id,))
        conn.commit()


def clear_expired():
    """Delete all entries past their expiry date."""
    init_db()
    now = datetime.datetime.utcnow().isoformat()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
        conn.commit()
        return cur.rowcount


def clear_all():
    """Wipe the entire cache."""
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM cache")
        conn.commit()


def get_all_entries() -> list[dict]:
    """Return all cache entries ordered by most recent first."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, url, report_type, created_at, expires_at FROM cache ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """Return summary stats for the cache."""
    init_db()
    now = datetime.datetime.utcnow().isoformat()
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM cache WHERE expires_at > ?", (now,)).fetchone()[0]
        expired = total - active
    return {"total": total, "active": active, "expired": expired}
