"""
SQLite cache for IOC Hunter results.
Keyed on (username, url, report_type) with a 7-day TTL.
Each user only sees and retrieves their own cached entries.
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
                username     TEXT NOT NULL DEFAULT 'anonymous',
                url          TEXT NOT NULL,
                report_type  TEXT NOT NULL,
                result_json  TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                UNIQUE(username, url, report_type)
            )
        """)

        # Check whether the existing table has the old UNIQUE(url, report_type)
        # constraint. If so, rebuild the table with the new constraint.
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='cache'"
        ).fetchone()
        table_sql = (row[0] or "") if row else ""

        needs_rebuild = (
            "unique(url, report_type)" in table_sql.lower()
            or (
                "unique(username, url, report_type)" not in table_sql.lower()
                and "username" not in table_sql.lower()
            )
        )

        if needs_rebuild:
            # Add username column if missing (safe to call even if it exists)
            try:
                conn.execute(
                    "ALTER TABLE cache ADD COLUMN username TEXT NOT NULL DEFAULT 'anonymous'"
                )
            except Exception:
                pass

            # Rebuild: copy into a new table with the correct UNIQUE constraint
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_new (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT NOT NULL DEFAULT 'anonymous',
                    url          TEXT NOT NULL,
                    report_type  TEXT NOT NULL,
                    result_json  TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    expires_at   TEXT NOT NULL,
                    UNIQUE(username, url, report_type)
                )
            """)
            conn.execute("""
                INSERT OR IGNORE INTO cache_new
                    (id, username, url, report_type, result_json, created_at, expires_at)
                SELECT id, username, url, report_type, result_json, created_at, expires_at
                FROM cache
            """)
            conn.execute("DROP TABLE cache")
            conn.execute("ALTER TABLE cache_new RENAME TO cache")

        conn.commit()


def get_cached(url: str, report_type: str, username: str) -> dict | None:
    """Return cached result for this user if it exists and hasn't expired, else None."""
    init_db()
    now = datetime.datetime.utcnow().isoformat()
    with _connect() as conn:
        row = conn.execute(
            """SELECT result_json, expires_at FROM cache
               WHERE username=? AND url=? AND report_type=?""",
            (username, url, report_type),
        ).fetchone()
    if row and row["expires_at"] > now:
        return json.loads(row["result_json"])
    return None


def save_cache(url: str, report_type: str, result: dict, username: str):
    """Insert or replace a cache entry for this user with a fresh 7-day TTL."""
    init_db()
    now = datetime.datetime.utcnow()
    expires = (now + datetime.timedelta(days=CACHE_TTL_DAYS)).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO cache (username, url, report_type, result_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(username, url, report_type) DO UPDATE SET
                result_json = excluded.result_json,
                created_at  = excluded.created_at,
                expires_at  = excluded.expires_at
            """,
            (username, url, report_type, json.dumps(result), now.isoformat(), expires),
        )
        conn.commit()


def delete_entry(entry_id: int, username: str):
    """Delete a cache entry only if it belongs to this user."""
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM cache WHERE id=? AND username=?", (entry_id, username))
        conn.commit()


def clear_expired(username: str):
    """Delete this user's expired entries."""
    init_db()
    now = datetime.datetime.utcnow().isoformat()
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM cache WHERE username=? AND expires_at < ?", (username, now)
        )
        conn.commit()
        return cur.rowcount


def clear_all(username: str):
    """Wipe all cache entries belonging to this user."""
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM cache WHERE username=?", (username,))
        conn.commit()


def get_all_entries(username: str) -> list[dict]:
    """Return this user's cache entries ordered by most recent first."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT id, username, url, report_type, created_at, expires_at
               FROM cache WHERE username=? ORDER BY created_at DESC""",
            (username,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_cached_result_for_entry(entry_id: int, username: str) -> dict | None:
    """Fetch the full result JSON for a specific cache entry owned by this user."""
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM cache WHERE id=? AND username=?",
            (entry_id, username),
        ).fetchone()
    return json.loads(row["result_json"]) if row else None


def get_stats(username: str) -> dict:
    """Return summary stats for this user's cache."""
    init_db()
    now = datetime.datetime.utcnow().isoformat()
    with _connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM cache WHERE username=?", (username,)
        ).fetchone()[0]
        active = conn.execute(
            "SELECT COUNT(*) FROM cache WHERE username=? AND expires_at > ?", (username, now)
        ).fetchone()[0]
        expired = total - active
    return {"total": total, "active": active, "expired": expired}
