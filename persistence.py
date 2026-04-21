"""
persistence.py — SQLite-backed intelligence log and cross-session deduplication.

Tables:
  intel_log  — enriched + scored IP records with full JSON blobs (permanent)
  seen_ips   — deduplication ledger that survives process restarts

Design notes:
  • WAL journal mode so reads never block writes.
  • UPSERT on intel_log so re-running an IP updates score without duplicating rows.
  • All public methods are synchronous (called from async code via run_in_executor
    or directly — SQLite writes are fast enough for this workload).
"""
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_FILE = "threat_intelligence.db"

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS intel_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    risk_level  TEXT    NOT NULL,
    country     TEXT    DEFAULT '',
    org         TEXT    DEFAULT '',
    reasons     TEXT    DEFAULT '[]',   -- JSON array
    enrichment  TEXT    DEFAULT '{}',   -- full enrichment JSON blob
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_intel_ip ON intel_log(ip);

CREATE TABLE IF NOT EXISTS seen_ips (
    ip         TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL
);
"""


class PersistenceLayer:
    """
    Thread-safe SQLite store.  One connection per process; asyncio callers
    should wrap writes in loop.run_in_executor if the event loop is saturated,
    but for typical threat-hunter volumes direct calls are fine.
    """

    def __init__(self, db_path: str = DB_FILE):
        self.path = Path(db_path)
        self._conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            isolation_level=None,   # autocommit — each statement its own txn
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        logger.info(f"PersistenceLayer ready: {self.path}  "
                    f"({self.total_records()} existing records)")

    # ── Deduplication ─────────────────────────────────────────────────────────

    def is_seen(self, ip: str) -> bool:
        """Return True if this IP was processed in ANY previous session."""
        row = self._conn.execute(
            "SELECT 1 FROM seen_ips WHERE ip = ?", (ip,)
        ).fetchone()
        return row is not None

    def mark_seen(self, ip: str) -> None:
        ts = _now()
        self._conn.execute(
            "INSERT OR IGNORE INTO seen_ips (ip, first_seen) VALUES (?, ?)",
            (ip, ts),
        )

    # ── Intelligence log ──────────────────────────────────────────────────────

    def upsert_intel(self, scored: dict, enrichment: dict) -> None:
        """
        Insert a new intel record or refresh an existing one.
        On conflict: score, risk_level, reasons, enrichment, and last_seen are
        all updated; first_seen is preserved so we keep the original discovery ts.
        """
        now = _now()
        self._conn.execute(
            """
            INSERT INTO intel_log
                (ip, score, risk_level, country, org, reasons, enrichment,
                 first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                score      = excluded.score,
                risk_level = excluded.risk_level,
                reasons    = excluded.reasons,
                enrichment = excluded.enrichment,
                last_seen  = excluded.last_seen
            """,
            (
                scored["ip"],
                scored["score"],
                scored["risk_level"],
                scored.get("country", ""),
                scored.get("org", ""),
                json.dumps(scored.get("reasons", [])),
                json.dumps(enrichment),
                now,
                now,
            ),
        )

    def get_intel(self, ip: str) -> Optional[dict]:
        """Return stored intel dict for an IP, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM intel_log WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["reasons"]    = json.loads(d["reasons"]    or "[]")
        d["enrichment"] = json.loads(d["enrichment"] or "{}")
        return d

    # ── Analytics queries ─────────────────────────────────────────────────────

    def top_threats(self, limit: int = 10) -> list[dict]:
        """Top N IPs ranked by score."""
        rows = self._conn.execute(
            """
            SELECT ip, score, risk_level, country, org, last_seen
            FROM   intel_log
            ORDER  BY score DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def country_stats(self, limit: int = 15) -> list[dict]:
        """Threat counts and average score grouped by country."""
        rows = self._conn.execute(
            """
            SELECT country,
                   COUNT(*)    AS total,
                   AVG(score)  AS avg_score,
                   MAX(score)  AS max_score
            FROM   intel_log
            GROUP  BY country
            ORDER  BY total DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def risk_breakdown(self) -> dict:
        """Count of records per risk_level."""
        rows = self._conn.execute(
            "SELECT risk_level, COUNT(*) AS cnt FROM intel_log GROUP BY risk_level"
        ).fetchall()
        return {r["risk_level"]: r["cnt"] for r in rows}

    def total_records(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM intel_log"
        ).fetchone()[0]

    def total_seen(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM seen_ips"
        ).fetchone()[0]

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()
        logger.info("PersistenceLayer closed")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
