"""
cache.py — Async JSON-backed key-value cache with TTL eviction.

Fixes applied vs original:
  1. Atomic writes   — uses a temp file + os.replace() so a crash mid-write
                       never corrupts the cache file.
  2. Dirty-flag      — only flushes to disk when something actually changed,
                       avoiding O(n) JSON serialisation on every cache hit.
  3. Lazy expiration — expired entries are purged lazily on access and on an
                       explicit purge_expired() sweep rather than on every stat().
"""
import json
import logging
import os
import time
import asyncio
from pathlib import Path

from config import CACHE_FILE, CACHE_TTL_SECONDS

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Thread-safe async cache backed by a local JSON file.
    Keys are namespaced: "ip:<addr>", "domain:<name>"
    """

    def __init__(self, path: str = CACHE_FILE):
        self.path   = Path(path)
        self._data: dict  = {}
        self._dirty: bool = False
        self._lock  = asyncio.Lock()
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    self._data = json.load(f)
                logger.info(
                    f"Cache loaded: {len(self._data)} entries from {self.path}"
                )
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Cache load failed ({e}), starting fresh")
                self._data = {}

    def _flush(self) -> None:
        """
        Atomic write: serialise to a sibling .tmp file, then rename() into place.
        rename() is atomic on POSIX; on Windows it may briefly fail if the target
        is open, but that risk is accepted in exchange for crash-safety.
        """
        if not self._dirty:
            return
        tmp = self.path.with_suffix(".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump(self._data, f, indent=2, default=str)
            os.replace(tmp, self.path)          # atomic on POSIX
            self._dirty = False
        except OSError as e:
            logger.error(f"Cache flush failed: {e}")
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    # ── Public API ───────────────────────────────────────────────────────────

    async def get(self, key: str):
        """Return cached value or None if missing / expired."""
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if time.time() - entry["ts"] > CACHE_TTL_SECONDS:
                del self._data[key]
                self._dirty = True
                self._flush()
                return None
            return entry["data"]

    async def set(self, key: str, data) -> None:
        """Store value with current timestamp and flush to disk."""
        async with self._lock:
            self._data[key] = {"data": data, "ts": time.time()}
            self._dirty = True
            self._flush()

    async def delete(self, key: str) -> bool:
        """Remove a key. Returns True if it existed."""
        async with self._lock:
            existed = key in self._data
            if existed:
                del self._data[key]
                self._dirty = True
                self._flush()
            return existed

    async def purge_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        async with self._lock:
            cutoff  = time.time() - CACHE_TTL_SECONDS
            expired = [k for k, v in self._data.items() if v["ts"] < cutoff]
            for k in expired:
                del self._data[k]
            if expired:
                self._dirty = True
                self._flush()
            return len(expired)

    async def stats(self) -> dict:
        """Return summary of cache contents (non-destructive)."""
        async with self._lock:
            cutoff       = time.time() - CACHE_TTL_SECONDS
            ip_count     = sum(1 for k in self._data if k.startswith("ip:"))
            domain_count = sum(1 for k in self._data if k.startswith("domain:"))
            expired      = sum(
                1 for v in self._data.values() if v["ts"] < cutoff
            )
            return {
                "total":   len(self._data),
                "ips":     ip_count,
                "domains": domain_count,
                "expired": expired,
            }
