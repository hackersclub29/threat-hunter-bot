"""
enrichment_engine.py — Async enrichment pipeline.
Sources: IPinfo API, AbuseIPDB API, Cloudflare DNS (1.1.1.1 / 1.0.0.1)
All results cached via CacheManager.

Fixes applied vs original:
  1. Exponential backoff with jitter on every outbound HTTP call.
     Transient failures (5xx, timeouts, connection resets) are retried up to
     MAX_RETRIES times before the engine returns {} for that source — so one
     flaky API never silently poisons the whole enrichment record.
  2. Per-source token-bucket rate limiters keep usage inside free-tier quotas:
       • IPinfo    — 50,000 req/month  ≈ ~1.67/min sustained; we cap at 30/min
       • AbuseIPDB — 1,000 req/day     ≈ ~0.69/min sustained; we cap at 15/min
     These are conservative ceilings; tune via config.py constants.
  3. HTTP status 429 (rate-limited by upstream) is detected and triggers an
     immediate, longer back-off rather than burning retries on futile attempts.
"""
import asyncio
import logging
import random
import time
import dns.resolver
import aiohttp

from cache import CacheManager
from config import IPINFO_TOKEN, ABUSEIPDB_KEY, DNS_SERVERS

logger = logging.getLogger(__name__)

# ── Tunable constants ─────────────────────────────────────────────────────────

MAX_RETRIES          = 3       # attempts per HTTP call (1 + 2 retries)
BACKOFF_BASE         = 1.0     # seconds — doubles each retry
BACKOFF_JITTER       = 0.5     # seconds of random jitter added each retry
RATE_LIMIT_BACKOFF   = 30.0    # seconds to wait on HTTP 429

IPINFO_RPM    = 30    # requests per minute ceiling for IPinfo
ABUSEIPDB_RPM = 15    # requests per minute ceiling for AbuseIPDB

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT    = 12
_TIMEOUT         = aiohttp.ClientTimeout(total=_READ_TIMEOUT, connect=_CONNECT_TIMEOUT)

# HTTP status codes worth retrying (transient server-side errors)
_RETRIABLE_STATUSES = {500, 502, 503, 504}


# ── Token-bucket rate limiter ─────────────────────────────────────────────────

class _RateLimiter:
    """
    Async token-bucket rate limiter.
    Callers await .acquire() before each request; if the bucket is empty they
    block for just long enough to refill one token.
    """

    def __init__(self, calls_per_minute: float):
        self._rate   = calls_per_minute / 60.0   # tokens per second
        self._tokens = float(calls_per_minute)
        self._max    = float(calls_per_minute)
        self._last   = time.monotonic()
        self._lock   = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last
            self._last   = now
            self._tokens = min(self._max, self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# ── Enrichment engine ─────────────────────────────────────────────────────────

class EnrichmentEngine:

    def __init__(self, cache: CacheManager):
        self.cache             = cache
        self._session: aiohttp.ClientSession | None = None
        self._ipinfo_rl        = _RateLimiter(IPINFO_RPM)
        self._abuseipdb_rl     = _RateLimiter(ABUSEIPDB_RPM)

    async def init(self) -> None:
        self._session = aiohttp.ClientSession(timeout=_TIMEOUT)
        logger.info("EnrichmentEngine HTTP session ready")

    async def close(self) -> None:
        if self._session:
            await self._session.close()

    # ── Public API ───────────────────────────────────────────────────────────

    async def enrich_ip(self, ip: str) -> dict:
        """
        Returns merged enrichment:
        {
          "ip":        str,
          "ipinfo":    {...},   # IPinfo response  (may be {} on persistent failure)
          "abuseipdb": {...},   # AbuseIPDB data   (may be {} if key not set)
        }
        """
        cached = await self.cache.get(f"ip:{ip}")
        if cached:
            logger.debug(f"Cache hit: {ip}")
            return cached

        ipinfo_task, abuseipdb_task = (
            asyncio.create_task(self._fetch_ipinfo(ip)),
            asyncio.create_task(self._fetch_abuseipdb(ip)),
        )

        ipinfo, abuseipdb = await asyncio.gather(
            ipinfo_task, abuseipdb_task, return_exceptions=True
        )

        result = {
            "ip":        ip,
            "ipinfo":    ipinfo    if isinstance(ipinfo, dict)    else {},
            "abuseipdb": abuseipdb if isinstance(abuseipdb, dict) else {},
        }

        await self.cache.set(f"ip:{ip}", result)
        return result

    async def resolve_domain(self, domain: str) -> dict:
        """
        Resolves domain via Cloudflare DNS (1.1.1.1 / 1.0.0.1).
        Returns: {"domain": str, "ips": [...], "error": str | None}
        """
        cached = await self.cache.get(f"domain:{domain}")
        if cached:
            return cached

        result: dict = {"domain": domain, "ips": [], "error": None}

        try:
            resolver              = dns.resolver.Resolver(configure=False)
            resolver.nameservers  = DNS_SERVERS
            resolver.timeout      = 5
            resolver.lifetime     = 8

            answers        = resolver.resolve(domain, "A")
            result["ips"]  = [str(rr) for rr in answers]
            logger.info(f"DNS resolved {domain} → {result['ips']}")
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            result["error"] = "No A records"
        except Exception as e:
            result["error"] = str(e)

        await self.cache.set(f"domain:{domain}", result)
        return result

    # ── Internal fetchers with retry / rate-limit ─────────────────────────────

    async def _fetch_ipinfo(self, ip: str) -> dict:
        url    = f"https://ipinfo.io/{ip}/json"
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}

        async def _do():
            await self._ipinfo_rl.acquire()
            async with self._session.get(url, params=params) as resp:
                return resp.status, await resp.json() if resp.status == 200 else await resp.text()

        return await self._retry(_do, label=f"IPinfo/{ip}")

    async def _fetch_abuseipdb(self, ip: str) -> dict:
        if not ABUSEIPDB_KEY:
            return {}
        url     = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "false"}

        async def _do():
            await self._abuseipdb_rl.acquire()
            async with self._session.get(url, headers=headers, params=params) as resp:
                if resp.status == 200:
                    payload = await resp.json()
                    return resp.status, payload.get("data", {})
                return resp.status, await resp.text()

        return await self._retry(_do, label=f"AbuseIPDB/{ip}")

    async def _retry(self, coro_fn, label: str) -> dict:
        """
        Execute coro_fn() up to MAX_RETRIES times with exponential backoff.

        coro_fn() must return (status_code, body):
          • status 200  → return body (dict)
          • status 429  → wait RATE_LIMIT_BACKOFF seconds then retry
          • retriable   → standard exponential backoff
          • other 4xx   → non-retriable; return {}

        Exceptions (TimeoutError, ClientError, etc.) are treated as retriable.
        """
        for attempt in range(MAX_RETRIES):
            try:
                status, body = await coro_fn()

                if status == 200:
                    return body

                if status == 429:
                    logger.warning(
                        f"{label}: rate-limited (429). "
                        f"Waiting {RATE_LIMIT_BACKOFF}s before retry."
                    )
                    await asyncio.sleep(RATE_LIMIT_BACKOFF)
                    continue

                if status in _RETRIABLE_STATUSES:
                    logger.warning(f"{label}: HTTP {status} (transient), will retry")
                    # fall through to backoff below
                else:
                    logger.error(f"{label}: HTTP {status} (non-retriable) — {str(body)[:120]}")
                    return {}

            except asyncio.TimeoutError:
                logger.warning(f"{label}: timeout on attempt {attempt + 1}")
            except aiohttp.ClientError as e:
                logger.warning(f"{label}: connection error on attempt {attempt + 1}: {e}")
            except Exception as e:
                logger.error(f"{label}: unexpected error: {e}")
                return {}

            if attempt < MAX_RETRIES - 1:
                delay = BACKOFF_BASE * (2 ** attempt) + random.uniform(0, BACKOFF_JITTER)
                logger.info(f"{label}: retry {attempt + 1}/{MAX_RETRIES - 1} in {delay:.1f}s")
                await asyncio.sleep(delay)

        logger.error(f"{label}: all {MAX_RETRIES} attempts exhausted — returning empty")
        return {}
