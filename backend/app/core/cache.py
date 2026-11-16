"""Small async key-value store with TTL, used for threat-intel caching and rate limiting.

Redis in real deployments; an in-process dictionary when `REDIS_URL` is empty or Redis
is unreachable, so local development and tests need no services. The in-memory store is
per-process, so rate limits are only exact with a single worker; use Redis otherwise.
"""

import logging
import time
from typing import Protocol

logger = logging.getLogger(__name__)


class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int) -> None: ...
    async def incr(self, key: str, ttl: int) -> int: ...


class MemoryCache:
    """Dictionary-backed fallback. Expired keys are dropped lazily and on a size cap."""

    def __init__(self, max_keys: int = 50_000) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._max_keys = max_keys

    def _live(self, key: str) -> str | None:
        item = self._data.get(key)
        if item is None:
            return None
        if item[0] < time.monotonic():
            del self._data[key]
            return None
        return item[1]

    def _evict(self) -> None:
        if len(self._data) < self._max_keys:
            return
        now = time.monotonic()
        self._data = {k: v for k, v in self._data.items() if v[0] >= now}
        if len(self._data) >= self._max_keys:
            self._data.clear()

    async def get(self, key: str) -> str | None:
        return self._live(key)

    async def set(self, key: str, value: str, ttl: int) -> None:
        self._evict()
        self._data[key] = (time.monotonic() + ttl, value)

    async def incr(self, key: str, ttl: int) -> int:
        current = self._live(key)
        if current is None:
            self._evict()
            self._data[key] = (time.monotonic() + ttl, "1")
            return 1
        expires = self._data[key][0]
        value = int(current) + 1
        self._data[key] = (expires, str(value))
        return value


class RedisCache:
    """Redis-backed store. Any Redis error degrades to the in-memory store for that call."""

    def __init__(self, url: str) -> None:
        import redis.asyncio as redis

        self._redis = redis.from_url(url, decode_responses=True, socket_timeout=1.0)
        self._fallback = MemoryCache()

    async def get(self, key: str) -> str | None:
        try:
            return await self._redis.get(key)
        except Exception:  # noqa: BLE001 - cache must never break a scan
            logger.warning("Redis unavailable for GET; using in-memory fallback")
            return await self._fallback.get(key)

    async def set(self, key: str, value: str, ttl: int) -> None:
        try:
            await self._redis.set(key, value, ex=ttl)
        except Exception:  # noqa: BLE001
            logger.warning("Redis unavailable for SET; using in-memory fallback")
            await self._fallback.set(key, value, ttl)

    async def incr(self, key: str, ttl: int) -> int:
        try:
            value = await self._redis.incr(key)
            if value == 1:
                await self._redis.expire(key, ttl)
            return int(value)
        except Exception:  # noqa: BLE001
            logger.warning("Redis unavailable for INCR; using in-memory fallback")
            return await self._fallback.incr(key, ttl)


def build_cache(redis_url: str) -> Cache:
    """Pick the cache backend from configuration."""
    return RedisCache(redis_url) if redis_url else MemoryCache()
