"""
cache.py — Neo4j Query Result Cache with TTL.

Wraps frequently-executed Neo4j read queries with a Redis-backed
cache layer using a configurable TTL (default: 30 seconds).
This prevents hammering Neo4j with identical queries from
multiple concurrent WebSocket clients.
"""

from __future__ import annotations

import json
import logging
from functools import wraps
from typing import Any, Callable

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 30  # seconds


class Neo4jQueryCache:
    """
    Redis-backed TTL cache for Neo4j read query results.

    Args:
        redis_client:   Async Redis client.
        ttl:            Cache lifetime in seconds (default: 30s).
        key_prefix:     Redis key prefix for all cache entries.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        ttl: int = _DEFAULT_TTL,
        key_prefix: str = "neo4j:cache:",
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl
        self._prefix = key_prefix

    def _make_key(self, query_id: str, params: dict[str, Any]) -> str:
        """Generate a deterministic Redis key from query name and params."""
        # Stable JSON serialization for key hashing
        param_str = json.dumps(params, sort_keys=True, default=str)
        return f"{self._prefix}{query_id}:{hash(param_str)}"

    async def get(self, query_id: str, params: dict[str, Any]) -> Any | None:
        """Fetch a cached result, or return None on cache miss."""
        key = self._make_key(query_id, params)
        try:
            raw = await self._redis.get(key)
            if raw:
                logger.debug("Cache HIT: %s", key)
                return json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cache get error for %s: %s", key, exc)
        return None

    async def set(self, query_id: str, params: dict[str, Any], result: Any) -> None:
        """Store a query result with the configured TTL."""
        key = self._make_key(query_id, params)
        try:
            await self._redis.setex(key, self._ttl, json.dumps(result, default=str))
            logger.debug("Cache SET: %s (TTL=%ds)", key, self._ttl)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cache set error for %s: %s", key, exc)

    async def invalidate(self, query_id: str) -> None:
        """Delete all cached entries for a given query name."""
        pattern = f"{self._prefix}{query_id}:*"
        keys = await self._redis.keys(pattern)
        if keys:
            await self._redis.delete(*keys)
            logger.info("Cache invalidated %d key(s) for query: %s", len(keys), query_id)


def cached_query(query_id: str):
    """
    Decorator factory for Neo4j async methods that should use the cache.

    Usage::

        @cached_query("get_full_graph")
        async def get_full_graph(self) -> ...:
            ...

    The decorated method must have `self._cache: Neo4jQueryCache` available.
    The params are derived from the function's keyword arguments.
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            cache: Neo4jQueryCache | None = getattr(self, "_cache", None)
            if cache is None:
                return await fn(self, *args, **kwargs)

            # Build a params dict from positional + keyword args
            import inspect
            sig = inspect.signature(fn)
            bound = sig.bind(self, *args, **kwargs)
            bound.apply_defaults()
            params = {k: v for k, v in bound.arguments.items() if k != "self"}

            cached = await cache.get(query_id, params)
            if cached is not None:
                return cached

            result = await fn(self, *args, **kwargs)

            # Only cache serializable results (skip complex objects)
            try:
                await cache.set(query_id, params, result)
            except (TypeError, ValueError):
                logger.debug("Result for %s is not JSON-serializable, skipping cache.", query_id)

            return result
        return wrapper
    return decorator
