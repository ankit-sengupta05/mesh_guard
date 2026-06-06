"""
deduplication.py — WebSocket Message Deduplication Layer.

Prevents the same SecurityEvent from being broadcast to clients
more than once per session, even if the Redis Pub/Sub stream
delivers duplicates under high load.

Uses a Redis sorted set as a server-side seen-set with TTL-based
pruning so memory stays bounded.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import redis.asyncio as aioredis

if TYPE_CHECKING:
    from backend.app.security.events import SecurityEvent

logger = logging.getLogger(__name__)

_SEEN_SET_KEY = "ws:dedup:seen_events"
_WINDOW_SECONDS = 300  # 5-minute dedup window


class WebSocketDeduplicator:
    """
    Server-side event deduplicator backed by a Redis sorted set.

    The sorted set stores event_ids with their publish timestamp as the
    score. A periodic prune removes entries older than the dedup window.

    Args:
        redis_client:   Async Redis client.
        window_seconds: How long to remember a seen event_id.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        window_seconds: int = _WINDOW_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._window = window_seconds

    async def is_duplicate(self, event_id: str) -> bool:
        """
        Return True if this event_id was already seen within the dedup window.
        Side effect: marks the event_id as seen if it's new.
        """
        now = time.time()
        cutoff = now - self._window

        # Use a Redis pipeline for atomicity
        async with self._redis.pipeline() as pipe:
            # Check membership
            pipe.zscore(_SEEN_SET_KEY, event_id)
            # Add with current timestamp (ZADD NX = only if not exists)
            pipe.zadd(_SEEN_SET_KEY, {event_id: now}, nx=True)
            # Remove expired entries
            pipe.zremrangebyscore(_SEEN_SET_KEY, "-inf", cutoff)
            results = await pipe.execute()

        existing_score = results[0]

        if existing_score is not None:
            logger.debug("Duplicate event suppressed: %s", event_id)
            return True

        return False

    async def filter_events(
        self, events: list["SecurityEvent"]
    ) -> list["SecurityEvent"]:
        """
        Filter a batch of events, returning only non-duplicate ones.
        """
        unique = []
        for event in events:
            if not await self.is_duplicate(event.event_id):
                unique.append(event)
        return unique


class RedisPipelineBatcher:
    """
    Batches high-frequency metric updates into Redis pipelines
    to reduce round-trip overhead under load.

    Usage::

        async with RedisPipelineBatcher(redis) as batcher:
            await batcher.hset("metrics:agent_x", "tool_calls", 42)
            await batcher.incr("metrics:total_scans")
        # Pipeline executes atomically on __aexit__

    Args:
        redis_client: Async Redis client.
    """

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._pipe: aioredis.client.Pipeline | None = None

    async def __aenter__(self) -> "RedisPipelineBatcher":
        self._pipe = self._redis.pipeline()
        return self

    async def __aexit__(self, *_) -> None:
        if self._pipe is not None:
            try:
                await self._pipe.execute()
            except Exception as exc:  # noqa: BLE001
                logger.error("Pipeline execution error: %s", exc)
            finally:
                self._pipe = None

    async def hset(self, key: str, field: str, value: str | float | int) -> None:
        """Queue an HSET command."""
        if self._pipe is not None:
            self._pipe.hset(key, field, value)

    async def incr(self, key: str) -> None:
        """Queue an INCR command."""
        if self._pipe is not None:
            self._pipe.incr(key)

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        """Queue a ZADD command."""
        if self._pipe is not None:
            self._pipe.zadd(key, mapping)

    async def expire(self, key: str, seconds: int) -> None:
        """Queue an EXPIRE command."""
        if self._pipe is not None:
            self._pipe.expire(key, seconds)
