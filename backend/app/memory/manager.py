"""
manager.py — AgentMemoryManager for the AgentOps Security Mesh.

Provides a fully boundary-enforced, async Redis interface scoped per agent.
All reads and writes pass through MemoryBoundaryEnforcer before touching Redis.

Key namespacing:
    Memory entries  → "agent:{agent_id}:memory:{key}"
    Snapshots       → "agent:{agent_id}:snapshot:{snapshot_id}"

Environment variables:
    REDIS_URL          — Redis connection URL (default: redis://localhost:6379/0)
    REDIS_MAX_CONNS    — Connection pool size (default: 20)
    MEMORY_DEFAULT_TTL — Default TTL in seconds (default: 3600)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool

from backend.app.memory.boundaries import MemoryBoundaryEnforcer
from backend.app.memory.schemas import MemoryEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MEMORY_KEY_PATTERN: str = "agent:{agent_id}:memory:{key}"
MEMORY_SCAN_PATTERN: str = "agent:{agent_id}:memory:*"
SNAPSHOT_KEY_PATTERN: str = "agent:{agent_id}:snapshot:{snapshot_id}"

DEFAULT_TTL: int = int(os.environ.get("MEMORY_DEFAULT_TTL", "3600"))
REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
REDIS_MAX_CONNS: int = int(os.environ.get("REDIS_MAX_CONNS", "20"))


# ---------------------------------------------------------------------------
# AgentMemoryManager
# ---------------------------------------------------------------------------


class AgentMemoryManager:
    """
    Async Redis-backed key-value store scoped to individual agents.

    All operations are routed through ``MemoryBoundaryEnforcer`` to prevent
    cross-agent namespace breaches.  Values are serialised as JSON; if a value
    is not JSON-serialisable, callers should serialise it before passing.

    Args:
        enforcer:     A MemoryBoundaryEnforcer instance (shared across managers).
        redis_client: Optional pre-constructed async Redis client.
                      If None, a client is built from environment variables on
                      the first call to ``initialize()``.

    Usage::

        manager = AgentMemoryManager(enforcer=enforcer)
        await manager.initialize()

        await manager.set(agent_id, "plan:step_1", {"action": "fetch"})
        value = await manager.get(agent_id, "plan:step_1")
        await manager.delete(agent_id, "plan:step_1")

        await manager.close()
    """

    def __init__(
        self,
        enforcer: MemoryBoundaryEnforcer,
        redis_client: aioredis.Redis | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._redis: aioredis.Redis | None = redis_client
        self._pool: ConnectionPool | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Create the async Redis connection pool and verify connectivity.

        Must be called before any memory operations if no ``redis_client``
        was supplied at construction time.

        Raises:
            redis.exceptions.ConnectionError: If Redis is unreachable.
        """
        if self._redis is None:
            self._pool = ConnectionPool.from_url(
                REDIS_URL,
                max_connections=REDIS_MAX_CONNS,
                decode_responses=False,  # raw bytes; we handle encoding ourselves
            )
            self._redis = aioredis.Redis(connection_pool=self._pool)

        await self._redis.ping()
        logger.info("AgentMemoryManager connected to Redis: %s", REDIS_URL)

    async def close(self) -> None:
        """Close the Redis connection pool gracefully."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
        if self._pool is not None:
            await self._pool.aclose()
            self._pool = None
        logger.info("AgentMemoryManager Redis connection closed.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_redis_key(self, agent_id: str, key: str) -> str:
        """Build the namespaced Redis key for a given agent and logical key."""
        return MEMORY_KEY_PATTERN.format(agent_id=agent_id, key=key)

    def _make_scan_pattern(self, agent_id: str) -> str:
        """Build the SCAN pattern to iterate all keys for an agent."""
        return MEMORY_SCAN_PATTERN.format(agent_id=agent_id)

    @property
    def _client(self) -> aioredis.Redis:
        """Return the Redis client, raising if not initialised."""
        if self._redis is None:
            raise RuntimeError(
                "AgentMemoryManager is not initialised. " "Call `await manager.initialize()` first."
            )
        return self._redis

    @staticmethod
    def _serialise(value: Any) -> bytes:
        """Serialise a value to UTF-8 encoded JSON bytes."""
        return json.dumps(value, default=str).encode("utf-8")

    @staticmethod
    def _deserialise(raw: bytes | None) -> Any:
        """Deserialise JSON bytes; returns None for missing keys."""
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    async def _current_entry_count(self, agent_id: str) -> int:
        """
        Return the current number of memory keys held by an agent.

        Uses Redis SCAN to avoid blocking with KEYS.
        """
        pattern = self._make_scan_pattern(agent_id)
        count = 0
        async for _ in self._client.scan_iter(match=pattern, count=100):
            count += 1
        return count

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    async def get(self, agent_id: str, key: str) -> Any:
        """
        Retrieve the value stored at ``key`` in ``agent_id``'s namespace.

        Args:
            agent_id: Owning agent UUID.
            key:      Logical key (no namespace prefix).

        Returns:
            The deserialised value, or ``None`` if the key does not exist.

        Raises:
            MemoryBoundaryViolation: If the key violates the agent's boundary policy.
            RuntimeError:            If the manager is not initialised.
        """
        await self._enforcer.enforce(
            agent_id=agent_id,
            key=key,
            operation="get",
        )
        redis_key = self._make_redis_key(agent_id, key)
        raw = await self._client.get(redis_key)
        value = self._deserialise(raw)

        logger.debug("MEMORY GET: agent=%s key=%s found=%s", agent_id, key, raw is not None)
        return value

    async def set(
        self,
        agent_id: str,
        key: str,
        value: Any,
        ttl: int = DEFAULT_TTL,
    ) -> MemoryEntry:
        """
        Write ``value`` to ``key`` in ``agent_id``'s namespace.

        Args:
            agent_id: Owning agent UUID.
            key:      Logical key (no namespace prefix).
            value:    JSON-serialisable payload.
            ttl:      Key TTL in seconds; 0 means no expiry.

        Returns:
            The constructed MemoryEntry representing the written record.

        Raises:
            MemoryBoundaryViolation: If the key or capacity limits are violated.
            RuntimeError:            If the manager is not initialised.
        """
        serialised = self._serialise(value)
        current_count = await self._current_entry_count(agent_id)

        await self._enforcer.enforce(
            agent_id=agent_id,
            key=key,
            operation="set",
            current_entry_count=current_count,
            value_size_bytes=len(serialised),
        )

        redis_key = self._make_redis_key(agent_id, key)

        if ttl > 0:
            await self._client.setex(redis_key, ttl, serialised)
        else:
            await self._client.set(redis_key, serialised)

        entry = MemoryEntry(
            key=key,
            value=value,
            agent_id=agent_id,
            ttl_seconds=ttl,
        )

        logger.debug(
            "MEMORY SET: agent=%s key=%s ttl=%ds size=%dB",
            agent_id,
            key,
            ttl,
            len(serialised),
        )
        return entry

    async def delete(self, agent_id: str, key: str) -> bool:
        """
        Delete ``key`` from ``agent_id``'s namespace.

        Args:
            agent_id: Owning agent UUID.
            key:      Logical key to delete.

        Returns:
            True if the key existed and was deleted, False otherwise.

        Raises:
            MemoryBoundaryViolation: If the key violates the agent's boundary policy.
            RuntimeError:            If the manager is not initialised.
        """
        await self._enforcer.enforce(
            agent_id=agent_id,
            key=key,
            operation="delete",
        )
        redis_key = self._make_redis_key(agent_id, key)
        deleted = await self._client.delete(redis_key)

        logger.debug("MEMORY DELETE: agent=%s key=%s deleted=%s", agent_id, key, bool(deleted))
        return bool(deleted)

    async def list_keys(self, agent_id: str) -> list[str]:
        """
        List all logical keys currently held in ``agent_id``'s namespace.

        Uses SCAN to avoid blocking; strips the namespace prefix so callers
        receive bare logical keys.

        Args:
            agent_id: Owning agent UUID.

        Returns:
            Sorted list of logical key strings.

        Raises:
            RuntimeError: If the manager is not initialised.
        """
        pattern = self._make_scan_pattern(agent_id)
        prefix = f"agent:{agent_id}:memory:"
        keys: list[str] = []

        async for raw_key in self._client.scan_iter(match=pattern, count=100):
            decoded = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else raw_key
            logical_key = decoded.removeprefix(prefix)
            keys.append(logical_key)

        logger.debug("MEMORY LIST: agent=%s keys_found=%d", agent_id, len(keys))
        return sorted(keys)

    async def clear_agent_memory(self, agent_id: str) -> int:
        """
        Delete **all** memory keys for an agent.

        Intended for use during agent recovery or decommissioning.
        Does **not** enforce boundary checks — this is an administrative operation.

        Args:
            agent_id: Target agent UUID.

        Returns:
            Number of keys deleted.

        Raises:
            RuntimeError: If the manager is not initialised.
        """
        pattern = self._make_scan_pattern(agent_id)
        deleted_count = 0

        batch: list[bytes] = []
        async for raw_key in self._client.scan_iter(match=pattern, count=100):
            batch.append(raw_key)
            if len(batch) >= 500:
                await self._client.delete(*batch)
                deleted_count += len(batch)
                batch = []

        if batch:
            await self._client.delete(*batch)
            deleted_count += len(batch)

        logger.warning("MEMORY CLEAR: agent=%s keys_deleted=%d", agent_id, deleted_count)
        return deleted_count

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    async def get_memory_size(self, agent_id: str) -> int:
        """
        Calculate the total serialised size (bytes) of all values for an agent.

        Iterates keys with SCAN and uses Redis STRLEN for byte-accurate counts.

        Args:
            agent_id: Target agent UUID.

        Returns:
            Total byte size of all stored values.

        Raises:
            RuntimeError: If the manager is not initialised.
        """
        pattern = self._make_scan_pattern(agent_id)
        total_bytes = 0

        async for raw_key in self._client.scan_iter(match=pattern, count=100):
            size = await self._client.strlen(raw_key)
            total_bytes += size

        logger.debug("MEMORY SIZE: agent=%s total_bytes=%d", agent_id, total_bytes)
        return total_bytes

    async def get_entry(self, agent_id: str, key: str) -> MemoryEntry | None:
        """
        Retrieve a key as a fully-hydrated ``MemoryEntry`` including its TTL.

        Args:
            agent_id: Owning agent UUID.
            key:      Logical key.

        Returns:
            MemoryEntry with current TTL, or None if key does not exist.

        Raises:
            MemoryBoundaryViolation: On boundary breach.
            RuntimeError:            If the manager is not initialised.
        """
        value = await self.get(agent_id, key)
        if value is None:
            return None

        redis_key = self._make_redis_key(agent_id, key)
        ttl_remaining = await self._client.ttl(redis_key)
        ttl = max(0, ttl_remaining) if ttl_remaining > 0 else 0

        return MemoryEntry(
            key=key,
            value=value,
            agent_id=agent_id,
            ttl_seconds=ttl,
        )

    async def set_raw_snapshot_bytes(self, redis_key: str, data: bytes, ttl: int) -> None:
        """
        Write raw bytes directly to Redis under a fully-qualified key.

        Used exclusively by MemorySnapshotManager to persist compressed
        snapshot payloads without passing through boundary enforcement.

        Args:
            redis_key: Fully-qualified Redis key (not a logical key).
            data:      Raw bytes to store.
            ttl:       TTL in seconds.
        """
        await self._client.setex(redis_key, ttl, data)

    async def get_raw_snapshot_bytes(self, redis_key: str) -> bytes | None:
        """
        Read raw bytes from a fully-qualified Redis key.

        Used exclusively by MemorySnapshotManager.

        Args:
            redis_key: Fully-qualified Redis key.

        Returns:
            Raw bytes or None.
        """
        return await self._client.get(redis_key)

    async def scan_snapshot_keys(self, agent_id: str) -> list[str]:
        """
        Return all snapshot Redis keys for an agent.

        Args:
            agent_id: Target agent UUID.

        Returns:
            List of fully-qualified snapshot Redis keys.
        """
        pattern = f"agent:{agent_id}:snapshot:*"
        keys: list[str] = []
        async for raw_key in self._client.scan_iter(match=pattern, count=100):
            decoded = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else raw_key
            keys.append(decoded)
        return keys
