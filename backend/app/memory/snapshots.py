"""
snapshots.py — MemorySnapshotManager for the AgentOps Security Mesh.

Provides point-in-time capture and restoration of agent memory, with
msgpack + zlib compression and a 24-hour Redis TTL.

Storage layout:
    Snapshot data   → "agent:{agent_id}:snapshot:{snapshot_id}"  (compressed bytes)
    Snapshot index  → "agent:{agent_id}:snapshot:index"           (JSON list of metadata)

Snapshot lifecycle:
    take_snapshot()     → captures all current keys → compresses → writes to Redis
    restore_snapshot()  → reads + decompresses → clears existing memory → replays entries
    list_snapshots()    → reads the index entry → returns MemorySnapshot headers
    auto_snapshot()     → wrapper: takes a snapshot with reason "auto:pre-operation"
"""

from __future__ import annotations

import json
import logging
import zlib
from datetime import datetime, timezone
from typing import Any

import msgpack

from backend.app.memory.manager import AgentMemoryManager
from backend.app.memory.schemas import MemoryEntry, MemorySnapshot

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SNAPSHOT_TTL_SECONDS: int = 24 * 3600  # 24 hours
SNAPSHOT_INDEX_KEY_PATTERN: str = "agent:{agent_id}:snapshot:index"
SNAPSHOT_INDEX_TTL_SECONDS: int = 7 * 24 * 3600  # 7 days (outlives individual snapshots)

#: msgpack + zlib compression level (1 = fastest, 9 = smallest)
COMPRESS_LEVEL: int = 6


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _pack(data: Any) -> bytes:
    """Serialise ``data`` to msgpack bytes and compress with zlib."""
    raw = msgpack.packb(data, use_bin_type=True)
    return zlib.compress(raw, level=COMPRESS_LEVEL)


def _unpack(compressed: bytes) -> Any:
    """Decompress zlib bytes and deserialise msgpack."""
    raw = zlib.decompress(compressed)
    return msgpack.unpackb(raw, raw=False)


def _entry_to_dict(entry: MemoryEntry) -> dict:
    """Convert a MemoryEntry to a msgpack-friendly dict."""
    return {
        "key": entry.key,
        "value": entry.value,
        "agent_id": entry.agent_id,
        "timestamp": entry.timestamp.isoformat(),
        "ttl_seconds": entry.ttl_seconds,
        "encrypted": entry.encrypted,
        "metadata": entry.metadata,
    }


def _dict_to_entry(d: dict) -> MemoryEntry:
    """Reconstruct a MemoryEntry from a deserialized dict."""
    ts = d.get("timestamp")
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    return MemoryEntry(
        key=d["key"],
        value=d["value"],
        agent_id=d["agent_id"],
        timestamp=ts or datetime.now(timezone.utc),
        ttl_seconds=d.get("ttl_seconds", 3600),
        encrypted=d.get("encrypted", False),
        metadata=d.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# MemorySnapshotManager
# ---------------------------------------------------------------------------


class MemorySnapshotManager:
    """
    Manages point-in-time snapshots of agent memory for rollback and audit.

    Snapshots are stored as msgpack + zlib compressed payloads in Redis
    with a 24-hour TTL.  A lightweight JSON index is maintained per agent
    to support fast listing without decompressing every snapshot.

    Args:
        memory_manager: An initialised ``AgentMemoryManager`` instance.

    Usage::

        snap_manager = MemorySnapshotManager(memory_manager=memory_mgr)

        # Take a snapshot before a risky operation
        snapshot = await snap_manager.auto_snapshot(agent_id)

        # List all snapshots
        snapshots = await snap_manager.list_snapshots(agent_id)

        # Roll back to a previous snapshot
        await snap_manager.restore_snapshot(agent_id, snapshot.snapshot_id)
    """

    def __init__(self, memory_manager: AgentMemoryManager) -> None:
        self._mgr = memory_manager

    # ------------------------------------------------------------------
    # Index helpers
    # ------------------------------------------------------------------

    def _index_key(self, agent_id: str) -> str:
        """Redis key for the snapshot index list."""
        return SNAPSHOT_INDEX_KEY_PATTERN.format(agent_id=agent_id)

    async def _append_to_index(self, agent_id: str, snapshot: MemorySnapshot) -> None:
        """
        Append snapshot metadata to the agent's snapshot index.

        The index stores lightweight headers (no entry payloads) as a
        JSON-encoded list in a single Redis key.
        """
        index_key = self._index_key(agent_id)
        raw = await self._mgr.get_raw_snapshot_bytes(index_key)

        if raw:
            existing: list[dict] = json.loads(raw.decode("utf-8"))
        else:
            existing = []

        existing.append(
            {
                "snapshot_id": snapshot.snapshot_id,
                "agent_id": snapshot.agent_id,
                "timestamp": snapshot.timestamp.isoformat(),
                "reason": snapshot.reason,
                "entry_count": snapshot.entry_count,
            }
        )

        # Keep only the 50 most recent snapshot records in the index
        existing = existing[-50:]

        await self._mgr.set_raw_snapshot_bytes(
            redis_key=index_key,
            data=json.dumps(existing).encode("utf-8"),
            ttl=SNAPSHOT_INDEX_TTL_SECONDS,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def take_snapshot(
        self,
        agent_id: str,
        reason: str,
    ) -> MemorySnapshot:
        """
        Capture the full current memory state of ``agent_id`` as a snapshot.

        Steps:
        1. List all current logical keys for the agent.
        2. Fetch each entry with its remaining TTL.
        3. Build a MemorySnapshot.
        4. Compress and write to Redis (SNAPSHOT_TTL_SECONDS TTL).
        5. Update the agent's snapshot index.

        Args:
            agent_id: Target agent UUID.
            reason:   Human-readable reason for taking the snapshot.

        Returns:
            The persisted MemorySnapshot (entries fully populated).

        Raises:
            RuntimeError: If the memory manager is not initialised.
        """
        logical_keys = await self._mgr.list_keys(agent_id)
        entries: list[MemoryEntry] = []

        for key in logical_keys:
            entry = await self._mgr.get_entry(agent_id, key)
            if entry is not None:
                entries.append(entry)

        snapshot = MemorySnapshot(
            agent_id=agent_id,
            entries=entries,
            reason=reason,
        )

        # Serialise + compress
        payload = _pack(
            {
                "snapshot_id": snapshot.snapshot_id,
                "agent_id": snapshot.agent_id,
                "timestamp": snapshot.timestamp.isoformat(),
                "reason": snapshot.reason,
                "entries": [_entry_to_dict(e) for e in snapshot.entries],
            }
        )

        await self._mgr.set_raw_snapshot_bytes(
            redis_key=snapshot.redis_key,
            data=payload,
            ttl=SNAPSHOT_TTL_SECONDS,
        )

        await self._append_to_index(agent_id, snapshot)

        logger.info(
            "Snapshot taken: agent=%s snapshot_id=%s entries=%d reason=%r compressed_bytes=%d",
            agent_id,
            snapshot.snapshot_id,
            snapshot.entry_count,
            reason,
            len(payload),
        )
        return snapshot

    async def restore_snapshot(
        self,
        agent_id: str,
        snapshot_id: str,
    ) -> MemorySnapshot:
        """
        Roll back an agent's memory to a previously captured snapshot.

        Steps:
        1. Load and decompress the snapshot from Redis.
        2. Clear all current memory for the agent (via ``clear_agent_memory``).
        3. Replay each MemoryEntry from the snapshot back into Redis,
           preserving original TTLs (capped to the remaining useful lifetime).

        Args:
            agent_id:    Target agent UUID.
            snapshot_id: UUID of the snapshot to restore.

        Returns:
            The restored MemorySnapshot.

        Raises:
            KeyError:    If the snapshot does not exist (expired or invalid ID).
            RuntimeError: If the memory manager is not initialised.
        """
        snapshot_redis_key = f"agent:{agent_id}:snapshot:{snapshot_id}"
        raw = await self._mgr.get_raw_snapshot_bytes(snapshot_redis_key)

        if raw is None:
            raise KeyError(
                f"Snapshot not found (expired or invalid): "
                f"agent={agent_id} snapshot_id={snapshot_id}"
            )

        data = _unpack(raw)
        entries = [_dict_to_entry(e) for e in data.get("entries", [])]
        snapshot = MemorySnapshot(
            snapshot_id=data["snapshot_id"],
            agent_id=data["agent_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            reason=data["reason"],
            entries=entries,
        )

        # Clear existing memory state
        deleted = await self._mgr.clear_agent_memory(agent_id)
        logger.info(
            "Restore: cleared %d existing keys for agent=%s", deleted, agent_id
        )

        # Replay entries — use original TTL or default if 0
        for entry in snapshot.entries:
            ttl = entry.ttl_seconds if entry.ttl_seconds > 0 else 3600
            try:
                await self._mgr.set(
                    agent_id=agent_id,
                    key=entry.key,
                    value=entry.value,
                    ttl=ttl,
                )
            except Exception as exc:  # noqa: BLE001
                # Log but do not abort restore on individual key failure
                logger.warning(
                    "Restore: failed to replay key '%s' for agent=%s: %s",
                    entry.key,
                    agent_id,
                    exc,
                )

        logger.info(
            "Snapshot restored: agent=%s snapshot_id=%s entries_replayed=%d",
            agent_id,
            snapshot_id,
            snapshot.entry_count,
        )
        return snapshot

    async def list_snapshots(self, agent_id: str) -> list[MemorySnapshot]:
        """
        Return lightweight MemorySnapshot objects for all stored snapshots.

        Reads from the JSON index (no decompression required).  Entries
        lists will be empty in the returned objects; call ``restore_snapshot``
        to get a fully populated snapshot.

        Args:
            agent_id: Target agent UUID.

        Returns:
            List of MemorySnapshot headers, newest-first.

        Raises:
            RuntimeError: If the memory manager is not initialised.
        """
        index_key = self._index_key(agent_id)
        raw = await self._mgr.get_raw_snapshot_bytes(index_key)

        if not raw:
            return []

        records: list[dict] = json.loads(raw.decode("utf-8"))
        snapshots: list[MemorySnapshot] = []

        for record in reversed(records):  # newest first
            snapshots.append(
                MemorySnapshot(
                    snapshot_id=record["snapshot_id"],
                    agent_id=record["agent_id"],
                    timestamp=datetime.fromisoformat(record["timestamp"]),
                    reason=record["reason"],
                    entries=[],  # headers only — call restore to hydrate
                )
            )

        return snapshots

    async def auto_snapshot(self, agent_id: str) -> MemorySnapshot:
        """
        Take an automatic pre-operation snapshot.

        Should be called before any risky memory operation (e.g., bulk clear,
        untrusted tool execution, or agent role change).

        Args:
            agent_id: Target agent UUID.

        Returns:
            The persisted MemorySnapshot.
        """
        logger.info("Auto-snapshot triggered for agent=%s", agent_id)
        return await self.take_snapshot(
            agent_id=agent_id,
            reason="auto:pre-operation",
        )

    async def get_snapshot(
        self, agent_id: str, snapshot_id: str
    ) -> MemorySnapshot:
        """
        Load and fully decompress a single snapshot by ID.

        Args:
            agent_id:    Target agent UUID.
            snapshot_id: UUID of the snapshot to load.

        Returns:
            Fully populated MemorySnapshot (entries hydrated).

        Raises:
            KeyError:    If the snapshot does not exist.
            RuntimeError: If the memory manager is not initialised.
        """
        snapshot_redis_key = f"agent:{agent_id}:snapshot:{snapshot_id}"
        raw = await self._mgr.get_raw_snapshot_bytes(snapshot_redis_key)

        if raw is None:
            raise KeyError(
                f"Snapshot not found: agent={agent_id} snapshot_id={snapshot_id}"
            )

        data = _unpack(raw)
        entries = [_dict_to_entry(e) for e in data.get("entries", [])]

        return MemorySnapshot(
            snapshot_id=data["snapshot_id"],
            agent_id=data["agent_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            reason=data["reason"],
            entries=entries,
        )

    async def delete_snapshot(self, agent_id: str, snapshot_id: str) -> bool:
        """
        Delete a snapshot from Redis and remove it from the index.

        Args:
            agent_id:    Target agent UUID.
            snapshot_id: UUID of the snapshot to delete.

        Returns:
            True if the snapshot existed and was deleted, False otherwise.
        """
        snapshot_redis_key = f"agent:{agent_id}:snapshot:{snapshot_id}"
        raw = await self._mgr.get_raw_snapshot_bytes(snapshot_redis_key)
        if raw is None:
            return False

        # Delete the snapshot blob
        await self._mgr._client.delete(snapshot_redis_key)  # noqa: SLF001 — internal bypass

        # Update the index
        index_key = self._index_key(agent_id)
        index_raw = await self._mgr.get_raw_snapshot_bytes(index_key)
        if index_raw:
            records: list[dict] = json.loads(index_raw.decode("utf-8"))
            records = [r for r in records if r["snapshot_id"] != snapshot_id]
            await self._mgr.set_raw_snapshot_bytes(
                redis_key=index_key,
                data=json.dumps(records).encode("utf-8"),
                ttl=SNAPSHOT_INDEX_TTL_SECONDS,
            )

        logger.info(
            "Snapshot deleted: agent=%s snapshot_id=%s", agent_id, snapshot_id
        )
        return True
