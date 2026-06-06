"""
schemas.py — Pydantic data models for the AgentOps Security Mesh memory system.

Defines the canonical shapes for memory entries, snapshots, and per-agent
boundary configuration.  All timestamps are UTC-aware.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# MemoryEntry
# ---------------------------------------------------------------------------


class MemoryEntry(BaseModel):
    """
    A single key-value record stored in an agent's Redis namespace.

    Attributes:
        key:         Logical key (without namespace prefix).
        value:       Arbitrary JSON-serialisable value.
        agent_id:    Owning agent UUID.
        timestamp:   UTC time the entry was written.
        ttl_seconds: Positive TTL in seconds; 0 means no expiry.
        encrypted:   True when the value is stored AES-encrypted at rest.
        metadata:    Optional free-form annotations (e.g., source tool, version).
    """

    key: str = Field(..., min_length=1, max_length=512, description="Logical key name.")
    value: Any = Field(..., description="JSON-serialisable payload.")
    agent_id: str = Field(..., description="Owning agent UUID.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC write timestamp.",
    )
    ttl_seconds: int = Field(
        default=3600,
        ge=0,
        description="TTL in seconds; 0 means no expiry.",
    )
    encrypted: bool = Field(
        default=False,
        description="Whether the stored value is encrypted at rest.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Optional free-form annotations.",
    )

    @property
    def redis_key(self) -> str:
        """Full Redis key: ``agent:{agent_id}:memory:{key}``."""
        return f"agent:{self.agent_id}:memory:{self.key}"

    class Config:
        json_schema_extra = {
            "example": {
                "key": "plan:current_step",
                "value": {"step": 3, "description": "analyse logs"},
                "agent_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "ttl_seconds": 3600,
                "encrypted": False,
            }
        }


# ---------------------------------------------------------------------------
# MemorySnapshot
# ---------------------------------------------------------------------------


class MemorySnapshot(BaseModel):
    """
    Point-in-time snapshot of an agent's full memory contents.

    Snapshots are stored compressed (msgpack + zlib) under:
    ``agent:{agent_id}:snapshot:{snapshot_id}``

    Attributes:
        snapshot_id: UUID v4 uniquely identifying this snapshot.
        agent_id:    Owning agent UUID.
        timestamp:   UTC time the snapshot was taken.
        entries:     Full ordered list of MemoryEntry objects captured.
        reason:      Human-readable explanation of why the snapshot was taken.
        entry_count: Computed count of entries (read-only convenience field).
    """

    snapshot_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID v4 snapshot identifier.",
    )
    agent_id: str = Field(..., description="Owning agent UUID.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time snapshot was taken.",
    )
    entries: list[MemoryEntry] = Field(
        default_factory=list,
        description="Captured memory entries.",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Why this snapshot was taken.",
    )

    @field_validator("snapshot_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        """Ensure snapshot_id is a valid UUID."""
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError(f"snapshot_id must be a valid UUID; got '{v}'.") from exc
        return v

    @property
    def entry_count(self) -> int:
        """Number of memory entries in this snapshot."""
        return len(self.entries)

    @property
    def redis_key(self) -> str:
        """Full Redis key for this snapshot."""
        return f"agent:{self.agent_id}:snapshot:{self.snapshot_id}"

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "reason": "Pre-operation snapshot before web fetch.",
                "entries": [],
            }
        }


# ---------------------------------------------------------------------------
# MemoryBoundary
# ---------------------------------------------------------------------------


class MemoryBoundary(BaseModel):
    """
    Access-control policy for an agent's memory namespace.

    Attributes:
        agent_id:             Owning agent UUID.
        allowed_key_prefixes: List of allowed key prefixes.
                              The special value ``["*"]`` grants unrestricted access.
        max_entries:          Maximum number of keys the agent may hold simultaneously.
        max_size_bytes:       Maximum total serialised size of all values in bytes.
        created_at:           UTC time this boundary policy was established.
        updated_at:           UTC time this boundary policy was last modified.
    """

    agent_id: str = Field(..., description="Owning agent UUID.")
    allowed_key_prefixes: list[str] = Field(
        ...,
        min_length=1,
        description="Allowed key prefixes; ['*'] means unrestricted.",
    )
    max_entries: int = Field(
        default=100,
        gt=0,
        description="Maximum concurrent keys.",
    )
    max_size_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MiB
        gt=0,
        description="Maximum total value size in bytes.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC last-modified timestamp.",
    )

    @model_validator(mode="after")
    def updated_not_before_created(self) -> "MemoryBoundary":
        """updated_at must be >= created_at."""
        if self.updated_at < self.created_at:
            raise ValueError("'updated_at' must be >= 'created_at'.")
        return self

    def allows_key(self, key: str) -> bool:
        """
        Return True if ``key`` matches any of the allowed prefixes.

        The wildcard prefix ``"*"`` grants access to any key.

        Args:
            key: Logical key to test (no namespace prefix).

        Returns:
            Boolean access decision.
        """
        for prefix in self.allowed_key_prefixes:
            if prefix == "*":
                return True
            if key.startswith(prefix):
                return True
        return False

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "allowed_key_prefixes": ["plan:"],
                "max_entries": 100,
                "max_size_bytes": 10485760,
            }
        }


# ---------------------------------------------------------------------------
# Violation record (emitted on the security:violations Pub/Sub channel)
# ---------------------------------------------------------------------------


class BoundaryViolationEvent(BaseModel):
    """
    Schema for the JSON payload published to the ``security:violations``
    Redis Pub/Sub channel when a boundary violation is detected.
    """

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique event UUID.",
    )
    agent_id: str = Field(..., description="Agent that triggered the violation.")
    attempted_key: str = Field(..., description="Key the agent tried to access.")
    allowed_prefixes: list[str] = Field(..., description="Agent's allowed prefixes.")
    operation: str = Field(..., description="Attempted operation: get / set / delete.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC violation timestamp.",
    )
    severity: str = Field(default="HIGH", description="Violation severity level.")
