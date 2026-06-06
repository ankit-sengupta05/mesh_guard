"""
events.py — SecurityEventEmitter for the AgentOps Security Mesh.

Publishes structured security events to:
  1. Redis Pub/Sub channel "security:events" (for backend consumers)
  2. An in-memory list for WebSocket broadcast (polled by the FastAPI layer)

Events are stored in a Redis sorted set (score = Unix timestamp) for
time-ordered retrieval via get_recent_events().

Environment variables:
    REDIS_URL              — Redis connection URL (default: redis://localhost:6379/0)
    SECURITY_EVENTS_CHANNEL — Pub/Sub channel name (default: security:events)
    SECURITY_EVENTS_KEY     — Sorted-set key for event history (default: security:event_history)
    SECURITY_EVENTS_MAX     — Maximum events in sorted set (default: 10000)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import redis.asyncio as aioredis
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECURITY_EVENTS_CHANNEL: str = os.environ.get("SECURITY_EVENTS_CHANNEL", "security:events")
SECURITY_EVENTS_KEY: str = os.environ.get("SECURITY_EVENTS_KEY", "security:event_history")
SECURITY_EVENTS_MAX: int = int(os.environ.get("SECURITY_EVENTS_MAX", "10000"))
REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """Enumerated security event types emitted by the mesh."""

    THREAT_DETECTED = "THREAT_DETECTED"
    BLOCKED = "BLOCKED"
    AGENT_SUSPENDED = "AGENT_SUSPENDED"
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_COMPLETE = "RECOVERY_COMPLETE"
    ATTACK_SIMULATED = "ATTACK_SIMULATED"
    PERMISSION_VIOLATION = "PERMISSION_VIOLATION"
    MEMORY_BOUNDARY_VIOLATION = "MEMORY_BOUNDARY_VIOLATION"
    TRUST_SCORE_CHANGED = "TRUST_SCORE_CHANGED"
    SNAPSHOT_TAKEN = "SNAPSHOT_TAKEN"
    SNAPSHOT_RESTORED = "SNAPSHOT_RESTORED"


class EventSeverity(str, Enum):
    """Severity levels for security events."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# SecurityEvent schema
# ---------------------------------------------------------------------------


class SecurityEvent(BaseModel):
    """
    Canonical schema for all security events emitted by the AgentOps mesh.

    Attributes:
        event_id:   UUID v4 uniquely identifying this event.
        event_type: Categorised event type from ``EventType``.
        agent_id:   UUID of the agent involved (or ``"SYSTEM"``).
        severity:   Severity level of the event.
        details:    Arbitrary structured metadata relevant to the event.
        timestamp:  UTC time the event was emitted.
        source:     Component that emitted the event (e.g., "firewall", "enforcer").
    """

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID v4 event identifier.",
    )
    event_type: EventType = Field(..., description="Categorised event type.")
    agent_id: str = Field(
        ...,
        description="UUID of involved agent, or 'SYSTEM' for system-level events.",
    )
    severity: EventSeverity = Field(..., description="Event severity level.")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary structured metadata.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC event emission timestamp.",
    )
    source: str = Field(
        default="firewall",
        description="Component that emitted this event.",
    )

    @property
    def unix_timestamp(self) -> float:
        """Return the timestamp as a Unix float for use as a Redis sorted set score."""
        return self.timestamp.timestamp()

    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "THREAT_DETECTED",
                "agent_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "severity": "HIGH",
                "details": {
                    "threat_type": "INJECTION",
                    "detector": "InjectionDetector",
                    "matched_pattern": "ignore previous instructions",
                },
                "source": "firewall",
            }
        }


# ---------------------------------------------------------------------------
# SecurityEventEmitter
# ---------------------------------------------------------------------------


class SecurityEventEmitter:
    """
    Emits structured security events to Redis Pub/Sub and WebSocket subscribers.

    Architecture:
    - ``emit()`` publishes to Redis ``security:events`` channel and appends to
      a sorted set (scored by Unix timestamp) for historical retrieval.
    - An in-process asyncio ``Queue`` lets the FastAPI WebSocket layer subscribe
      without Redis round-trips per socket frame.
    - ``get_recent_events()`` reads from the Redis sorted set for persistence
      across process restarts.

    Args:
        redis_client: An initialised ``redis.asyncio.Redis`` instance.

    Usage::

        emitter = SecurityEventEmitter(redis_client=redis)

        event = SecurityEvent(
            event_type=EventType.THREAT_DETECTED,
            agent_id=agent_id,
            severity=EventSeverity.HIGH,
            details={"detector": "InjectionDetector"},
        )
        await emitter.emit(event)

        recent = await emitter.get_recent_events(limit=50)
    """

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        #: In-process WebSocket broadcast queue
        self._ws_queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=1000)
        #: Registered WebSocket send callbacks: {conn_id: coroutine_callable}
        self._ws_subscribers: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # WebSocket subscription management
    # ------------------------------------------------------------------

    def subscribe_websocket(
        self,
        connection_id: str,
        send_callback: Any,
    ) -> None:
        """
        Register a WebSocket connection to receive security events.

        Args:
            connection_id: Unique identifier for this WebSocket connection.
            send_callback: Async callable that accepts a JSON string and sends
                           it to the WebSocket client.
        """
        self._ws_subscribers[connection_id] = send_callback
        logger.info("WebSocket subscribed to security events: conn=%s", connection_id)

    def unsubscribe_websocket(self, connection_id: str) -> None:
        """
        Remove a WebSocket connection from security event broadcasts.

        Args:
            connection_id: Identifier of the connection to remove.
        """
        self._ws_subscribers.pop(connection_id, None)
        logger.info("WebSocket unsubscribed: conn=%s", connection_id)

    # ------------------------------------------------------------------
    # Core emission
    # ------------------------------------------------------------------

    async def emit(self, event: SecurityEvent) -> None:
        """
        Publish a security event to all configured sinks.

        Sinks (each is fire-and-forget; failure of one does not block others):
        1. Redis Pub/Sub channel ``security:events``.
        2. Redis sorted set ``security:event_history`` (score = Unix timestamp).
        3. All registered WebSocket send callbacks.
        4. In-process asyncio queue (for components polling locally).

        Args:
            event: The SecurityEvent to emit.
        """
        payload_json = event.model_dump_json()

        # 1. Redis Pub/Sub
        await self._publish_redis(payload_json)

        # 2. Redis sorted set for historical retrieval
        await self._store_history(event, payload_json)

        # 3. WebSocket broadcast
        await self._broadcast_websockets(event, payload_json)

        # 4. In-process queue (non-blocking)
        try:
            self._ws_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("SecurityEventEmitter: in-process queue full, dropping event.")

        logger.info(
            "SecurityEvent emitted: type=%s agent=%s severity=%s",
            event.event_type.value,
            event.agent_id,
            event.severity.value,
        )

    async def _publish_redis(self, payload_json: str) -> None:
        """Publish event JSON to the Redis security:events Pub/Sub channel."""
        try:
            await self._redis.publish(SECURITY_EVENTS_CHANNEL, payload_json)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "SecurityEventEmitter: Redis publish failed: %s", exc, exc_info=True
            )

    async def _store_history(self, event: SecurityEvent, payload_json: str) -> None:
        """Append event to the sorted-set history; prune if over SECURITY_EVENTS_MAX."""
        try:
            pipe = self._redis.pipeline(transaction=False)
            pipe.zadd(
                SECURITY_EVENTS_KEY,
                {payload_json: event.unix_timestamp},
            )
            # Trim to keep only the most recent SECURITY_EVENTS_MAX entries
            pipe.zremrangebyrank(SECURITY_EVENTS_KEY, 0, -(SECURITY_EVENTS_MAX + 1))
            await pipe.execute()
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "SecurityEventEmitter: history store failed: %s", exc, exc_info=True
            )

    async def _broadcast_websockets(
        self, event: SecurityEvent, payload_json: str
    ) -> None:
        """Fan-out event JSON to all registered WebSocket send callbacks."""
        if not self._ws_subscribers:
            return

        dead_connections: list[str] = []

        for conn_id, send_fn in list(self._ws_subscribers.items()):
            try:
                await send_fn(payload_json)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "SecurityEventEmitter: WS send failed for conn=%s: %s",
                    conn_id,
                    exc,
                )
                dead_connections.append(conn_id)

        for conn_id in dead_connections:
            self._ws_subscribers.pop(conn_id, None)

    # ------------------------------------------------------------------
    # Historical retrieval
    # ------------------------------------------------------------------

    async def get_recent_events(
        self,
        limit: int = 100,
        min_severity: Optional[EventSeverity] = None,
        event_type: Optional[EventType] = None,
        agent_id: Optional[str] = None,
    ) -> list[SecurityEvent]:
        """
        Retrieve the most recent security events from the Redis sorted set.

        Supports optional server-side filtering by severity, event type,
        and agent ID (applied in Python after fetching, as Redis sorted sets
        don't support compound filters).

        Args:
            limit:        Maximum number of events to return (newest first).
            min_severity: Only return events at or above this severity.
            event_type:   Only return events of this type.
            agent_id:     Only return events for this agent.

        Returns:
            List of SecurityEvent objects, newest first.
        """
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_sev_order = severity_order.get(min_severity.value if min_severity else "LOW", 0)

        try:
            # Fetch up to 10× limit to allow filtering headroom
            raw_items = await self._redis.zrevrange(
                SECURITY_EVENTS_KEY,
                0,
                max(limit * 10, 999),
                withscores=False,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "SecurityEventEmitter: history read failed: %s", exc, exc_info=True
            )
            return []

        events: list[SecurityEvent] = []
        for raw in raw_items:
            if len(events) >= limit:
                break
            try:
                decoded = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                ev = SecurityEvent.model_validate_json(decoded)

                if severity_order.get(ev.severity.value, 0) < min_sev_order:
                    continue
                if event_type and ev.event_type != event_type:
                    continue
                if agent_id and ev.agent_id != agent_id:
                    continue

                events.append(ev)
            except Exception as exc:  # noqa: BLE001
                logger.debug("SecurityEventEmitter: skipping malformed event: %s", exc)

        return events

    # ------------------------------------------------------------------
    # Convenience factory methods
    # ------------------------------------------------------------------

    async def emit_threat(
        self,
        agent_id: str,
        severity: str,
        details: dict,
        source: str = "firewall",
    ) -> SecurityEvent:
        """Emit a THREAT_DETECTED event and return it."""
        event = SecurityEvent(
            event_type=EventType.THREAT_DETECTED,
            agent_id=agent_id,
            severity=EventSeverity(severity),
            details=details,
            source=source,
        )
        await self.emit(event)
        return event

    async def emit_blocked(
        self,
        agent_id: str,
        severity: str,
        details: dict,
        source: str = "firewall",
    ) -> SecurityEvent:
        """Emit a BLOCKED event and return it."""
        event = SecurityEvent(
            event_type=EventType.BLOCKED,
            agent_id=agent_id,
            severity=EventSeverity(severity),
            details=details,
            source=source,
        )
        await self.emit(event)
        return event

    async def emit_agent_suspended(
        self,
        agent_id: str,
        reason: str,
        source: str = "trust_graph",
    ) -> SecurityEvent:
        """Emit an AGENT_SUSPENDED event and return it."""
        event = SecurityEvent(
            event_type=EventType.AGENT_SUSPENDED,
            agent_id=agent_id,
            severity=EventSeverity.CRITICAL,
            details={"reason": reason},
            source=source,
        )
        await self.emit(event)
        return event

    async def emit_recovery(
        self,
        agent_id: str,
        started: bool,
        details: dict | None = None,
        source: str = "recovery",
    ) -> SecurityEvent:
        """Emit a RECOVERY_STARTED or RECOVERY_COMPLETE event."""
        event = SecurityEvent(
            event_type=EventType.RECOVERY_STARTED if started else EventType.RECOVERY_COMPLETE,
            agent_id=agent_id,
            severity=EventSeverity.HIGH,
            details=details or {},
            source=source,
        )
        await self.emit(event)
        return event

    # ------------------------------------------------------------------
    # In-process queue access (for WebSocket poller)
    # ------------------------------------------------------------------

    async def next_event(self, timeout: float = 1.0) -> Optional[SecurityEvent]:
        """
        Wait up to ``timeout`` seconds for the next event from the in-process queue.

        Useful for WebSocket push loops that don't use subscriber callbacks.

        Args:
            timeout: Seconds to wait before returning None.

        Returns:
            The next SecurityEvent, or None if the queue was empty.
        """
        try:
            return await asyncio.wait_for(self._ws_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
