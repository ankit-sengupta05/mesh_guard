"""
boundaries.py — MemoryBoundaryEnforcer for the AgentOps Security Mesh.

Enforces per-agent key-prefix restrictions, capacity limits, and publishes
violations to the ``security:violations`` Redis Pub/Sub channel.

Default boundary matrix by agent role:
    PLANNER   → prefix "plan:",              max_entries=100
    EXECUTOR  → prefix "exec:{agent_id}:",  max_entries=500
    VALIDATOR → prefix "val:",               max_entries=200
    SENTINEL  → prefix "*" (unrestricted),   max_entries=10,000
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import redis.asyncio as aioredis

from backend.app.memory.schemas import (
    BoundaryViolationEvent,
    MemoryBoundary,
)
from backend.app.trust.models import AgentRole

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VIOLATION_CHANNEL: str = "security:violations"

#: Default boundary config keyed by AgentRole value.
#: ``{agent_id}`` is a template placeholder expanded at runtime for EXECUTOR.
DEFAULT_BOUNDARY_MATRIX: dict[str, dict] = {
    AgentRole.PLANNER.value: {
        "allowed_key_prefixes": ["plan:"],
        "max_entries": 100,
        "max_size_bytes": 5 * 1024 * 1024,  # 5 MiB
    },
    AgentRole.EXECUTOR.value: {
        "allowed_key_prefixes": ["exec:{agent_id}:"],
        "max_entries": 500,
        "max_size_bytes": 50 * 1024 * 1024,  # 50 MiB
    },
    AgentRole.VALIDATOR.value: {
        "allowed_key_prefixes": ["val:"],
        "max_entries": 200,
        "max_size_bytes": 10 * 1024 * 1024,  # 10 MiB
    },
    AgentRole.SENTINEL.value: {
        "allowed_key_prefixes": ["*"],
        "max_entries": 10_000,
        "max_size_bytes": 500 * 1024 * 1024,  # 500 MiB
    },
}


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class MemoryBoundaryViolation(Exception):
    """
    Raised when an agent attempts a disallowed memory operation.

    Attributes:
        agent_id:     The violating agent's UUID.
        attempted_key: The key the agent tried to access.
        operation:     The attempted operation (get / set / delete / list).
        reason:        Human-readable explanation.
    """

    def __init__(
        self,
        agent_id: str,
        attempted_key: str,
        operation: str,
        reason: str,
    ) -> None:
        self.agent_id = agent_id
        self.attempted_key = attempted_key
        self.operation = operation
        self.reason = reason
        super().__init__(
            f"Memory boundary violation by agent '{agent_id}' "
            f"on key '{attempted_key}' ({operation}): {reason}"
        )


# ---------------------------------------------------------------------------
# MemoryBoundaryEnforcer
# ---------------------------------------------------------------------------


class MemoryBoundaryEnforcer:
    """
    Enforces key-prefix access control and capacity limits for agent memory.

    All violations are:
    1. Raised as ``MemoryBoundaryViolation`` exceptions to the caller.
    2. Logged at WARNING level via Python logging.
    3. Published as JSON to the ``security:violations`` Redis Pub/Sub channel.

    Args:
        redis_client: An async Redis client (``redis.asyncio.Redis``).

    Usage::

        enforcer = MemoryBoundaryEnforcer(redis_client=redis)

        # Register a boundary (typically done at agent-registration time)
        boundary = enforcer.build_default_boundary(agent_id, role=AgentRole.PLANNER)
        enforcer.register_boundary(boundary)

        # Enforce before every memory operation
        await enforcer.enforce(agent_id, key="plan:step_1", operation="set")
    """

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        # In-process boundary registry: {agent_id: MemoryBoundary}
        self._boundaries: dict[str, MemoryBoundary] = {}
        # Running violation counts per agent for observability
        self._violation_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Boundary registry
    # ------------------------------------------------------------------

    def register_boundary(self, boundary: MemoryBoundary) -> None:
        """
        Register or replace the boundary policy for an agent.

        Args:
            boundary: The MemoryBoundary to apply.
        """
        self._boundaries[boundary.agent_id] = boundary
        logger.info(
            "Boundary registered: agent=%s prefixes=%s max_entries=%d",
            boundary.agent_id,
            boundary.allowed_key_prefixes,
            boundary.max_entries,
        )

    def get_boundary(self, agent_id: str) -> MemoryBoundary | None:
        """
        Return the registered boundary for an agent, or None if unregistered.

        Args:
            agent_id: Target agent UUID.

        Returns:
            MemoryBoundary or None.
        """
        return self._boundaries.get(agent_id)

    def build_default_boundary(self, agent_id: str, role: AgentRole) -> MemoryBoundary:
        """
        Construct the default MemoryBoundary for a given role.

        EXECUTOR prefixes are expanded with the agent's own ID so each executor
        is isolated to its own sub-namespace.

        Args:
            agent_id: Target agent UUID.
            role:     The agent's functional role.

        Returns:
            A MemoryBoundary ready to be registered.
        """
        config = DEFAULT_BOUNDARY_MATRIX.get(
            role.value, DEFAULT_BOUNDARY_MATRIX[AgentRole.EXECUTOR.value]
        ).copy()

        # Expand {agent_id} placeholder in prefix templates
        config["allowed_key_prefixes"] = [
            prefix.replace("{agent_id}", agent_id) for prefix in config["allowed_key_prefixes"]
        ]

        return MemoryBoundary(
            agent_id=agent_id,
            allowed_key_prefixes=config["allowed_key_prefixes"],
            max_entries=config["max_entries"],
            max_size_bytes=config["max_size_bytes"],
        )

    # ------------------------------------------------------------------
    # Core enforcement
    # ------------------------------------------------------------------

    async def enforce(
        self,
        agent_id: str,
        key: str,
        operation: str,
        current_entry_count: int = 0,
        value_size_bytes: int = 0,
    ) -> None:
        """
        Assert that ``agent_id`` is permitted to perform ``operation`` on ``key``.

        Checks (in order):
        1. Boundary is registered.
        2. Key prefix is allowed.
        3. Entry count does not exceed ``max_entries`` (set operations only).
        4. Value size does not exceed ``max_size_bytes`` (set operations only).

        Args:
            agent_id:            Requesting agent UUID.
            key:                 Logical key being accessed.
            operation:           One of ``get``, ``set``, ``delete``, ``list``.
            current_entry_count: Current key count for the agent (for set checks).
            value_size_bytes:    Serialised size of the value (for set checks).

        Raises:
            MemoryBoundaryViolation: On any access-control failure.
        """
        boundary = self._boundaries.get(agent_id)

        if boundary is None:
            await self._violation(
                agent_id=agent_id,
                attempted_key=key,
                operation=operation,
                reason="No boundary policy registered for this agent.",
                allowed_prefixes=[],
            )

        assert boundary is not None  # narrowing for type checker

        # 1. Key prefix check
        if not boundary.allows_key(key):
            await self._violation(
                agent_id=agent_id,
                attempted_key=key,
                operation=operation,
                reason=(f"Key prefix not in allowed list: {boundary.allowed_key_prefixes}."),
                allowed_prefixes=boundary.allowed_key_prefixes,
            )

        # 2. Entry count limit (only relevant for write operations)
        if operation == "set" and current_entry_count >= boundary.max_entries:
            await self._violation(
                agent_id=agent_id,
                attempted_key=key,
                operation=operation,
                reason=(f"Entry limit reached: {current_entry_count}/{boundary.max_entries}."),
                allowed_prefixes=boundary.allowed_key_prefixes,
            )

        # 3. Size limit check (only relevant for write operations)
        if operation == "set" and value_size_bytes > boundary.max_size_bytes:
            await self._violation(
                agent_id=agent_id,
                attempted_key=key,
                operation=operation,
                reason=(
                    f"Value size {value_size_bytes} bytes exceeds "
                    f"max_size_bytes {boundary.max_size_bytes}."
                ),
                allowed_prefixes=boundary.allowed_key_prefixes,
            )

    async def enforce_cross_agent_isolation(
        self, requesting_agent_id: str, target_agent_id: str, operation: str
    ) -> None:
        """
        Ensure that ``requesting_agent_id`` is not attempting to access
        ``target_agent_id``'s namespace (unless it is a SENTINEL).

        Args:
            requesting_agent_id: The agent making the request.
            target_agent_id:     The agent whose namespace is targeted.
            operation:           Attempted operation name.

        Raises:
            MemoryBoundaryViolation: If cross-agent access is attempted by
                                     a non-SENTINEL agent.
        """
        if requesting_agent_id == target_agent_id:
            return  # Self-access is always allowed

        boundary = self._boundaries.get(requesting_agent_id)
        if boundary and "*" in boundary.allowed_key_prefixes:
            return  # SENTINEL — unrestricted

        await self._violation(
            agent_id=requesting_agent_id,
            attempted_key=f"agent:{target_agent_id}:memory:*",
            operation=operation,
            reason=(
                f"Agent '{requesting_agent_id}' attempted to access "
                f"namespace of agent '{target_agent_id}'."
            ),
            allowed_prefixes=boundary.allowed_key_prefixes if boundary else [],
        )

    # ------------------------------------------------------------------
    # Violation handling
    # ------------------------------------------------------------------

    async def _violation(
        self,
        agent_id: str,
        attempted_key: str,
        operation: str,
        reason: str,
        allowed_prefixes: list[str],
    ) -> None:
        """
        Emit a violation event, increment counter, then raise MemoryBoundaryViolation.

        This method always raises — it never returns normally.

        Args:
            agent_id:        Violating agent UUID.
            attempted_key:   Key the agent tried to access.
            operation:       Attempted operation.
            reason:          Explanation for the violation.
            allowed_prefixes: The agent's allowed prefixes for context.

        Raises:
            MemoryBoundaryViolation: Always.
        """
        self._violation_counts[agent_id] = self._violation_counts.get(agent_id, 0) + 1

        event = BoundaryViolationEvent(
            agent_id=agent_id,
            attempted_key=attempted_key,
            allowed_prefixes=allowed_prefixes,
            operation=operation,
        )

        logger.warning(
            "MEMORY BOUNDARY VIOLATION #%d: agent=%s key=%r operation=%s reason=%s",
            self._violation_counts[agent_id],
            agent_id,
            attempted_key,
            operation,
            reason,
        )

        # Publish to Redis Pub/Sub channel (fire-and-forget; don't block caller)
        try:
            await self._redis.publish(
                VIOLATION_CHANNEL,
                event.model_dump_json(),
            )
        except Exception as pub_exc:  # noqa: BLE001
            logger.error(
                "Failed to publish violation event to '%s': %s",
                VIOLATION_CHANNEL,
                pub_exc,
                exc_info=True,
            )

        raise MemoryBoundaryViolation(
            agent_id=agent_id,
            attempted_key=attempted_key,
            operation=operation,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def violation_count(self, agent_id: str) -> int:
        """
        Return the cumulative violation count for an agent.

        Args:
            agent_id: Target agent UUID.

        Returns:
            Non-negative integer.
        """
        return self._violation_counts.get(agent_id, 0)

    def all_violation_counts(self) -> dict[str, int]:
        """Return a copy of the full violation counter map."""
        return dict(self._violation_counts)
