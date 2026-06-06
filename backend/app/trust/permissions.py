"""
permissions.py — PermissionEnforcer for the AgentOps Security Mesh.

Provides synchronous permission checks backed by an async Neo4j trust graph,
with an in-process cache layer and a role-based default permission matrix.

Default permission matrix:
    PLANNER  → [AGENT_SPAWN, MEMORY]
    EXECUTOR → [WEB, CODE, MEMORY]
    VALIDATOR→ [MEMORY]
    SENTINEL → ALL resources
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from backend.app.trust.models import AgentRole, AgentStatus, Permission, ResourceType

if TYPE_CHECKING:
    from backend.app.trust.graph import AsyncNeo4jTrustGraph

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PermissionDenied(Exception):
    """
    Raised when an agent attempts to access a resource it is not permitted to use.

    Attributes:
        agent_id:  The requesting agent's UUID.
        resource:  The resource that was denied.
        reason:    Human-readable explanation of the denial.
    """

    def __init__(self, agent_id: str, resource: ResourceType, reason: str) -> None:
        self.agent_id = agent_id
        self.resource = resource
        self.reason = reason
        super().__init__(
            f"Permission denied for agent '{agent_id}' on resource '{resource.value}': {reason}"
        )


class AgentSuspended(PermissionDenied):
    """Raised when the requesting agent is in SUSPENDED or COMPROMISED status."""


# ---------------------------------------------------------------------------
# Default permission matrix
# ---------------------------------------------------------------------------

#: Maps each AgentRole to the set of ResourceTypes granted by default.
DEFAULT_PERMISSION_MATRIX: dict[AgentRole, frozenset[ResourceType]] = {
    AgentRole.PLANNER: frozenset(
        {ResourceType.AGENT_SPAWN, ResourceType.MEMORY}
    ),
    AgentRole.EXECUTOR: frozenset(
        {ResourceType.WEB, ResourceType.CODE, ResourceType.MEMORY}
    ),
    AgentRole.VALIDATOR: frozenset(
        {ResourceType.MEMORY}
    ),
    AgentRole.SENTINEL: frozenset(ResourceType),  # ALL resources
}


# ---------------------------------------------------------------------------
# PermissionEnforcer
# ---------------------------------------------------------------------------


class PermissionEnforcer:
    """
    Enforces agent–resource access control with Neo4j-backed persistence
    and an in-process cache.

    The enforcer integrates with AsyncNeo4jTrustGraph to:
    - Persist grant/revoke decisions as Permission nodes.
    - Read back permissions on check, falling back to the default matrix.
    - Track permission violations for trust-score penalisation.

    Args:
        graph: An initialised AsyncNeo4jTrustGraph instance.

    Usage::

        enforcer = PermissionEnforcer(graph=trust_graph)

        # Initialise defaults for a newly registered agent
        await enforcer.apply_default_permissions(agent_id, role=AgentRole.EXECUTOR)

        # Check access (raises PermissionDenied if not permitted)
        await enforcer.check_permission(agent_id, ResourceType.WEB)

        # Explicit grant / revoke
        await enforcer.grant_permission(agent_id, ResourceType.CODE, granted_by="SYSTEM")
        await enforcer.revoke_permission(agent_id, ResourceType.CODE)
    """

    def __init__(self, graph: "AsyncNeo4jTrustGraph") -> None:
        self._graph = graph
        #: In-process permission cache: {agent_id: {resource: granted}}
        self._cache: dict[str, dict[ResourceType, bool]] = {}
        #: Violation counter per agent (used by TrustScorer)
        self._violation_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _cache_permission(
        self, agent_id: str, resource: ResourceType, granted: bool
    ) -> None:
        """Update the in-process cache for a single permission entry."""
        self._cache.setdefault(agent_id, {})[resource] = granted

    def _get_cached(
        self, agent_id: str, resource: ResourceType
    ) -> bool | None:
        """Return the cached permission state, or None if not cached."""
        return self._cache.get(agent_id, {}).get(resource)

    def invalidate_cache(self, agent_id: str) -> None:
        """
        Remove all cached permissions for an agent.

        Call this after any external permission change to force a fresh
        database read on the next check.

        Args:
            agent_id: Target agent UUID.
        """
        self._cache.pop(agent_id, None)

    # ------------------------------------------------------------------
    # Default-matrix bootstrap
    # ------------------------------------------------------------------

    async def apply_default_permissions(
        self, agent_id: str, role: AgentRole
    ) -> list[Permission]:
        """
        Persist the default permission set for a role to Neo4j.

        Should be called once immediately after agent registration.

        Args:
            agent_id: Target agent UUID.
            role:     The agent's functional role.

        Returns:
            List of Permission objects created.
        """
        default_resources = DEFAULT_PERMISSION_MATRIX.get(role, frozenset())
        permissions: list[Permission] = []

        # Grant defaults
        for resource in default_resources:
            perm = await self._graph.grant_permission(
                agent_id=agent_id,
                resource=resource,
                granted_by="SYSTEM",
            )
            self._cache_permission(agent_id, resource, True)
            permissions.append(perm)

        # Explicitly deny everything else (stored as granted=False)
        for resource in ResourceType:
            if resource not in default_resources:
                await self._graph.revoke_permission(
                    agent_id=agent_id,
                    resource=resource,
                    revoked_by="SYSTEM",
                )
                self._cache_permission(agent_id, resource, False)

        logger.info(
            "Default permissions applied: agent=%s role=%s granted=%s",
            agent_id,
            role.value,
            [r.value for r in default_resources],
        )
        return permissions

    # ------------------------------------------------------------------
    # Core enforcement API
    # ------------------------------------------------------------------

    async def check_permission(
        self, agent_id: str, resource: ResourceType
    ) -> None:
        """
        Assert that an agent is permitted to access a resource.

        Checks:
        1. Agent existence and status (not SUSPENDED/COMPROMISED).
        2. In-process permission cache.
        3. Neo4j Permission nodes (refreshes cache).

        Args:
            agent_id: The requesting agent's UUID.
            resource: The resource being accessed.

        Raises:
            AgentSuspended:  If the agent is suspended or compromised.
            PermissionDenied: If the agent is not granted the resource.
            KeyError:         If the agent does not exist.
        """
        # 1. Validate agent status
        agent = await self._graph.get_agent(agent_id)
        if agent.status in (AgentStatus.SUSPENDED, AgentStatus.COMPROMISED):
            raise AgentSuspended(
                agent_id=agent_id,
                resource=resource,
                reason=f"Agent is {agent.status.value}.",
            )

        # 2. Cache hit
        cached = self._get_cached(agent_id, resource)
        if cached is True:
            return
        if cached is False:
            self._record_violation(agent_id, resource)
            raise PermissionDenied(
                agent_id=agent_id,
                resource=resource,
                reason="Permission explicitly denied (cached).",
            )

        # 3. Database lookup
        permissions = await self._graph.get_agent_permissions(agent_id)
        resource_map: dict[ResourceType, bool] = {
            p.resource: p.granted for p in permissions
        }

        # Refresh cache for all loaded permissions
        for res, granted in resource_map.items():
            self._cache_permission(agent_id, res, granted)

        if resource_map.get(resource) is True:
            return

        # Not found in DB — deny
        self._record_violation(agent_id, resource)
        raise PermissionDenied(
            agent_id=agent_id,
            resource=resource,
            reason="Permission not found in trust store.",
        )

    async def grant_permission(
        self,
        agent_id: str,
        resource: ResourceType,
        granted_by: str,
        expires_at: datetime | None = None,
    ) -> Permission:
        """
        Grant a resource permission to an agent.

        Args:
            agent_id:   Target agent UUID.
            resource:   Resource type to grant.
            granted_by: UUID of granting agent or "SYSTEM".
            expires_at: Optional UTC expiry datetime.

        Returns:
            The persisted Permission object.
        """
        perm = await self._graph.grant_permission(
            agent_id=agent_id,
            resource=resource,
            granted_by=granted_by,
            expires_at=expires_at,
        )
        self._cache_permission(agent_id, resource, True)
        logger.info(
            "Permission granted: agent=%s resource=%s by=%s",
            agent_id,
            resource.value,
            granted_by,
        )
        return perm

    async def revoke_permission(
        self,
        agent_id: str,
        resource: ResourceType,
        revoked_by: str = "SYSTEM",
    ) -> None:
        """
        Revoke a resource permission from an agent.

        Args:
            agent_id:   Target agent UUID.
            resource:   Resource type to revoke.
            revoked_by: UUID of revoking agent or "SYSTEM".
        """
        await self._graph.revoke_permission(
            agent_id=agent_id,
            resource=resource,
            revoked_by=revoked_by,
        )
        self._cache_permission(agent_id, resource, False)
        logger.info(
            "Permission revoked: agent=%s resource=%s by=%s",
            agent_id,
            resource.value,
            revoked_by,
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def violation_count(self, agent_id: str) -> int:
        """
        Return the number of permission violations recorded for an agent
        in the current process lifetime.

        Args:
            agent_id: Target agent UUID.

        Returns:
            Non-negative integer violation count.
        """
        return self._violation_counts.get(agent_id, 0)

    def _record_violation(self, agent_id: str, resource: ResourceType) -> None:
        """Increment the in-process violation counter for an agent."""
        self._violation_counts[agent_id] = (
            self._violation_counts.get(agent_id, 0) + 1
        )
        logger.warning(
            "Permission violation #%d: agent=%s resource=%s",
            self._violation_counts[agent_id],
            agent_id,
            resource.value,
        )

    async def get_permission_summary(
        self, agent_id: str
    ) -> dict[str, bool]:
        """
        Return a resource → granted mapping for all resources for an agent.

        Useful for admin dashboards and the React frontend.

        Args:
            agent_id: Target agent UUID.

        Returns:
            Dict mapping resource name to current grant state.
        """
        permissions = await self._graph.get_agent_permissions(agent_id)
        granted_set = {p.resource for p in permissions if p.granted and not p.is_expired}
        return {r.value: (r in granted_set) for r in ResourceType}
