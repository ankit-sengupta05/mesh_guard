"""
graph.py — AsyncNeo4jTrustGraph: async Neo4j driver wrapper for the AgentOps
Security Mesh trust graph.

All Cypher queries are defined as module-level constants so they can be audited,
indexed, and unit-tested independently of the driver session.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession

from backend.app.trust.models import (
    AgentIdentity,
    AgentRole,
    AgentStatus,
    Permission,
    ResourceType,
    TrustEdge,
    TrustGraphSnapshot,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher query constants
# ---------------------------------------------------------------------------

# --- Index creation ---
CQL_CREATE_AGENT_INDEX: str = "CREATE INDEX agent_id_index IF NOT EXISTS " "FOR (a:Agent) ON (a.id)"

CQL_CREATE_PERMISSION_INDEX: str = (
    "CREATE INDEX permission_agent_resource_index IF NOT EXISTS "
    "FOR (p:Permission) ON (p.agent_id, p.resource)"
)

# --- Agent CRUD ---
CQL_REGISTER_AGENT: str = """
MERGE (a:Agent {id: $id})
SET
  a.name         = $name,
  a.role         = $role,
  a.created_at   = $created_at,
  a.trust_score  = $trust_score,
  a.status       = $status,
  a.metadata     = $metadata
RETURN a
"""

CQL_GET_AGENT: str = """
MATCH (a:Agent {id: $agent_id})
RETURN a
"""

CQL_UPDATE_TRUST_SCORE: str = """
MATCH (a:Agent {id: $agent_id})
SET
  a.trust_score = CASE
    WHEN a.trust_score + $delta > 1.0 THEN 1.0
    WHEN a.trust_score + $delta < 0.0 THEN 0.0
    ELSE a.trust_score + $delta
  END
WITH a
CREATE (e:TrustScoreEvent {
  agent_id   : $agent_id,
  delta      : $delta,
  reason     : $reason,
  occurred_at: $occurred_at
})
RETURN a.trust_score AS new_score
"""

CQL_SUSPEND_AGENT: str = """
MATCH (a:Agent {id: $agent_id})
SET a.status = 'SUSPENDED'
WITH a
CREATE (e:SuspensionEvent {
  agent_id   : $agent_id,
  reason     : $reason,
  occurred_at: $occurred_at
})
RETURN a
"""

# --- Interaction / edge ---
CQL_RECORD_INTERACTION: str = """
MATCH (src:Agent {id: $from_id})
MATCH (dst:Agent {id: $to_id})
MERGE (src)-[r:INTERACTS_WITH]->(dst)
ON CREATE SET
  r.interaction_count = 1,
  r.anomaly_count     = $anomaly_int,
  r.last_interaction  = $now,
  r.trust_weight      = 1.0
ON MATCH SET
  r.interaction_count = r.interaction_count + 1,
  r.anomaly_count     = r.anomaly_count + $anomaly_int,
  r.last_interaction  = $now,
  r.trust_weight      = CASE
    WHEN (r.anomaly_count + $anomaly_int) = 0 THEN 1.0
    ELSE 1.0 - toFloat(r.anomaly_count + $anomaly_int) / toFloat(r.interaction_count + 1)
  END
RETURN r
"""

# --- Permissions ---
CQL_GET_PERMISSIONS: str = """
MATCH (p:Permission {agent_id: $agent_id, granted: true})
RETURN p
"""

CQL_UPSERT_PERMISSION: str = """
MERGE (p:Permission {agent_id: $agent_id, resource: $resource})
SET
  p.granted     = $granted,
  p.granted_by  = $granted_by,
  p.granted_at  = $granted_at,
  p.expires_at  = $expires_at
RETURN p
"""

# --- Full graph snapshot ---
CQL_GET_ALL_AGENTS: str = """
MATCH (a:Agent)
RETURN a
ORDER BY a.created_at
"""

CQL_GET_ALL_EDGES: str = """
MATCH (src:Agent)-[r:INTERACTS_WITH]->(dst:Agent)
RETURN src.id AS from_id, dst.id AS to_id,
       r.interaction_count AS interaction_count,
       r.anomaly_count     AS anomaly_count,
       r.last_interaction  AS last_interaction,
       r.trust_weight      AS trust_weight
"""

# --- Decay ---
CQL_DECAY_SCORES: str = """
MATCH (a:Agent {status: 'ACTIVE'})
WHERE a.last_interaction IS NOT NULL
  AND datetime(a.last_interaction) < datetime() - duration({hours: 1})
SET a.trust_score = CASE
  WHEN a.trust_score - 0.01 < 0.0 THEN 0.0
  ELSE a.trust_score - 0.01
END
RETURN count(a) AS decayed_agents
"""


# ---------------------------------------------------------------------------
# Graph driver
# ---------------------------------------------------------------------------


class AsyncNeo4jTrustGraph:
    """
    Async wrapper around Neo4j for AgentOps trust graph operations.

    Environment variables:
        NEO4J_URI      — bolt URI, e.g. bolt://localhost:7687
        NEO4J_USER     — database username (default: neo4j)
        NEO4J_PASSWORD — database password

    Usage::

        graph = AsyncNeo4jTrustGraph()
        await graph.initialize()          # creates indexes
        await graph.register_agent(identity)
        await graph.close()
    """

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str = "neo4j",
    ) -> None:
        self._uri: str = uri or os.environ["NEO4J_URI"]
        self._user: str = user or os.environ.get("NEO4J_USER", "neo4j")
        self._password: str = password or os.environ["NEO4J_PASSWORD"]
        self._database: str = database
        self._driver: AsyncDriver | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open driver connection and ensure Neo4j schema indexes exist."""
        self._driver = AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password),
        )
        await self._driver.verify_connectivity()
        logger.info("Neo4j connection verified: %s", self._uri)
        await self._create_indexes()

    async def close(self) -> None:
        """Gracefully close the Neo4j driver."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j driver closed.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _session(self) -> AsyncSession:
        if self._driver is None:
            raise RuntimeError(
                "AsyncNeo4jTrustGraph is not initialized. Call await graph.initialize() first."
            )
        return self._driver.session(database=self._database)

    async def _create_indexes(self) -> None:
        """Create Neo4j schema indexes required for fast agent lookups."""
        async with self._session() as session:
            for cql in (CQL_CREATE_AGENT_INDEX, CQL_CREATE_PERMISSION_INDEX):
                await session.run(cql)
        logger.info("Neo4j trust graph indexes ensured.")

    async def _execute_read(self, query: str, params: dict | None = None) -> list[Any]:
        """
        Execute a raw Cypher read query and return all records as a list.

        Args:
            query:  Cypher query string.
            params: Optional dict of query parameters.

        Returns:
            List of neo4j.Record objects (supports dict-style access).

        Raises:
            RuntimeError: If the driver is not initialized.
            Neo4jError:   On database read failure.
        """
        async with self._session() as session:
            result = await session.run(query, **(params or {}))
            records = await result.data()
        return records

    @staticmethod
    def _node_to_agent(props: dict[str, Any]) -> AgentIdentity:
        """Convert a raw Neo4j node property map to an AgentIdentity."""
        created_at = props.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)

        metadata_raw = props.get("metadata", "{}")
        if isinstance(metadata_raw, str):
            import json

            metadata = json.loads(metadata_raw)
        else:
            metadata = metadata_raw or {}

        return AgentIdentity(
            id=props["id"],
            name=props["name"],
            role=AgentRole(props["role"]),
            created_at=created_at or datetime.now(timezone.utc),
            trust_score=float(props.get("trust_score", 1.0)),
            status=AgentStatus(props.get("status", AgentStatus.ACTIVE)),
            metadata=metadata,
        )

    @staticmethod
    def _node_to_permission(props: dict[str, Any]) -> Permission:
        """Convert a raw Neo4j Permission node property map to a Permission model."""
        granted_at = props.get("granted_at")
        if isinstance(granted_at, str):
            granted_at = datetime.fromisoformat(granted_at)

        expires_at = props.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        return Permission(
            agent_id=props["agent_id"],
            resource=ResourceType(props["resource"]),
            granted=bool(props.get("granted", False)),
            granted_by=props.get("granted_by", "SYSTEM"),
            granted_at=granted_at or datetime.now(timezone.utc),
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register_agent(self, identity: AgentIdentity) -> AgentIdentity:
        """
        Create or update an Agent node in Neo4j.

        Args:
            identity: The AgentIdentity to persist.

        Returns:
            The persisted AgentIdentity (with any Neo4j-generated fields).

        Raises:
            Neo4jError: On database write failure.
        """
        import json

        async with self._session() as session:
            result = await session.run(
                CQL_REGISTER_AGENT,
                id=identity.id,
                name=identity.name,
                role=identity.role.value,
                created_at=identity.created_at.isoformat(),
                trust_score=identity.trust_score,
                status=identity.status.value,
                metadata=json.dumps(identity.metadata),
            )
            record = await result.single()
            if record is None:
                raise RuntimeError(f"Failed to register agent {identity.id!r}.")

        logger.info("Agent registered: id=%s role=%s", identity.id, identity.role)
        return identity

    async def get_agent(self, agent_id: str) -> AgentIdentity:
        """
        Retrieve an Agent node from Neo4j by ID.

        Args:
            agent_id: UUID string of the target agent.

        Returns:
            The matching AgentIdentity.

        Raises:
            KeyError: If no agent with that ID exists.
            Neo4jError: On database read failure.
        """
        async with self._session() as session:
            result = await session.run(CQL_GET_AGENT, agent_id=agent_id)
            record = await result.single()

        if record is None:
            raise KeyError(f"Agent not found: {agent_id!r}")

        return self._node_to_agent(dict(record["a"]))

    async def update_trust_score(
        self,
        agent_id: str,
        delta: float,
        reason: str,
    ) -> float:
        """
        Apply a signed delta to an agent's trust score (clamped to [0.0, 1.0]).

        Args:
            agent_id: Target agent UUID.
            delta:    Signed float to add to the current trust score.
            reason:   Human-readable reason for the update (stored as audit event).

        Returns:
            The new trust score after applying the delta.

        Raises:
            KeyError:    If the agent does not exist.
            Neo4jError:  On database write failure.
        """
        async with self._session() as session:
            result = await session.run(
                CQL_UPDATE_TRUST_SCORE,
                agent_id=agent_id,
                delta=delta,
                reason=reason,
                occurred_at=datetime.now(timezone.utc).isoformat(),
            )
            record = await result.single()

        if record is None:
            raise KeyError(f"Agent not found: {agent_id!r}")

        new_score: float = float(record["new_score"])
        logger.info(
            "Trust score updated: agent=%s delta=%+.3f reason=%r new_score=%.3f",
            agent_id,
            delta,
            reason,
            new_score,
        )
        return new_score

    async def record_interaction(
        self,
        from_id: str,
        to_id: str,
        anomalous: bool,
    ) -> TrustEdge:
        """
        Increment interaction count on the directed edge from_id→to_id.

        Creates the edge if it does not yet exist and recomputes trust_weight
        based on the running anomaly rate.

        Args:
            from_id:   Source agent UUID.
            to_id:     Target agent UUID.
            anomalous: Whether this interaction was flagged as anomalous.

        Returns:
            The updated TrustEdge.

        Raises:
            Neo4jError: On database write failure.
        """
        now = datetime.now(timezone.utc).isoformat()
        async with self._session() as session:
            result = await session.run(
                CQL_RECORD_INTERACTION,
                from_id=from_id,
                to_id=to_id,
                anomaly_int=1 if anomalous else 0,
                now=now,
            )
            record = await result.single()

        if record is None:
            raise RuntimeError(f"Failed to record interaction {from_id!r}→{to_id!r}.")

        rel = dict(record["r"])
        edge = TrustEdge(
            from_agent_id=from_id,
            to_agent_id=to_id,
            interaction_count=int(rel["interaction_count"]),
            anomaly_count=int(rel["anomaly_count"]),
            last_interaction=(
                datetime.fromisoformat(rel["last_interaction"])
                if isinstance(rel.get("last_interaction"), str)
                else datetime.now(timezone.utc)
            ),
            trust_weight=float(rel.get("trust_weight", 1.0)),
        )
        logger.debug(
            "Interaction recorded: %s→%s anomalous=%s weight=%.3f",
            from_id,
            to_id,
            anomalous,
            edge.trust_weight,
        )
        return edge

    async def get_agent_permissions(self, agent_id: str) -> list[Permission]:
        """
        Fetch all active (granted=true, non-expired) permissions for an agent.

        Args:
            agent_id: Target agent UUID.

        Returns:
            List of Permission objects currently granted to the agent.

        Raises:
            Neo4jError: On database read failure.
        """
        async with self._session() as session:
            result = await session.run(CQL_GET_PERMISSIONS, agent_id=agent_id)
            records = await result.data()

        permissions: list[Permission] = []
        for record in records:
            perm = self._node_to_permission(dict(record["p"]))
            if not perm.is_expired:
                permissions.append(perm)

        return permissions

    async def grant_permission(
        self,
        agent_id: str,
        resource: ResourceType,
        granted_by: str,
        expires_at: datetime | None = None,
    ) -> Permission:
        """
        Grant a resource permission to an agent, persisting to Neo4j.

        Args:
            agent_id:   Target agent UUID.
            resource:   Resource type to grant.
            granted_by: UUID of granting agent or "SYSTEM".
            expires_at: Optional expiry datetime.

        Returns:
            The created/updated Permission.
        """
        now = datetime.now(timezone.utc)
        perm = Permission(
            agent_id=agent_id,
            resource=resource,
            granted=True,
            granted_by=granted_by,
            granted_at=now,
            expires_at=expires_at,
        )
        async with self._session() as session:
            await session.run(
                CQL_UPSERT_PERMISSION,
                agent_id=agent_id,
                resource=resource.value,
                granted=True,
                granted_by=granted_by,
                granted_at=now.isoformat(),
                expires_at=expires_at.isoformat() if expires_at else None,
            )
        logger.info(
            "Permission granted: agent=%s resource=%s by=%s",
            agent_id,
            resource,
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
        now = datetime.now(timezone.utc)
        async with self._session() as session:
            await session.run(
                CQL_UPSERT_PERMISSION,
                agent_id=agent_id,
                resource=resource.value,
                granted=False,
                granted_by=revoked_by,
                granted_at=now.isoformat(),
                expires_at=None,
            )
        logger.info(
            "Permission revoked: agent=%s resource=%s by=%s",
            agent_id,
            resource,
            revoked_by,
        )

    async def suspend_agent(self, agent_id: str, reason: str) -> AgentIdentity:
        """
        Set an agent's status to SUSPENDED and create an audit event.

        Args:
            agent_id: Target agent UUID.
            reason:   Human-readable suspension reason.

        Returns:
            The updated AgentIdentity.

        Raises:
            KeyError:   If the agent does not exist.
            Neo4jError: On database write failure.
        """
        async with self._session() as session:
            result = await session.run(
                CQL_SUSPEND_AGENT,
                agent_id=agent_id,
                reason=reason,
                occurred_at=datetime.now(timezone.utc).isoformat(),
            )
            record = await result.single()

        if record is None:
            raise KeyError(f"Agent not found: {agent_id!r}")

        agent = self._node_to_agent(dict(record["a"]))
        logger.warning("Agent suspended: id=%s reason=%r", agent_id, reason)
        return agent

    async def get_full_graph(self) -> TrustGraphSnapshot:
        """
        Return a complete snapshot of the trust graph for frontend visualisation.

        Returns:
            TrustGraphSnapshot with all Agent nodes and INTERACTS_WITH edges.

        Raises:
            Neo4jError: On database read failure.
        """
        async with self._session() as session:
            agents_result = await session.run(CQL_GET_ALL_AGENTS)
            agent_records = await agents_result.data()

            edges_result = await session.run(CQL_GET_ALL_EDGES)
            edge_records = await edges_result.data()

        nodes: list[AgentIdentity] = [self._node_to_agent(dict(r["a"])) for r in agent_records]

        edges: list[TrustEdge] = []
        for r in edge_records:
            last_ts = r.get("last_interaction")
            if isinstance(last_ts, str):
                last_ts = datetime.fromisoformat(last_ts)
            else:
                last_ts = datetime.now(timezone.utc)

            edges.append(
                TrustEdge(
                    from_agent_id=r["from_id"],
                    to_agent_id=r["to_id"],
                    interaction_count=int(r.get("interaction_count", 0)),
                    anomaly_count=int(r.get("anomaly_count", 0)),
                    last_interaction=last_ts,
                    trust_weight=float(r.get("trust_weight", 1.0)),
                )
            )

        snapshot = TrustGraphSnapshot(nodes=nodes, edges=edges)
        logger.debug("Graph snapshot: %d nodes, %d edges", len(nodes), len(edges))
        return snapshot

    async def decay_inactive_scores(self) -> int:
        """
        Apply 0.01/hour trust decay to agents inactive for over one hour.

        Returns:
            Count of agents whose scores were decayed.
        """
        async with self._session() as session:
            result = await session.run(CQL_DECAY_SCORES)
            record = await result.single()

        count: int = int(record["decayed_agents"]) if record else 0
        if count:
            logger.info("Trust decay applied to %d inactive agents.", count)
        return count
