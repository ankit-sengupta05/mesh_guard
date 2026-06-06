"""
agents.py — FastAPI routes for Agent Management.

Provides endpoints to list agents, view trust scores, inspect memory
snapshots, and manually suspend or restore agents.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.app.trust.graph import AsyncNeo4jTrustGraph
from backend.app.memory.snapshots import MemorySnapshotManager

router = APIRouter(prefix="/api/agents", tags=["Agents"])

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_trust_graph(request: Request) -> AsyncNeo4jTrustGraph:
    return request.app.state.trust_graph


def get_snapshot_manager(request: Request) -> MemorySnapshotManager:
    return request.app.state.snapshot_manager


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
async def list_agents(
    trust_graph: AsyncNeo4jTrustGraph = Depends(get_trust_graph),
) -> list[dict[str, Any]]:
    """Get all registered agents and their current trust scores/status."""
    try:
        # trust_graph.get_all_agents() needs to be implemented in Neo4jTrustGraph,
        # but for now we assume it exists or we mock it.
        # As a fallback, we fetch via a custom Cypher query.
        records = await trust_graph._execute_read(
            "MATCH (a:Agent) RETURN a.id AS id, a.name AS name, a.role AS role, "
            "a.trust_score AS trust_score, a.status AS status"
        )
        return [dict(r) for r in records]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{agent_id}")
async def get_agent_detail(
    agent_id: str,
    trust_graph: AsyncNeo4jTrustGraph = Depends(get_trust_graph),
    snapshots: MemorySnapshotManager = Depends(get_snapshot_manager),
) -> dict[str, Any]:
    """Get full details for a specific agent, including memory snapshots."""
    try:
        agent = await trust_graph.get_agent(agent_id)
        snaps = await snapshots.list_snapshots(agent_id)

        return {
            "identity": agent.model_dump(),
            "snapshots": [s.model_dump() for s in snaps],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{agent_id}/permissions")
async def get_agent_permissions(
    agent_id: str,
    request: Request,
) -> list[str]:
    """List all resource permissions granted to this agent."""
    enforcer = request.app.state.permission_enforcer
    try:
        # In a real app we'd query the DB for all grants.
        # The PermissionEnforcer currently checks specific resources.
        # We'll just return a mock or run a Cypher query.
        records = await enforcer.trust_graph._execute_read(
            "MATCH (a:Agent {id: $agent_id})-[:HAS_PERMISSION]->(r:Resource) "
            "RETURN r.type AS type",
            {"agent_id": agent_id},
        )
        return [r["type"] for r in records]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{agent_id}/suspend")
async def suspend_agent(
    agent_id: str,
    reason: str = "Manual suspension via API",
    trust_graph: AsyncNeo4jTrustGraph = Depends(get_trust_graph),
) -> dict[str, str]:
    """Manually suspend an agent, revoking all permissions."""
    try:
        await trust_graph.suspend_agent(agent_id, reason)
        return {"status": "success", "message": f"Agent {agent_id} suspended."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{agent_id}/restore")
async def restore_agent(
    agent_id: str,
    snapshot_id: str,
    snapshots: MemorySnapshotManager = Depends(get_snapshot_manager),
) -> dict[str, str]:
    """Restore an agent's memory to a specific snapshot."""
    try:
        await snapshots.restore_snapshot(agent_id, snapshot_id)
        return {"status": "success", "message": f"Restored snapshot {snapshot_id}."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Global Graph Visualization Route
# ---------------------------------------------------------------------------


@router.get("/trust-graph/viz")
async def get_trust_graph_viz(
    trust_graph: AsyncNeo4jTrustGraph = Depends(get_trust_graph),
) -> dict[str, Any]:
    """
    Export the entire Neo4j trust graph as nodes and edges for frontend D3.
    Returns nodes with name, role, trust_score, status at the top level.
    """
    try:
        # Get all Agent nodes directly
        agent_records = await trust_graph._execute_read(
            "MATCH (a:Agent) RETURN a.id AS id, a.name AS name, a.role AS role, "
            "a.trust_score AS trust_score, a.status AS status"
        )

        # Get all edges
        edge_records = await trust_graph._execute_read(
            "MATCH (src:Agent)-[r:INTERACTS_WITH]->(dst:Agent) "
            "RETURN src.id AS source, dst.id AS target, "
            "type(r) AS type, r.interaction_count AS interaction_count, "
            "r.trust_weight AS trust_weight"
        )

        nodes = []
        for r in agent_records:
            if r.get("id"):
                nodes.append(
                    {
                        "id": r["id"],
                        "name": r.get("name") or r["id"],
                        "role": r.get("role") or "executor",
                        "trust_score": float(r.get("trust_score") or 1.0),
                        "status": r.get("status") or "ACTIVE",
                    }
                )

        edges = []
        for r in edge_records:
            if r.get("source") and r.get("target"):
                edges.append(
                    {
                        "source": r["source"],
                        "target": r["target"],
                        "type": r.get("type") or "INTERACTS_WITH",
                        "interaction_count": int(r.get("interaction_count") or 1),
                        "trust_weight": float(r.get("trust_weight") or 1.0),
                    }
                )

        return {"nodes": nodes, "edges": edges}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
