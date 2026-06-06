"""
AgentOps Security Mesh — Trust Graph API Router.

REST endpoints for querying and managing the Neo4j agent trust graph:
- Get agent trust score
- Update trust score (manual override)
- Query permission graph
- Get trust topology (all agents + edges)
- Authorize agent-to-agent call
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.auth import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────

class TrustScoreResponse(BaseModel):
    """Current trust state for an agent."""
    agent_id: str
    name: str
    trust_score: float
    status: str
    last_decay: Optional[str]
    quarantined: bool
    timestamp: str


class TrustUpdateRequest(BaseModel):
    """Manual trust score adjustment."""
    delta: float = Field(..., description="Score change (+/-). Applied to current score.")
    reason: str = Field(..., min_length=1, description="Human-readable justification")
    operator: Optional[str] = Field(None, description="Who made the change")


class AuthorizeRequest(BaseModel):
    """Request to authorize one agent calling another."""
    caller_id: str = Field(..., description="Agent making the call")
    target_id: str = Field(..., description="Agent being called")
    action: str = Field(..., description="Action being requested (e.g. 'read_memory')")


class AuthorizeResponse(BaseModel):
    """Authorization decision."""
    authorized: bool
    reason: str
    caller_trust_score: float
    path_exists: bool
    timestamp: str


class TrustTopologyResponse(BaseModel):
    """Full trust graph topology for visualization."""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    total_agents: int
    quarantined_count: int
    avg_trust_score: float
    timestamp: str


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/{agent_id}/score",
    response_model=TrustScoreResponse,
    summary="Get agent trust score",
)
async def get_trust_score(agent_id: str, request: Request) -> TrustScoreResponse:
    """
    Return the current trust score and status for a given agent.

    In Phase 4, this will query Neo4j directly.
    Currently reads from the in-memory agent registry + Redis.
    """
    from app.api.agents import _AGENT_REGISTRY
    from app.config import get_settings

    settings = get_settings()
    agent = _AGENT_REGISTRY.get(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    trust_score = agent.get("trust_score", settings.initial_trust_score)
    quarantined = agent.get("status") == "quarantined"

    # Try Redis for last_decay timestamp
    redis = getattr(request.app.state, "redis", None)
    last_decay = None
    if redis:
        last_decay = await redis.hget(f"agent:{agent_id}:trust", "last_decay")

    return TrustScoreResponse(
        agent_id=agent_id,
        name=agent["name"],
        trust_score=trust_score,
        status=agent.get("status", "idle"),
        last_decay=last_decay,
        quarantined=quarantined,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post(
    "/{agent_id}/score",
    summary="Manually adjust agent trust score",
)
async def update_trust_score(
    agent_id: str,
    body: TrustUpdateRequest,
    request: Request,
) -> Dict[str, Any]:
    """
    Apply a manual trust score adjustment (positive or negative delta).

    Score is clamped to [0, 100].
    Broadcasts 'trust:score_updated' event to WebSocket subscribers.
    Quarantines agent if score drops below threshold.
    """
    from app.api.agents import _AGENT_REGISTRY
    from app.config import get_settings

    settings = get_settings()
    agent = _AGENT_REGISTRY.get(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    old_score = float(agent.get("trust_score", settings.initial_trust_score))
    new_score = max(0.0, min(100.0, old_score + body.delta))
    agent["trust_score"] = new_score
    now = datetime.now(timezone.utc).isoformat()

    # Auto-quarantine if below threshold
    quarantined = False
    if new_score < settings.trust_quarantine_threshold and agent["status"] not in ("terminated",):
        agent["status"] = "quarantined"
        quarantined = True

    # Persist to Redis
    redis = getattr(request.app.state, "redis", None)
    if redis:
        await redis.hset(
            f"agent:{agent_id}:trust",
            mapping={
                "score": str(new_score),
                "last_updated": now,
                "last_reason": body.reason,
            },
        )
        if quarantined:
            await redis.hset(f"agent:{agent_id}:meta", "status", "quarantined")

    # Broadcast
    ws_manager = getattr(request.app.state, "ws_manager", None)
    if ws_manager:
        await ws_manager.broadcast(
            {
                "type": "trust:score_updated",
                "agent_id": agent_id,
                "name": agent["name"],
                "old_score": old_score,
                "new_score": new_score,
                "delta": body.delta,
                "reason": body.reason,
                "quarantined": quarantined,
                "timestamp": now,
            },
            channel="agents",
        )

    return {
        "agent_id": agent_id,
        "old_score": old_score,
        "new_score": new_score,
        "delta": body.delta,
        "quarantined": quarantined,
        "reason": body.reason,
        "timestamp": now,
    }


@router.post(
    "/authorize",
    response_model=AuthorizeResponse,
    summary="Authorize agent-to-agent call",
)
async def authorize_call(
    body: AuthorizeRequest,
    request: Request,
) -> AuthorizeResponse:
    """
    Determine whether caller_id is authorized to perform action on target_id.

    Authorization logic (Phase 4 will use full Cypher graph traversal):
    1. Caller must exist and have trust_score > quarantine threshold
    2. Caller must not be quarantined/terminated
    3. Permission path must exist in trust graph (scaffold: role-based check)
    """
    from app.api.agents import _AGENT_REGISTRY
    from app.config import get_settings

    settings = get_settings()
    now = datetime.now(timezone.utc).isoformat()

    caller = _AGENT_REGISTRY.get(body.caller_id)
    target = _AGENT_REGISTRY.get(body.target_id)

    if not caller:
        return AuthorizeResponse(
            authorized=False,
            reason=f"Caller agent '{body.caller_id}' not found",
            caller_trust_score=0.0,
            path_exists=False,
            timestamp=now,
        )

    caller_score = float(caller.get("trust_score", 0))

    # Trust score gate
    if caller_score < settings.trust_quarantine_threshold:
        return AuthorizeResponse(
            authorized=False,
            reason=f"Caller trust score {caller_score:.1f} below quarantine threshold {settings.trust_quarantine_threshold}",
            caller_trust_score=caller_score,
            path_exists=False,
            timestamp=now,
        )

    # Status gate
    blocked_statuses = {"quarantined", "terminated", "failed"}
    if caller.get("status") in blocked_statuses:
        return AuthorizeResponse(
            authorized=False,
            reason=f"Caller agent is {caller.get('status')} — cannot make calls",
            caller_trust_score=caller_score,
            path_exists=False,
            timestamp=now,
        )

    # Scaffold permission check (Phase 4 replaces with Neo4j Cypher traversal)
    _ROLE_PERMISSIONS: Dict[str, List[str]] = {
        "planner": ["read_memory", "write_memory", "delegate", "query_trust"],
        "web": ["read_memory", "fetch_url"],
        "code": ["read_memory", "write_memory", "execute_code"],
        "api": ["read_memory", "api_call"],
        "memory": ["read_memory", "write_memory", "checkpoint"],
        "monitor": ["read_memory", "query_trust", "read_events"],
    }

    caller_role = caller.get("role", "web")
    allowed_actions = _ROLE_PERMISSIONS.get(caller_role, [])
    path_exists = body.action in allowed_actions

    return AuthorizeResponse(
        authorized=path_exists,
        reason=(
            f"Action '{body.action}' allowed for role '{caller_role}'"
            if path_exists
            else f"Action '{body.action}' not in permissions for role '{caller_role}'"
        ),
        caller_trust_score=caller_score,
        path_exists=path_exists,
        timestamp=now,
    )


@router.get(
    "/topology",
    response_model=TrustTopologyResponse,
    summary="Get full trust graph topology",
)
async def get_topology(request: Request) -> TrustTopologyResponse:
    """
    Return full trust graph topology for dashboard visualization.

    Returns nodes (agents) and edges (trust relationships / permissions).
    Phase 4 replaces this with a live Neo4j Cypher query.
    """
    from app.api.agents import _AGENT_REGISTRY
    from app.config import get_settings

    settings = get_settings()
    agents = list(_AGENT_REGISTRY.values())

    nodes = [
        {
            "id": a["agent_id"],
            "name": a["name"],
            "role": a["role"],
            "status": a["status"],
            "trust_score": a.get("trust_score", settings.initial_trust_score),
            "quarantined": a.get("status") == "quarantined",
        }
        for a in agents
    ]

    # Scaffold: planner connects to all executors
    edges = []
    planner_nodes = [n for n in nodes if n["role"] == "planner"]
    executor_nodes = [n for n in nodes if n["role"] != "planner"]
    for planner in planner_nodes:
        for executor in executor_nodes:
            edges.append({
                "id": str(uuid.uuid4()),
                "source": planner["id"],
                "target": executor["id"],
                "type": "DELEGATES_TO",
                "trust_weight": min(planner["trust_score"], executor["trust_score"]) / 100.0,
            })

    scores = [n["trust_score"] for n in nodes] or [0.0]
    quarantined = sum(1 for n in nodes if n["quarantined"])

    return TrustTopologyResponse(
        nodes=nodes,
        edges=edges,
        total_agents=len(nodes),
        quarantined_count=quarantined,
        avg_trust_score=round(sum(scores) / len(scores), 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
