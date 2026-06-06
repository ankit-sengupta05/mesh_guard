"""
AgentOps Security Mesh — Agents API Router.

CRUD endpoints for managing agent lifecycle:
- Register new agents
- List active agents
- Get agent details + trust score
- Pause / resume / terminate agents
- Emit lifecycle events to WebSocket subscribers
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.auth import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ─────────────────────────────────────────────────────────────────────────────
# Enums + Models
# ─────────────────────────────────────────────────────────────────────────────

class AgentRole(str, Enum):
    """Defines the capability set granted to an agent in the trust graph."""
    PLANNER = "planner"
    WEB = "web"
    CODE = "code"
    API = "api"
    MEMORY = "memory"
    MONITOR = "monitor"


class AgentStatus(str, Enum):
    """Current lifecycle state of an agent."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    QUARANTINED = "quarantined"
    TERMINATED = "terminated"
    FAILED = "failed"


class AgentRegisterRequest(BaseModel):
    """Request body for registering a new agent."""
    name: str = Field(..., min_length=1, max_length=64, description="Unique agent name")
    role: AgentRole = Field(..., description="Agent role determines trust permissions")
    description: Optional[str] = Field(None, max_length=256, description="Human-readable description")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary agent metadata")


class AgentResponse(BaseModel):
    """Agent data returned from API endpoints."""
    agent_id: str
    name: str
    role: AgentRole
    status: AgentStatus
    trust_score: float
    description: Optional[str]
    metadata: Dict[str, Any]
    registered_at: str
    last_active: Optional[str]


class AgentControlRequest(BaseModel):
    """Request body for agent control actions."""
    action: str = Field(..., description="Action: pause | resume | terminate | quarantine")
    reason: Optional[str] = Field(None, description="Human-readable reason for the action")


# ─────────────────────────────────────────────────────────────────────────────
# In-memory agent registry (Phase 2+ will use Redis + Neo4j persistence)
# ─────────────────────────────────────────────────────────────────────────────

_AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new agent",
)
async def register_agent(
    body: AgentRegisterRequest,
    request: Request,
) -> AgentResponse:
    """
    Register a new agent in the security mesh.

    Creates:
    1. Agent entry in in-memory registry (scaffolding — Phase 4 adds Neo4j)
    2. Agent entry in Redis with initial state
    3. Broadcasts 'agent:registered' event to WebSocket subscribers

    Returns the new agent's full record including assigned agent_id.
    """
    from app.config import get_settings
    settings = get_settings()

    # Check for name collision
    existing = next(
        (a for a in _AGENT_REGISTRY.values() if a["name"] == body.name),
        None,
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent with name '{body.name}' already registered",
        )

    agent_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    agent_data: Dict[str, Any] = {
        "agent_id": agent_id,
        "name": body.name,
        "role": body.role.value,
        "status": AgentStatus.IDLE.value,
        "trust_score": float(settings.initial_trust_score),
        "description": body.description,
        "metadata": body.metadata or {},
        "registered_at": now,
        "last_active": None,
    }

    _AGENT_REGISTRY[agent_id] = agent_data

    # Persist to Redis
    redis = getattr(request.app.state, "redis", None)
    if redis:
        await redis.hset(
            f"agent:{agent_id}:meta",
            mapping={k: json.dumps(v) if isinstance(v, dict) else str(v) for k, v in agent_data.items()},
        )
        await redis.expire(f"agent:{agent_id}:meta", settings.redis_default_ttl)
        await redis.sadd("agents:active", agent_id)

    # Broadcast event
    ws_manager = getattr(request.app.state, "ws_manager", None)
    if ws_manager:
        await ws_manager.broadcast(
            {
                "type": "agent:registered",
                "agent_id": agent_id,
                "name": body.name,
                "role": body.role.value,
                "trust_score": float(settings.initial_trust_score),
                "timestamp": now,
            },
            channel="agents",
        )

    return AgentResponse(**agent_data)


@router.get(
    "/",
    response_model=List[AgentResponse],
    summary="List all registered agents",
)
async def list_agents(
    status_filter: Optional[AgentStatus] = None,
    role_filter: Optional[AgentRole] = None,
) -> List[AgentResponse]:
    """
    Return all registered agents, optionally filtered by status or role.
    """
    agents = list(_AGENT_REGISTRY.values())

    if status_filter:
        agents = [a for a in agents if a["status"] == status_filter.value]
    if role_filter:
        agents = [a for a in agents if a["role"] == role_filter.value]

    return [AgentResponse(**a) for a in agents]


@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    summary="Get agent by ID",
)
async def get_agent(agent_id: str) -> AgentResponse:
    """Return a single agent's full record by agent_id."""
    agent = _AGENT_REGISTRY.get(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )
    return AgentResponse(**agent)


@router.post(
    "/{agent_id}/control",
    summary="Control agent lifecycle (pause/resume/terminate/quarantine)",
)
async def control_agent(
    agent_id: str,
    body: AgentControlRequest,
    request: Request,
) -> Dict[str, Any]:
    """
    Send a control command to an agent.

    Actions:
    - **pause**: Halt agent task execution, preserve state
    - **resume**: Restart a paused agent
    - **terminate**: Permanently stop the agent
    - **quarantine**: Isolate agent due to security anomaly

    All control actions are broadcast to WebSocket subscribers.
    """
    agent = _AGENT_REGISTRY.get(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    valid_actions = {"pause", "resume", "terminate", "quarantine"}
    if body.action not in valid_actions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid action '{body.action}'. Must be one of: {valid_actions}",
        )

    # Apply status transition
    action_to_status = {
        "pause": AgentStatus.PAUSED,
        "resume": AgentStatus.IDLE,
        "terminate": AgentStatus.TERMINATED,
        "quarantine": AgentStatus.QUARANTINED,
    }
    new_status = action_to_status[body.action]
    agent["status"] = new_status.value
    now = datetime.now(timezone.utc).isoformat()

    # Persist to Redis
    redis = getattr(request.app.state, "redis", None)
    if redis:
        await redis.hset(f"agent:{agent_id}:meta", "status", new_status.value)
        if body.action == "terminate":
            await redis.srem("agents:active", agent_id)
            await redis.sadd("agents:terminated", agent_id)

    # Broadcast
    ws_manager = getattr(request.app.state, "ws_manager", None)
    if ws_manager:
        await ws_manager.broadcast(
            {
                "type": f"agent:{body.action}",
                "agent_id": agent_id,
                "name": agent["name"],
                "new_status": new_status.value,
                "reason": body.reason,
                "timestamp": now,
            },
            channel="agents",
        )

    return {
        "agent_id": agent_id,
        "action": body.action,
        "new_status": new_status.value,
        "timestamp": now,
    }


@router.delete(
    "/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deregister and remove an agent",
)
async def delete_agent(agent_id: str, request: Request) -> None:
    """Permanently remove an agent from the registry and Redis."""
    if agent_id not in _AGENT_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    del _AGENT_REGISTRY[agent_id]

    redis = getattr(request.app.state, "redis", None)
    if redis:
        await redis.delete(f"agent:{agent_id}:meta")
        await redis.delete(f"agent:{agent_id}:memory")
        await redis.srem("agents:active", agent_id)
