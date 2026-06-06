"""
healing.py — FastAPI routes for the Self-Healing Engine.

Provides:
  GET  /api/healing/status     — Live agent health + recovery history
  POST /api/healing/trigger    — Manually trigger recovery on a specific agent
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.app.security.healing import SelfHealingOrchestrator

router = APIRouter(prefix="/api/healing", tags=["Self-Healing"])


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_healing_orchestrator(request: Request) -> SelfHealingOrchestrator:
    return request.app.state.healing_orchestrator


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/status")
async def get_healing_status(
    orchestrator: SelfHealingOrchestrator = Depends(get_healing_orchestrator),
) -> dict[str, Any]:
    """
    Return the current self-healing status:
    - per-agent health metrics and anomaly scores
    - recent recovery cycle history
    """
    try:
        return await orchestrator.get_healing_status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/trigger/{agent_id}")
async def trigger_recovery(
    agent_id: str,
    request: Request,
    reason: str = "Manual trigger via API",
    orchestrator: SelfHealingOrchestrator = Depends(get_healing_orchestrator),
) -> dict[str, str]:
    """
    Manually trigger the 8-step self-healing recovery protocol for a specific agent.
    """
    try:
        import asyncio

        asyncio.create_task(orchestrator._recovery.initiate_recovery(agent_id, reason, {}))
        return {"status": "triggered", "agent_id": agent_id, "reason": reason}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
