"""
security.py — FastAPI routes for Security Events and Anomalies.

Provides endpoints for fetching recent security events, aggregated statistics,
anomaly scores, and self-healing recovery history.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from backend.app.security.events import EventSeverity, EventType, SecurityEventEmitter
from backend.app.security.healing import SelfHealingOrchestrator
from backend.app.security.recovery import RecoveryManager

router = APIRouter(prefix="/api/security", tags=["Security"])

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def get_event_emitter(request: Request) -> SecurityEventEmitter:
    return request.app.state.event_emitter

def get_healing_orchestrator(request: Request) -> SelfHealingOrchestrator:
    return request.app.state.healing_orchestrator

def get_recovery_manager(request: Request) -> RecoveryManager:
    return request.app.state.recovery_manager

def get_redis(request: Request) -> Any:
    return request.app.state.redis

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class EventStats(BaseModel):
    total_events: int
    by_severity: dict[str, int]
    by_type: dict[str, int]

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/events")
async def get_recent_events(
    limit: int = Query(100, ge=1, le=1000),
    min_severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    event_type: Optional[str] = Query(None, description="Event type string"),
    agent_id: Optional[str] = Query(None),
    emitter: SecurityEventEmitter = Depends(get_event_emitter),
) -> list[dict[str, Any]]:
    """Get a list of recent security events from the Redis sorted set."""
    try:
        sev_enum = EventSeverity(min_severity) if min_severity else None
        type_enum = EventType(event_type) if event_type else None
        
        events = await emitter.get_recent_events(
            limit=limit,
            min_severity=sev_enum,
            event_type=type_enum,
            agent_id=agent_id,
        )
        return [json.loads(e.model_dump_json()) for e in events]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/events/stats", response_model=EventStats)
async def get_event_stats(
    emitter: SecurityEventEmitter = Depends(get_event_emitter),
) -> EventStats:
    """Get aggregated statistics of the recent events for dashboard charts."""
    try:
        # Fetch a large chunk to aggregate
        events = await emitter.get_recent_events(limit=500)
        
        by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        by_type: dict[str, int] = {}
        
        for e in events:
            by_severity[e.severity.value] += 1
            by_type[e.event_type.value] = by_type.get(e.event_type.value, 0) + 1
            
        return EventStats(
            total_events=len(events),
            by_severity=by_severity,
            by_type=by_type,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/firewall/stats")
async def get_firewall_stats(
    emitter: SecurityEventEmitter = Depends(get_event_emitter),
) -> dict[str, Any]:
    """
    Get aggregated stats for the Prompt Injection Firewall from the live event history.
    """
    try:
        events = await emitter.get_recent_events(limit=500)

        total_scans = len(events)
        blocked_scans = sum(1 for e in events if e.event_type.value in ("BLOCKED", "THREAT_DETECTED"))
        block_rate = round(blocked_scans / total_scans, 3) if total_scans > 0 else 0.0

        # Count by event type for top threats
        type_counts: dict[str, int] = {}
        for e in events:
            t = e.event_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        top_threats = [
            {"type": k, "count": v}
            for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
        ][:5]

        return {
            "total_scans": total_scans,
            "blocked_scans": blocked_scans,
            "block_rate": block_rate,
            "top_threats": top_threats,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/anomalies")
async def get_current_anomalies(
    healing: SelfHealingOrchestrator = Depends(get_healing_orchestrator),
) -> dict[str, Any]:
    """
    Get the latest anomaly scores and health status for all active agents.
    """
    try:
        status = await healing.get_healing_status()
        return status["agent_health"]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/recovery/history")
async def get_recovery_history(
    recovery: RecoveryManager = Depends(get_recovery_manager),
) -> list[dict[str, Any]]:
    """
    Get the full history of self-healing recovery attempts.
    """
    try:
        history = await recovery.get_recovery_history()
        return [json.loads(h.model_dump_json()) for h in history]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
