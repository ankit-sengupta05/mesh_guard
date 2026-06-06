"""
AgentOps Security Mesh — Health Check API Router.

Provides liveness and readiness endpoints for:
- Docker healthcheck
- Azure Container Apps health probes
- Kubernetes liveness/readiness probes
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health", summary="Liveness probe")
async def health(request: Request) -> Dict[str, Any]:
    """
    Liveness endpoint — returns 200 if the process is alive.

    Does NOT check downstream dependencies (use /ready for that).
    Used by Docker HEALTHCHECK and load balancers.
    """
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready", summary="Readiness probe")
async def ready(request: Request) -> Dict[str, Any]:
    """
    Readiness endpoint — returns 200 only when all dependencies are connected.

    Checks:
    - Redis connectivity (ping)
    - Neo4j connectivity (verify_connectivity)
    - Application ready flag

    Returns 503 if any dependency is unavailable.
    """
    from fastapi import HTTPException

    state = request.app.state
    checks: Dict[str, str] = {}
    all_healthy = True

    # Redis check
    if state.redis:
        try:
            await state.redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {exc}"
            all_healthy = False
    else:
        checks["redis"] = "not_initialized"
        all_healthy = False

    # Neo4j check
    if state.neo4j:
        try:
            await state.neo4j.verify_connectivity()
            checks["neo4j"] = "ok"
        except Exception as exc:
            checks["neo4j"] = f"error: {exc}"
            all_healthy = False
    else:
        checks["neo4j"] = "not_initialized"
        all_healthy = False

    # WebSocket manager
    checks["websocket_manager"] = "ok" if state.ws_manager else "not_initialized"
    checks["active_ws_connections"] = str(
        state.ws_manager.connection_count if state.ws_manager else 0
    )

    startup_time = getattr(state, "startup_time", None)
    uptime_seconds = (
        (datetime.now(timezone.utc) - startup_time).total_seconds()
        if startup_time
        else 0
    )

    response = {
        "status": "ready" if all_healthy else "degraded",
        "version": "1.0.0",
        "uptime_seconds": round(uptime_seconds, 2),
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if not all_healthy:
        raise HTTPException(status_code=503, detail=response)

    return response
