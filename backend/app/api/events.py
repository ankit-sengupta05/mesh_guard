"""
AgentOps Security Mesh — WebSocket Events Router.

Additional REST endpoints supporting the WebSocket event system:
- Get WebSocket connection status
- Emit a manual test event (dev/testing)
- Get event channel definitions
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.auth import require_api_key

router = APIRouter()  # No auth required for status endpoint


class EventBroadcastRequest(BaseModel):
    """Manually broadcast a test event via WebSocket."""

    channel: str = Field(default="*", description="Target channel")
    event_type: str = Field(..., description="Event type label")
    data: Dict[str, Any] = Field(default_factory=dict, description="Event payload")


@router.get("/ws/status", summary="WebSocket connection status")
async def ws_status(request: Request) -> Dict[str, Any]:
    """Return current WebSocket manager state."""
    ws_manager = getattr(request.app.state, "ws_manager", None)
    return {
        "active_connections": ws_manager.connection_count if ws_manager else 0,
        "channels": ["threats", "agents", "recovery", "attack", "*"],
        "websocket_url": "/ws/events",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post(
    "/ws/broadcast",
    dependencies=[Depends(require_api_key)],
    summary="Broadcast a test event to WebSocket subscribers",
)
async def broadcast_test_event(
    body: EventBroadcastRequest,
    request: Request,
) -> Dict[str, Any]:
    """
    Manually emit an event to WebSocket subscribers.

    Useful for testing the dashboard UI without triggering real attacks.
    """
    ws_manager = getattr(request.app.state, "ws_manager", None)
    if not ws_manager:
        return {"status": "error", "message": "WebSocket manager not initialized"}

    event = {
        "type": body.event_type,
        "data": body.data,
        "manual": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    await ws_manager.broadcast(event, channel=body.channel)

    return {
        "status": "broadcast",
        "channel": body.channel,
        "event_type": body.event_type,
        "delivered_to": ws_manager.connection_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
