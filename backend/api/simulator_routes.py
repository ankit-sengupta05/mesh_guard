"""
simulator_routes.py — FastAPI routes for the Attack Simulator Demo.

Exposes endpoints to trigger specific attacks, run the full demo sequence,
and stream live AttackResult events over WebSockets.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from starlette.requests import Request

from backend.app.security.attack_payloads import SCENARIOS
from backend.app.security.simulator import AttackResult, AttackSimulator

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/simulator",
    tags=["Attack Simulator"],
)

# ---------------------------------------------------------------------------
# Dependency Injection
# ---------------------------------------------------------------------------

def get_simulator(request: Request) -> AttackSimulator:
    """Extract the AttackSimulator instance from the FastAPI app state."""
    # Assuming `app.state.simulator` is set during FastAPI startup
    return request.app.state.simulator


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/scenarios", response_model=list[dict[str, Any]])
async def list_scenarios() -> list[dict[str, Any]]:
    """Return all available attack scenarios with their descriptions."""
    return [
        {
            "name": name,
            "description": scenario.description,
            "target": scenario.target_agent,
            "injection_point": scenario.injection_point,
        }
        for name, scenario in SCENARIOS.items()
    ]


@router.get("/history", response_model=list[AttackResult])
async def get_attack_history(
    simulator: AttackSimulator = Depends(get_simulator),
) -> list[AttackResult]:
    """Return the history of all simulated attacks."""
    return await simulator.get_attack_history()


@router.post("/attack/{scenario_name}", response_model=AttackResult)
async def trigger_attack(
    scenario_name: str,
    simulator: AttackSimulator = Depends(get_simulator),
) -> AttackResult:
    """
    Trigger a single specific attack scenario.
    """
    if scenario_name not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")
        
    try:
        return await simulator.run_attack(scenario_name)
    except Exception as exc:  # noqa: BLE001
        logger.error("Error running attack %s: %s", scenario_name, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/demo")
async def trigger_full_demo_sequence(
    simulator: AttackSimulator = Depends(get_simulator),
) -> dict[str, str]:
    """
    Start the full 8-attack demo sequence in the background.
    Results will be streamed over the WebSocket.
    """
    # Fire and forget
    asyncio.create_task(simulator.run_full_demo_sequence())
    return {"message": "Demo sequence started. Subscribe to /ws/simulator to view results."}


# ---------------------------------------------------------------------------
# WebSockets
# ---------------------------------------------------------------------------

@router.websocket("/ws/events")
async def simulator_websocket(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for streaming raw SecurityEvents (which includes the
    AttackResult events emitted by the simulator).
    """
    await websocket.accept()
    
    # We retrieve the SecurityEventEmitter from app state
    emitter = websocket.app.state.event_emitter
    
    # Define an async push callback
    async def push_event(payload_json: str) -> None:
        try:
            await websocket.send_text(payload_json)
        except Exception:
            pass

    conn_id = str(id(websocket))
    emitter.subscribe_websocket(conn_id, push_event)
    
    logger.info("WebSocket client connected to simulator stream.")
    
    try:
        # Keep connection open, waiting for client disconnect
        while True:
            await websocket.receive_text()
            
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected from simulator stream.")
    except Exception as exc:  # noqa: BLE001
        logger.error("WebSocket error: %s", exc)
    finally:
        emitter.unsubscribe_websocket(conn_id)
