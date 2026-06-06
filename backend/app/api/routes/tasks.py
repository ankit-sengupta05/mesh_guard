"""
tasks.py — FastAPI routes for Task Execution and Swarm Orchestration.

Provides endpoints to submit tasks to the LangGraph swarm, check task status,
list recent tasks, and stream real-time SwarmState updates via WebSockets.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from backend.app.graph.orchestrator import SwarmOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tasks", tags=["Tasks"])

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_orchestrator(request: Request) -> SwarmOrchestrator:
    return request.app.state.orchestrator


def get_redis(request: Request) -> Any:
    return request.app.state.redis


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TaskSubmitRequest(BaseModel):
    task: str


class TaskSubmitResponse(BaseModel):
    task_id: str
    status: str


# ---------------------------------------------------------------------------
# Global Task Store (in-memory for demo, should be Redis in prod)
# ---------------------------------------------------------------------------

# In a real app we'd query the langgraph checkpointer (MemorySaver or PostgresSaver)
# For this demo, we'll keep a lightweight dict of recent runs
_task_runs: dict[str, dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Background Task Runner
# ---------------------------------------------------------------------------


async def _run_task_background(
    task_id: str, task: str, orchestrator: SwarmOrchestrator, redis: Any
):
    """Run the graph and store the latest state."""
    _task_runs[task_id] = {
        "task_id": task_id,
        "task": task,
        "status": "RUNNING",
        "latest_state": None,
    }

    try:
        # astream yields the full state dict after each node
        async for state_snapshot in orchestrator.run_task(task, run_id=task_id):
            _task_runs[task_id]["latest_state"] = state_snapshot

            # Broadcast state update to Redis pub/sub for the WebSocket to pick up
            payload = {"type": "SWARM_STATE_UPDATE", "task_id": task_id, "state": state_snapshot}
            await redis.publish(f"tasks:stream:{task_id}", json.dumps(payload))

        _task_runs[task_id]["status"] = "COMPLETED"
    except Exception as exc:  # noqa: BLE001
        logger.error("Background task %s failed: %s", task_id, exc, exc_info=True)
        _task_runs[task_id]["status"] = "FAILED"
        _task_runs[task_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=TaskSubmitResponse)
async def submit_task(
    req: TaskSubmitRequest,
    request: Request,
    orchestrator: SwarmOrchestrator = Depends(get_orchestrator),
    redis=Depends(get_redis),
) -> TaskSubmitResponse:
    """
    Submit a new task to the AgentOps swarm.
    Returns a task_id immediately. Execution happens in the background.
    """
    task_id = str(uuid.uuid4())

    # Fire and forget the background execution
    asyncio.create_task(_run_task_background(task_id, req.task, orchestrator, redis))

    return TaskSubmitResponse(task_id=task_id, status="STARTED")


@router.get("")
async def list_tasks() -> list[dict[str, Any]]:
    """List all recent tasks and their current status."""
    return [
        {
            "task_id": t["task_id"],
            "task": t["task"],
            "status": t["status"],
        }
        for t in _task_runs.values()
    ]


@router.get("/{task_id}")
async def get_task_status(task_id: str) -> dict[str, Any]:
    """Get the latest state and status of a specific task."""
    if task_id not in _task_runs:
        raise HTTPException(status_code=404, detail="Task not found")

    return _task_runs[task_id]


# ---------------------------------------------------------------------------
# WebSockets
# ---------------------------------------------------------------------------


@router.websocket("/ws/{task_id}")
async def task_websocket(websocket: WebSocket, task_id: str) -> None:
    """
    WebSocket endpoint for streaming live SwarmState updates for a specific task.
    """
    await websocket.accept()
    redis = websocket.app.state.redis
    pubsub = redis.pubsub()
    channel = f"tasks:stream:{task_id}"

    await pubsub.subscribe(channel)
    logger.info("WebSocket connected to task stream: %s", task_id)

    try:
        # Send the current state immediately if available
        if task_id in _task_runs and _task_runs[task_id]["latest_state"]:
            await websocket.send_json(
                {
                    "type": "SWARM_STATE_UPDATE",
                    "task_id": task_id,
                    "state": _task_runs[task_id]["latest_state"],
                }
            )

        while True:
            # Check for disconnects
            try:
                # Use a small timeout to yield back to event loop
                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                pass

            # Check for Redis messages
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message and message["type"] == "message":
                payload = message["data"].decode("utf-8")
                await websocket.send_text(payload)

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected from task stream: %s", task_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("Task WebSocket error: %s", exc)
    finally:
        await pubsub.unsubscribe(channel)
