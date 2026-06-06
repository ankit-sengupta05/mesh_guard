"""
main.py — FastAPI Application Entrypoint for AgentOps Security Mesh.

Assembles all subsystems: Redis Memory, Neo4j Trust Graph, Prompt Injection Firewall,
LangGraph Swarm Orchestrator, Self-Healing Daemon, and the Attack Simulator.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# Domain imports
from backend.app.graph.orchestrator import SwarmOrchestrator
from backend.app.memory.boundaries import MemoryBoundaryEnforcer
from backend.app.memory.manager import AgentMemoryManager
from backend.app.memory.snapshots import MemorySnapshotManager
from backend.app.security.anomaly import AnomalyDetector
from backend.app.security.events import SECURITY_EVENTS_CHANNEL, SecurityEventEmitter
from backend.app.security.firewall import PromptInjectionFirewall
from backend.app.security.healing import SelfHealingOrchestrator
from backend.app.security.recovery import RecoveryManager
from backend.app.security.simulator import AttackSimulator
from backend.app.trust.graph import AsyncNeo4jTrustGraph
from backend.app.trust.permissions import PermissionEnforcer

# API Routers
from backend.app.api.routes import agents, security, tasks, healing
from backend.app.api.websocket import manager as ws_manager
from backend.api import simulator_routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agentops")

# ---------------------------------------------------------------------------
# Background Tasks
# ---------------------------------------------------------------------------

async def redis_event_subscriber(redis: aioredis.Redis, ws_mgr):
    """
    Background task that subscribes to the Redis Pub/Sub channel for security events
    and forwards them to all connected WebSocket dashboard clients.
    """
    pubsub = redis.pubsub()
    await pubsub.subscribe(SECURITY_EVENTS_CHANNEL)
    logger.info("Subscribed to Redis channel: %s", SECURITY_EVENTS_CHANNEL)
    
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                payload = message["data"].decode("utf-8")
                # Broadcast the raw JSON to all dashboard clients
                await ws_mgr.broadcast_raw(payload)
    except asyncio.CancelledError:
        logger.info("Redis event subscriber cancelled.")
    except Exception as exc:  # noqa: BLE001
        logger.error("Redis event subscriber error: %s", exc)
    finally:
        await pubsub.unsubscribe(SECURITY_EVENTS_CHANNEL)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle hooks."""
    logger.info("Starting AgentOps Security Mesh...")
    
    # 1. Initialize Redis
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    app.state.redis = aioredis.from_url(redis_url, decode_responses=False)
    
    # 2. Initialize Neo4j Trust Graph
    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("NEO4J_PASSWORD", "password")
    
    trust_graph = AsyncNeo4jTrustGraph(neo4j_uri, neo4j_user, neo4j_password)
    app.state.trust_graph = trust_graph
    
    # 3. Initialize Core Managers
    app.state.event_emitter = SecurityEventEmitter(app.state.redis)
    # MemoryBoundaryEnforcer enforces per-agent key-prefix isolation
    boundary_enforcer = MemoryBoundaryEnforcer(app.state.redis)
    app.state.memory_manager = AgentMemoryManager(
        enforcer=boundary_enforcer,
        redis_client=app.state.redis,
    )
    app.state.snapshot_manager = MemorySnapshotManager(app.state.memory_manager)
    app.state.permission_enforcer = PermissionEnforcer(trust_graph)
    
    # 4. Initialize Security Firewall
    app.state.firewall = PromptInjectionFirewall(
        event_emitter=app.state.event_emitter,
        semantic_enabled=os.environ.get("ENABLE_SEMANTIC_FIREWALL", "false").lower() == "true",
    )
    
    # 5. Initialize Self-Healing Components
    anomaly_detector = AnomalyDetector(app.state.redis)
    app.state.recovery_manager = RecoveryManager(
        redis_client=app.state.redis,
        trust_graph=trust_graph,
        snapshot_manager=app.state.snapshot_manager,
        event_emitter=app.state.event_emitter,
    )
    app.state.healing_orchestrator = SelfHealingOrchestrator(
        anomaly_detector=anomaly_detector,
        recovery_manager=app.state.recovery_manager,
    )
    
    # 6. Initialize LangGraph Orchestrator
    app.state.orchestrator = SwarmOrchestrator(
        memory_manager=app.state.memory_manager,
        snapshot_manager=app.state.snapshot_manager,
        trust_graph=trust_graph,
        permission_enforcer=app.state.permission_enforcer,
        firewall=app.state.firewall,
        event_emitter=app.state.event_emitter,
    )
    
    # 7. Initialize Attack Simulator
    app.state.simulator = AttackSimulator(
        firewall=app.state.firewall,
        memory_manager=app.state.memory_manager,
        trust_graph=trust_graph,
        event_emitter=app.state.event_emitter,
        redis_client=app.state.redis,
    )
    
    # --- Startup Actions ---
    try:
        # Initialize Neo4j: open driver connection and create schema indexes.
        await trust_graph.initialize()
        logger.info("Neo4j constraints initialized.")
        
        # Register the initial swarm agents to the Trust Graph
        from backend.app.trust.models import AgentIdentity, AgentRole, AgentStatus
        agents_to_register = [
            ("Planner", AgentRole.PLANNER, app.state.orchestrator.planner_agent),
            ("Web", AgentRole.EXECUTOR, app.state.orchestrator.web_agent),
            ("Code", AgentRole.EXECUTOR, app.state.orchestrator.code_agent),
            ("API", AgentRole.EXECUTOR, app.state.orchestrator.api_agent),
            ("Validator", AgentRole.VALIDATOR, app.state.orchestrator.validator_agent),
            ("Sentinel", AgentRole.SENTINEL, app.state.orchestrator.sentinel_agent),
        ]
        
        for name, role, executor in agents_to_register:
            aid = (executor.metadata or {}).get("agent_id")
            if aid:
                identity = AgentIdentity(
                    id=aid,
                    name=f"{name}Agent",
                    role=role,
                    trust_score=1.0,
                    status=AgentStatus.ACTIVE
                )
                await trust_graph.register_agent(identity)
        logger.info("Initial swarm agents registered to Neo4j.")
    except Exception as exc:
        logger.warning("Failed to initialize Neo4j constraints (Neo4j might be down): %s", exc)
        
    # Wire trust graph so the healing loop can fetch agents from Neo4j
    app.state.healing_orchestrator.attach_graph(trust_graph)

    # Start background tasks
    app.state.redis_subscriber_task = asyncio.create_task(
        redis_event_subscriber(app.state.redis, ws_manager)
    )
    app.state.healing_orchestrator.start()
    
    yield  # Application runs here
    
    # --- Shutdown Actions ---
    logger.info("Shutting down AgentOps Security Mesh...")
    app.state.healing_orchestrator.stop()
    if app.state.redis_subscriber_task:
        app.state.redis_subscriber_task.cancel()
        
    await trust_graph.close()
    await app.state.redis.close()

# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AgentOps Security Mesh",
    version="1.0.0",
    description="Security Operating System for AI Agent Swarms",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify React app domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Logging Middleware
class AgentContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        agent_id = request.headers.get("X-Agent-ID", "external-client")
        
        # We could inject agent_id into request state here
        request.state.agent_id = agent_id
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        logger.info(
            "%s %s - %s - %.3fs",
            request.method,
            request.url.path,
            response.status_code,
            process_time
        )
        return response

app.add_middleware(AgentContextMiddleware)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(agents.router)
app.include_router(security.router)
app.include_router(tasks.router)
app.include_router(healing.router)
app.include_router(simulator_routes.router)

# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check(request: Request):
    """Deep health check verifying Redis and Neo4j connectivity."""
    from fastapi.responses import JSONResponse

    status = {"status": "ok", "redis": "unknown", "neo4j": "unknown"}

    # Check Redis
    try:
        await request.app.state.redis.ping()
        status["redis"] = "connected"
    except Exception as exc:
        status["redis"] = f"error: {exc}"
        status["status"] = "degraded"

    # Check Neo4j
    try:
        await request.app.state.trust_graph._execute_read("RETURN 1 AS alive")
        status["neo4j"] = "connected"
    except Exception as exc:
        status["neo4j"] = f"error: {exc}"
        status["status"] = "degraded"

    http_status = 503 if status["status"] != "ok" else 200
    return JSONResponse(content=status, status_code=http_status)

# ---------------------------------------------------------------------------
# Global WebSocket endpoints (Fallback/Alias)
# ---------------------------------------------------------------------------

@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    """
    Global dashboard websocket that receives all security events.
    """
    client_id = str(id(websocket))
    await ws_manager.connect(websocket, client_id)
    try:
        while True:
            # We don't expect messages from the dashboard, but we need to keep the loop alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)
    except Exception as exc:
        logger.error("Dashboard WebSocket error: %s", exc)
        ws_manager.disconnect(client_id)
