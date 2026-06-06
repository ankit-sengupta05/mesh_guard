"""
websocket.py — WebSocket Manager for the AgentOps Security Mesh API.

Manages active connections and broadcasts security events and task
updates to the frontend React dashboard.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from fastapi import WebSocket

if TYPE_CHECKING:
    from backend.app.security.events import SecurityEvent

logger = logging.getLogger(__name__)

class WebSocketManager:
    """
    Manages active WebSocket connections for the dashboard.
    """

    def __init__(self) -> None:
        # Map of client_id -> WebSocket
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str) -> None:
        """Accept a connection and store it."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info("WebSocket connected: %s", client_id)

    def disconnect(self, client_id: str) -> None:
        """Remove a connection."""
        self.active_connections.pop(client_id, None)
        logger.info("WebSocket disconnected: %s", client_id)

    async def send_personal(self, client_id: str, message: dict) -> None:
        """Send a JSON message to a specific client."""
        ws = self.active_connections.get(client_id)
        if ws:
            try:
                await ws.send_json(message)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to send message to %s: %s", client_id, exc)
                self.disconnect(client_id)

    async def broadcast(self, event: "SecurityEvent") -> None:
        """
        Broadcast a SecurityEvent to ALL connected clients.
        """
        if not self.active_connections:
            return
            
        payload = event.model_dump_json()
        dead_clients = []
        
        for client_id, ws in self.active_connections.items():
            try:
                await ws.send_text(payload)
            except Exception as exc:  # noqa: BLE001
                logger.error("Broadcast failed for %s: %s", client_id, exc)
                dead_clients.append(client_id)
                
        for dead_id in dead_clients:
            self.disconnect(dead_id)

    async def broadcast_raw(self, payload_json: str) -> None:
        """
        Broadcast a raw JSON string to ALL connected clients.
        Useful when forwarding directly from Redis Pub/Sub.
        """
        if not self.active_connections:
            return
            
        dead_clients = []
        
        for client_id, ws in self.active_connections.items():
            try:
                await ws.send_text(payload_json)
            except Exception as exc:  # noqa: BLE001
                logger.error("Raw broadcast failed for %s: %s", client_id, exc)
                dead_clients.append(client_id)
                
        for dead_id in dead_clients:
            self.disconnect(dead_id)

# Global singleton
manager = WebSocketManager()
