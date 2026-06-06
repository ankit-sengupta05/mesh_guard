"""
client.py — MCP Client Manager for the Security Mesh.

Manages connections to the various MCP FastMCP servers. Enforces the
PromptInjectionFirewall and PermissionEnforcer on every tool call.
Implements a basic circuit breaker pattern.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Any

from pydantic import BaseModel

from backend.app.security.events import SecurityEventEmitter
from backend.app.security.firewall import PromptInjectionFirewall
from backend.app.trust.permissions import PermissionEnforcer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ToolResult(BaseModel):
    success: bool
    result: Any
    latency_ms: int
    error: str | None = None


# ---------------------------------------------------------------------------
# MCPClientManager
# ---------------------------------------------------------------------------


class MCPClientManager:
    """
    Manages client connections to MCP servers.
    Wraps tool calls with security layers: Permissions, Firewall, and Logging.
    """

    def __init__(
        self,
        firewall: PromptInjectionFirewall,
        permission_enforcer: PermissionEnforcer,
        event_emitter: SecurityEventEmitter,
    ) -> None:
        self.firewall = firewall
        self.enforcer = permission_enforcer
        self.emitter = event_emitter

        # State
        # In a real MCP setup, we'd hold stdio subprocesses or SSE client connections here
        self.servers: dict[str, Any] = {}

        # Circuit Breaker state: server_tool -> list of failure timestamps
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._circuit_open: set[str] = set()

    async def list_available_tools(self) -> dict[str, list[str]]:
        """List all tools across all servers."""
        # Mocking the discovery protocol
        return {
            "web_tools": ["web_search", "web_fetch", "extract_links", "screenshot_page"],
            "code_tools": ["run_python", "lint_code", "read_file"],
            "security_tools": [
                "scan_content",
                "check_permission",
                "get_agent_trust",
                "report_anomaly",
            ],
        }

    async def call_tool(
        self, server: str, tool: str, params: dict[str, Any], agent_id: str
    ) -> ToolResult:
        """
        Execute an MCP tool with full security wrapping.
        """
        circuit_key = f"{server}::{tool}"

        # 1. Check Circuit Breaker
        if circuit_key in self._circuit_open:
            return ToolResult(
                success=False, result=None, latency_ms=0, error="Circuit Breaker OPEN"
            )

        start_time = time.monotonic()

        try:
            # 2. Permission Check
            # Assume tool names map loosely to resource types
            resource = f"mcp:{server}:{tool}"
            has_permission = await self.enforcer.check_permission(agent_id, resource)
            if not has_permission:
                await self.emitter.emit_threat(
                    agent_id=agent_id,
                    severity="HIGH",
                    details={"action": "tool_call_denied", "tool": tool},
                    source="mcp_client",
                )
                raise PermissionError(f"Agent {agent_id} lacks permission for {resource}")

            # 3. Input Firewall Scan
            params_str = json.dumps(params)
            scan_in = await self.firewall.scan(params_str, agent_id, context=f"tool_input:{tool}")
            if scan_in.blocked:
                raise ValueError(f"Input blocked by firewall: {scan_in.threat_type}")

            # 4. Actual Tool Execution (Mocked RPC)
            logger.info("Executing MCP tool [%s:%s] for agent %s", server, tool, agent_id)
            await asyncio.sleep(0.1)  # Simulating network/execution latency

            # Mocking the actual server responses based on tool name for the demo
            raw_result: Any = {"status": "success", "data": "Mocked tool execution result."}
            if tool == "web_fetch":
                raw_result = {"content": "Normal page text.", "is_safe": True}
            elif tool == "run_python":
                if "plan:" in params.get("code", ""):
                    raise Exception("Container execution failed: Permission denied")

            # 5. Output Firewall Scan
            result_str = json.dumps(raw_result)
            scan_out = await self.firewall.scan(result_str, agent_id, context=f"tool_output:{tool}")

            # Use sanitized output
            final_result = (
                scan_out.sanitized_content
                if scan_out.sanitized_content != result_str
                else raw_result
            )

            latency = int((time.monotonic() - start_time) * 1000)

            # Reset circuit breaker on success
            self._failures[circuit_key].clear()

            return ToolResult(success=True, result=final_result, latency_ms=latency)

        except Exception as exc:
            latency = int((time.monotonic() - start_time) * 1000)
            logger.error("Tool execution failed [%s]: %s", circuit_key, exc)

            # Record failure
            now = time.time()
            self._failures[circuit_key].append(now)

            # Keep only failures in last 60s
            recent_failures = [t for t in self._failures[circuit_key] if now - t < 60.0]
            self._failures[circuit_key] = recent_failures

            # Trip circuit breaker: 3 failures in 60s
            if len(recent_failures) >= 3:
                logger.critical("Tripping circuit breaker for %s", circuit_key)
                self._circuit_open.add(circuit_key)
                await self.emitter.emit_threat(
                    agent_id=agent_id,
                    severity="CRITICAL",
                    details={"action": "circuit_breaker_tripped", "tool": circuit_key},
                    source="mcp_client",
                )

            return ToolResult(success=False, result=None, latency_ms=latency, error=str(exc))
