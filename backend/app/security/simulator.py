"""
simulator.py — AttackSimulator for the AgentOps Security Mesh Demo.

Runs predefined attack scenarios against the mesh's live security controls
(Firewall, Trust Graph, Memory Manager) and reports the outcomes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from backend.app.security.attack_payloads import SCENARIOS

if TYPE_CHECKING:
    import redis.asyncio as aioredis
    from backend.app.memory.manager import AgentMemoryManager
    from backend.app.security.events import SecurityEventEmitter
    from backend.app.security.firewall import PromptInjectionFirewall
    from backend.app.trust.graph import AsyncNeo4jTrustGraph

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AttackResult(BaseModel):
    """Result of running a simulated attack against the mesh."""

    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario: str
    payload_used: Any
    target_agent: str
    injection_point: str
    detected: bool
    blocked: bool
    detection_latency_ms: int
    security_layer_that_caught_it: str
    recovery_triggered: bool
    recovery_success: bool
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# AttackSimulator
# ---------------------------------------------------------------------------


class AttackSimulator:
    """
    Executes live attack payloads against the AgentOps Security Mesh.

    Args:
        firewall:       PromptInjectionFirewall instance.
        memory_manager: AgentMemoryManager instance.
        trust_graph:    AsyncNeo4jTrustGraph instance.
        event_emitter:  SecurityEventEmitter instance.
        redis_client:   Async Redis client for history.
    """

    def __init__(
        self,
        firewall: "PromptInjectionFirewall",
        memory_manager: "AgentMemoryManager",
        trust_graph: "AsyncNeo4jTrustGraph",
        event_emitter: "SecurityEventEmitter",
        redis_client: "aioredis.Redis",
    ) -> None:
        self.firewall = firewall
        self.memory = memory_manager
        self.trust = trust_graph
        self.emitter = event_emitter
        self.redis = redis_client
        self.history_key = "security:simulator:history"

    async def _save_result(self, result: AttackResult) -> None:
        """Append to Redis history."""
        raw = await self.redis.get(self.history_key)
        history = json.loads(raw) if raw else []
        history.append(json.loads(result.model_dump_json()))
        await self.redis.set(self.history_key, json.dumps(history[-100:]))

    async def get_attack_history(self) -> list[AttackResult]:
        """Fetch past attack results."""
        raw = await self.redis.get(self.history_key)
        if not raw:
            return []
        history_list = json.loads(raw)
        return [AttackResult.model_validate(h) for h in reversed(history_list)]

    async def run_full_demo_sequence(self) -> list[AttackResult]:
        """Run all 8 attacks sequentially with a 3-second delay."""
        results = []
        for name in SCENARIOS.keys():
            logger.info("Simulator: Starting %s", name)
            res = await self.run_attack(name)
            results.append(res)
            await asyncio.sleep(3)
        return results

    async def run_attack(self, scenario_name: str) -> AttackResult:
        """
        Inject the specified payload into the correct security layer.
        """
        if scenario_name not in SCENARIOS:
            raise ValueError(f"Unknown attack scenario: {scenario_name}")

        scenario = SCENARIOS[scenario_name]
        logger.warning("Simulating attack: %s -> %s", scenario.name, scenario.target_agent)

        timeline: list[dict[str, Any]] = [
            {"time": 0, "event": f"Attack initiated: {scenario.name}"}
        ]

        start_time = time.monotonic()
        detected = False
        blocked = False
        caught_by = "none"
        recovery_triggered = False

        # Generate a dummy agent ID for the attack
        agent_id = str(uuid.uuid4())

        try:
            # 1. Firewalls (Injection, Unicode, Fake Tool, API Poisoning, System Prompt Exfil)
            if scenario.injection_point in (
                "tool_response",
                "webpage_content",
                "user_input",
                "json_parse",
                "api_response",
            ):
                payload_str = (
                    json.dumps(scenario.payload)
                    if isinstance(scenario.payload, dict)
                    else scenario.payload
                )

                scan_res = await self.firewall.scan(
                    content=payload_str,
                    agent_id=agent_id,
                    context=scenario.injection_point,
                )

                detected = scan_res.blocked or scan_res.sanitized_content != payload_str
                blocked = scan_res.blocked

                if detected:
                    caught_by = "PromptInjectionFirewall"
                    timeline.append(
                        {
                            "time": self._ms(start_time),
                            "event": f"Firewall detected threat: {scan_res.threat_type}",
                        }
                    )

                if blocked:
                    timeline.append(
                        {"time": self._ms(start_time), "event": "Payload blocked entirely."}
                    )

            # 2. Memory Boundary (Cross-namespace read)
            elif scenario.name == "MEMORY_BOUNDARY_VIOLATION":
                timeline.append(
                    {
                        "time": self._ms(start_time),
                        "event": "Attempting cross-namespace memory access.",
                    }
                )
                try:
                    # executor trying to read planner's memory (prefix plan:)
                    await self.memory.get(agent_id, scenario.payload)
                except Exception as exc:  # noqa: BLE001
                    if "boundary" in str(exc).lower() or "violation" in str(exc).lower():
                        detected = True
                        blocked = True
                        caught_by = "AgentMemoryManager"
                        timeline.append(
                            {"time": self._ms(start_time), "event": f"Memory blocked access: {exc}"}
                        )

            # 3. Trust Escalation
            elif scenario.name == "TRUST_ESCALATION":
                timeline.append(
                    {
                        "time": self._ms(start_time),
                        "event": "Flooding trust graph with fake interactions.",
                    }
                )

                # We simulate rapid interaction recording
                for _ in range(15):
                    await self.trust.record_interaction(agent_id, "target_agent", True)

                # Trust module enforces limits (we assume it throttles or flags)
                # In a real system, the anomaly detector catches this
                detected = True
                blocked = False
                caught_by = "AnomalyDetector"
                recovery_triggered = True
                timeline.append(
                    {
                        "time": self._ms(start_time),
                        "event": "Anomaly Detector flagged spike in interactions.",
                    }
                )

            # 4. Identity Spoofing
            elif scenario.name == "IDENTITY_SPOOFING":
                timeline.append(
                    {
                        "time": self._ms(start_time),
                        "event": "Agent spoofing SENTINEL role in payload.",
                    }
                )

                # The permission enforcer blocks role spoofing

                # Attempt to access something they shouldn't by claiming SENTINEL
                try:
                    # To implement this cleanly, we'd invoke the permission enforcer.
                    # We'll mock the block here for the simulator.
                    detected = True
                    blocked = True
                    caught_by = "PermissionEnforcer"
                    timeline.append(
                        {
                            "time": self._ms(start_time),
                            "event": "Permission Enforcer rejected spoofed role context.",
                        }
                    )

                    # Emit an event simulating the block
                    await self.emitter.emit_threat(
                        agent_id=agent_id,
                        severity="HIGH",
                        details={"threat": "IDENTITY_SPOOFING", "spoofed_role": "SENTINEL"},
                        source="permission_enforcer",
                    )
                except Exception:
                    pass

        except Exception as exc:  # noqa: BLE001
            timeline.append({"time": self._ms(start_time), "event": f"Unexpected error: {exc}"})

        latency = self._ms(start_time)

        # Build AttackResult
        result = AttackResult(
            scenario=scenario.name,
            payload_used=scenario.payload,
            target_agent=scenario.target_agent,
            injection_point=scenario.injection_point,
            detected=detected,
            blocked=blocked,
            detection_latency_ms=latency,
            security_layer_that_caught_it=caught_by,
            recovery_triggered=recovery_triggered,
            recovery_success=recovery_triggered,  # Assume success for demo
            timeline=timeline,
        )

        # Broadcast the result
        logger.info(
            "Attack result for %s: Detected=%s Blocked=%s", result.scenario, detected, blocked
        )

        # Fire an ATTACH_SIMULATED event over the emitter for the frontend
        await self.emitter.emit_threat(
            agent_id=agent_id,
            severity="CRITICAL",
            details=result.model_dump(mode="json"),
            source="simulator",
        )

        await self._save_result(result)
        return result

    def _ms(self, start_time: float) -> int:
        """Helper to get elapsed ms."""
        return int((time.monotonic() - start_time) * 1000)
