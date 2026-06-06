"""
healing.py — SelfHealingOrchestrator for the AgentOps Security Mesh.

Runs continuously alongside the swarm to monitor agent metrics and trigger
automatic recovery via the RecoveryManager when anomalies are detected.
Now actively polls Neo4j for registered agents each tick and generates
synthetic behavioural metrics to drive the anomaly detector.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING, Any

from backend.app.security.anomaly import AgentMetrics, AnomalyDetector
from backend.app.security.recovery import RecoveryManager

if TYPE_CHECKING:
    from backend.app.trust.graph import AsyncNeo4jTrustGraph
    from backend.app.trust.models import AgentIdentity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POLL_INTERVAL_SECONDS: int = 15  # How often we scan agents


# ---------------------------------------------------------------------------
# SelfHealingOrchestrator
# ---------------------------------------------------------------------------


class SelfHealingOrchestrator:
    """
    Background daemon orchestrating continuous self-healing for the swarm.

    Polls Neo4j for all active agents, generates or collects behavioural
    metrics, passes them through the AnomalyDetector, and invokes the
    RecoveryManager when thresholds are exceeded.

    Args:
        anomaly_detector: AnomalyDetector instance.
        recovery_manager: RecoveryManager instance.
        trust_graph:      AsyncNeo4jTrustGraph (optional — set via attach_graph).
    """

    def __init__(
        self,
        anomaly_detector: AnomalyDetector,
        recovery_manager: RecoveryManager,
    ) -> None:
        self._detector = anomaly_detector
        self._recovery = recovery_manager
        self._trust_graph: "AsyncNeo4jTrustGraph | None" = None
        self._task: asyncio.Task | None = None
        self._running: bool = False
        self._last_scores: dict[str, dict[str, Any]] = {}
        self._tick: int = 0

    def attach_graph(self, trust_graph: "AsyncNeo4jTrustGraph") -> None:
        """Wire the trust graph so the loop can fetch live agents."""
        self._trust_graph = trust_graph

    def start(self) -> None:
        """Start the background monitoring task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("SelfHealingOrchestrator background loop started.")

    def stop(self) -> None:
        """Stop the background monitoring task."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("SelfHealingOrchestrator background loop stopped.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_active_agents(self) -> list[dict[str, Any]]:
        """Return active agent records from Neo4j."""
        if self._trust_graph is None:
            return []
        try:
            records = await self._trust_graph._execute_read(
                "MATCH (a:Agent) WHERE a.status <> 'SUSPENDED' "
                "RETURN a.id AS id, a.name AS name, a.role AS role, "
                "a.trust_score AS trust_score, a.status AS status"
            )
            return [dict(r) for r in records]
        except Exception as exc:
            logger.debug("SelfHealing: could not fetch agents from Neo4j: %s", exc)
            return []

    @staticmethod
    def _synthetic_metrics(agent: dict[str, Any], tick: int) -> AgentMetrics:
        """
        Generate plausible agent metrics for each monitoring tick.
        Most ticks produce normal values; occasionally inject a spike to
        exercise anomaly detection and show the self-healing UI working.
        """
        # Roughly 2% chance of an anomalous spike on any given agent/tick
        spike = random.random() < 0.02
        base_tool_rate = random.uniform(0.5, 3.0)
        return AgentMetrics(
            tool_call_rate=base_tool_rate * (random.uniform(6, 10) if spike else 1),
            unique_domains_accessed=random.randint(1, 5) * (4 if spike else 1),
            memory_write_rate=random.uniform(100, 1000),
            api_error_rate=random.uniform(0, 0.3) * (8 if spike else 1),
            prompt_length=random.randint(200, 2000),
        )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        """Continuous polling loop — fetches agents from Neo4j each tick."""
        # Warm-up: wait a bit so Neo4j can finish initialising
        await asyncio.sleep(5)

        while self._running:
            try:
                self._tick += 1
                agents = await self._fetch_active_agents()

                for agent in agents:
                    agent_id = agent.get("id")
                    if not agent_id:
                        continue

                    metrics = self._synthetic_metrics(agent, self._tick)

                    # Update the statistical baseline
                    await self._detector.update_baseline(agent_id, metrics)

                    # Detect anomaly
                    anomaly_result = await self._detector.detect_anomaly(agent_id, metrics)

                    # Store for dashboard reporting
                    self._last_scores[agent_id] = {
                        "name": agent.get("name") or agent_id,
                        "role": agent.get("role") or "unknown",
                        "trust_score": float(agent.get("trust_score") or 1.0),
                        "is_anomalous": anomaly_result.is_anomalous,
                        "anomaly_score": anomaly_result.anomaly_score,
                        "action": anomaly_result.recommended_action,
                        "deviants": anomaly_result.deviant_metrics,
                    }

                    # Trigger recovery for anything PAUSE or above
                    if anomaly_result.recommended_action in ("PAUSE", "SUSPEND", "TERMINATE"):
                        reason = f"Anomaly (z={anomaly_result.max_z_score}): " + ", ".join(
                            anomaly_result.deviant_metrics
                        )
                        logger.warning(
                            "SelfHealing: triggering recovery agent=%s reason=%r",
                            agent_id,
                            reason,
                        )
                        asyncio.create_task(self._recovery.initiate_recovery(agent_id, reason, {}))

            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                logger.error("SelfHealingOrchestrator loop error: %s", exc)

            try:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                break

    # ------------------------------------------------------------------
    # Public API — called by API routes
    # ------------------------------------------------------------------

    async def monitor_swarm(
        self,
        active_agents: dict[str, "AgentIdentity"],
        current_metrics: dict[str, AgentMetrics],
    ) -> None:
        """
        Evaluate health of explicitly-supplied agents (called from graph nodes).

        Args:
            active_agents:   Dict mapping agent_id -> AgentIdentity.
            current_metrics: Dict mapping agent_id -> AgentMetrics.
        """
        for agent_id, identity in active_agents.items():
            metrics = current_metrics.get(agent_id)
            if not metrics:
                continue

            await self._detector.update_baseline(agent_id, metrics)
            anomaly_result = await self._detector.detect_anomaly(agent_id, metrics)

            self._last_scores[agent_id] = {
                "name": identity.name,
                "role": identity.role.value,
                "trust_score": identity.trust_score,
                "is_anomalous": anomaly_result.is_anomalous,
                "anomaly_score": anomaly_result.anomaly_score,
                "action": anomaly_result.recommended_action,
                "deviants": anomaly_result.deviant_metrics,
            }

            if anomaly_result.recommended_action in ("PAUSE", "SUSPEND", "TERMINATE"):
                reason = f"Anomaly (z={anomaly_result.max_z_score}): " + ", ".join(
                    anomaly_result.deviant_metrics
                )
                asyncio.create_task(self._recovery.initiate_recovery(agent_id, reason, {}))

    async def get_healing_status(self) -> dict[str, Any]:
        """Return a consolidated payload for the frontend dashboard."""
        history = await self._recovery.get_recovery_history()

        return {
            "agent_health": self._last_scores,
            "tick": self._tick,
            "recent_recoveries": [
                {
                    "recovery_id": h.recovery_id,
                    "agent_id": h.new_agent_id,
                    "original_id": h.original_agent_id,
                    "reason": h.reason,
                    "success": h.success,
                    "duration_ms": h.duration_ms,
                    "steps": h.steps_completed,
                    "timestamp": h.timestamp.isoformat(),
                }
                for h in history[:10]
            ],
        }
