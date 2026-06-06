"""
scoring.py — TrustScorer for the AgentOps Security Mesh.

Calculates composite trust scores for agents based on:
  - Interaction history (volume signals healthy engagement)
  - Anomaly rate on outbound edges
  - Agent age (newer agents start with less earned trust)
  - Permission violations (tracked by PermissionEnforcer)

Also provides a scheduled decay task that reduces scores for idle agents
at a configurable rate (default: 0.01 per hour).
"""

from __future__ import annotations

import asyncio
import logging
import math
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final

from backend.app.trust.models import AgentStatus

if TYPE_CHECKING:
    from backend.app.trust.graph import AsyncNeo4jTrustGraph
    from backend.app.trust.permissions import PermissionEnforcer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Trust threshold constants
# ---------------------------------------------------------------------------

TRUST_THRESHOLDS: Final[dict[str, float]] = {
    "SUSPEND": 0.2,  # Below this → automatic suspension candidate
    "WARN": 0.4,  # Below this → emit warning, restrict optional resources
    "HEALTHY": 0.7,  # Above this → fully trusted
}

# ---------------------------------------------------------------------------
# Scoring weight constants
# ---------------------------------------------------------------------------

#: Weight applied to the normalised interaction-volume component.
W_INTERACTION_VOLUME: Final[float] = 0.25

#: Weight applied to the anomaly-rate penalty component.
W_ANOMALY_RATE: Final[float] = 0.35

#: Weight applied to the agent-age component (saturates after ~7 days).
W_AGENT_AGE: Final[float] = 0.15

#: Weight applied to the permission-violation penalty.
W_PERMISSION_VIOLATIONS: Final[float] = 0.25

#: Score decrement applied per permission violation (diminishing returns via log).
VIOLATION_PENALTY_BASE: Final[float] = 0.05

#: Decay amount subtracted per hour from inactive agents.
DECAY_RATE_PER_HOUR: Final[float] = 0.01

#: Interaction count at which the volume component reaches 95 % saturation.
INTERACTION_SATURATION: Final[float] = 200.0

#: Age in seconds at which the age component reaches 95 % saturation (~7 days).
AGE_SATURATION_SECONDS: Final[float] = 7 * 24 * 3600.0

#: Interval between automatic decay ticks when run as a background task.
DECAY_INTERVAL_SECONDS: Final[float] = 3600.0  # 1 hour


# ---------------------------------------------------------------------------
# TrustScorer
# ---------------------------------------------------------------------------


class TrustScorer:
    """
    Computes and maintains normalised trust scores for agents in the mesh.

    The composite score is assembled from four independent sub-scores, each
    weighted so they sum to 1.0:

    ┌─────────────────────────────────────────────────────────────────────┐
    │ Component              Weight  Direction  Description                │
    ├─────────────────────────────────────────────────────────────────────┤
    │ interaction_volume      0.25   positive   More interactions → higher │
    │ anomaly_rate            0.35   negative   More anomalies   → lower   │
    │ agent_age               0.15   positive   Older agents     → higher  │
    │ permission_violations   0.25   negative   More violations  → lower   │
    └─────────────────────────────────────────────────────────────────────┘

    Args:
        graph:    Initialised AsyncNeo4jTrustGraph for reading agent data.
        enforcer: PermissionEnforcer for reading violation counts.

    Usage::

        scorer = TrustScorer(graph=trust_graph, enforcer=permission_enforcer)

        # One-shot score calculation + Neo4j update
        new_score = await scorer.calculate_score("agent-uuid")

        # Background decay loop (typically started via asyncio.create_task)
        await scorer.decay_scores()
    """

    def __init__(
        self,
        graph: "AsyncNeo4jTrustGraph",
        enforcer: "PermissionEnforcer",
    ) -> None:
        self._graph = graph
        self._enforcer = enforcer
        self._decay_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Sub-score helpers (all return floats in [0.0, 1.0])
    # ------------------------------------------------------------------

    @staticmethod
    def _interaction_volume_score(total_interactions: int) -> float:
        """
        Sigmoid-style score based on total outbound interaction count.

        Saturates at ~1.0 as interaction_count approaches INTERACTION_SATURATION.

        Args:
            total_interactions: Sum of interaction_count across outbound edges.

        Returns:
            Sub-score in [0.0, 1.0].
        """
        if total_interactions <= 0:
            return 0.0
        # 1 - e^(-k*x) where k is chosen so f(SATURATION) ≈ 0.95
        k = -math.log(0.05) / INTERACTION_SATURATION
        return 1.0 - math.exp(-k * total_interactions)

    @staticmethod
    def _anomaly_rate_score(anomaly_rate: float) -> float:
        """
        Penalty score based on the fraction of anomalous interactions.

        Args:
            anomaly_rate: Value in [0.0, 1.0].

        Returns:
            Sub-score in [0.0, 1.0] (higher is better; 0 anomalies → 1.0).
        """
        return max(0.0, 1.0 - anomaly_rate)

    @staticmethod
    def _agent_age_score(created_at: datetime) -> float:
        """
        Score based on how long the agent has been registered.

        New agents have lower inherent trust; trust grows with time and saturates
        after approximately 7 days.

        Args:
            created_at: UTC registration timestamp.

        Returns:
            Sub-score in [0.0, 1.0].
        """
        now = datetime.now(timezone.utc)
        age_seconds = max(0.0, (now - created_at).total_seconds())
        k = -math.log(0.05) / AGE_SATURATION_SECONDS
        return 1.0 - math.exp(-k * age_seconds)

    @staticmethod
    def _violation_penalty_score(violation_count: int) -> float:
        """
        Penalty based on the number of permission violations.

        Uses logarithmic scaling so early violations hurt more than later ones.

        Args:
            violation_count: Non-negative integer.

        Returns:
            Sub-score in [0.0, 1.0] (higher is better; 0 violations → 1.0).
        """
        if violation_count <= 0:
            return 1.0
        # penalty grows logarithmically and is capped at 1.0
        penalty = VIOLATION_PENALTY_BASE * math.log1p(violation_count)
        return max(0.0, 1.0 - penalty)

    # ------------------------------------------------------------------
    # Composite score
    # ------------------------------------------------------------------

    async def calculate_score(self, agent_id: str) -> float:
        """
        Compute the composite trust score for an agent and persist it to Neo4j.

        Steps:
        1. Fetch agent identity and current graph state.
        2. Compute each sub-score component.
        3. Apply weights to produce a composite in [0.0, 1.0].
        4. Push the delta (composite − current_score) back to Neo4j via
           `update_trust_score`.
        5. Trigger automatic suspension if score drops below SUSPEND threshold.

        Args:
            agent_id: UUID of the target agent.

        Returns:
            The new composite trust score in [0.0, 1.0].

        Raises:
            KeyError:   If the agent does not exist.
            Neo4jError: On database read/write failure.
        """
        # 1. Fetch current agent identity
        agent = await self._graph.get_agent(agent_id)

        # 2. Gather edge statistics from the full graph snapshot
        snapshot = await self._graph.get_full_graph()
        outbound_edges = [e for e in snapshot.edges if e.from_agent_id == agent_id]

        total_interactions: int = sum(e.interaction_count for e in outbound_edges)
        total_anomalies: int = sum(e.anomaly_count for e in outbound_edges)
        anomaly_rate: float = total_anomalies / total_interactions if total_interactions else 0.0

        # 3. Compute sub-scores
        vol_score = self._interaction_volume_score(total_interactions)
        anom_score = self._anomaly_rate_score(anomaly_rate)
        age_score = self._agent_age_score(agent.created_at)
        viol_score = self._violation_penalty_score(self._enforcer.violation_count(agent_id))

        # 4. Weighted composite
        composite = (
            W_INTERACTION_VOLUME * vol_score
            + W_ANOMALY_RATE * anom_score
            + W_AGENT_AGE * age_score
            + W_PERMISSION_VIOLATIONS * viol_score
        )
        composite = round(max(0.0, min(1.0, composite)), 4)

        logger.debug(
            "Trust score components: agent=%s vol=%.3f anom=%.3f age=%.3f viol=%.3f → composite=%.4f",
            agent_id,
            vol_score,
            anom_score,
            age_score,
            viol_score,
            composite,
        )

        # 5. Persist delta to Neo4j
        delta = composite - agent.trust_score
        if abs(delta) > 1e-6:  # avoid no-op writes
            await self._graph.update_trust_score(
                agent_id=agent_id,
                delta=delta,
                reason="Periodic trust score recalculation.",
            )

        # 6. Auto-suspend below threshold
        if composite < TRUST_THRESHOLDS["SUSPEND"] and agent.status == AgentStatus.ACTIVE:
            logger.warning(
                "Agent %s score %.4f below SUSPEND threshold %.2f — suspending.",
                agent_id,
                composite,
                TRUST_THRESHOLDS["SUSPEND"],
            )
            await self._graph.suspend_agent(
                agent_id=agent_id,
                reason=(
                    f"Trust score {composite:.4f} fell below automatic "
                    f"suspension threshold {TRUST_THRESHOLDS['SUSPEND']}."
                ),
            )

        return composite

    def classify_score(self, score: float) -> str:
        """
        Return a human-readable classification for a trust score.

        Args:
            score: Normalised trust score in [0.0, 1.0].

        Returns:
            One of ``"CRITICAL"``, ``"WARN"``, ``"HEALTHY"``, or ``"OPTIMAL"``.
        """
        if score < TRUST_THRESHOLDS["SUSPEND"]:
            return "CRITICAL"
        if score < TRUST_THRESHOLDS["WARN"]:
            return "WARN"
        if score < TRUST_THRESHOLDS["HEALTHY"]:
            return "HEALTHY"
        return "OPTIMAL"

    # ------------------------------------------------------------------
    # Scheduled decay
    # ------------------------------------------------------------------

    async def decay_scores(self) -> int:
        """
        Apply DECAY_RATE_PER_HOUR trust decay to all inactive agents via Neo4j.

        This method delegates the actual Cypher UPDATE to
        ``AsyncNeo4jTrustGraph.decay_inactive_scores()``, which handles the
        database-level clamping.

        Call this method periodically (e.g., every hour) or start it as a
        long-running background loop via :meth:`start_decay_loop`.

        Returns:
            Number of agents whose scores were decremented.
        """
        count = await self._graph.decay_inactive_scores()
        logger.info("decay_scores tick: %d agents decayed by %.2f.", count, DECAY_RATE_PER_HOUR)
        return count

    async def start_decay_loop(self) -> None:
        """
        Run :meth:`decay_scores` on a recurring schedule (every DECAY_INTERVAL_SECONDS).

        Designed to be launched as a background ``asyncio.Task``::

            asyncio.create_task(scorer.start_decay_loop())

        The loop runs until cancelled. Cancellation is handled gracefully.
        """
        logger.info(
            "Trust decay loop started (interval=%.0fs, rate=%.3f/hr).",
            DECAY_INTERVAL_SECONDS,
            DECAY_RATE_PER_HOUR,
        )
        while True:
            try:
                await asyncio.sleep(DECAY_INTERVAL_SECONDS)
                await self.decay_scores()
            except asyncio.CancelledError:
                logger.info("Trust decay loop cancelled.")
                break
            except Exception as exc:  # noqa: BLE001
                # Log but do not crash the loop on transient errors
                logger.error("Trust decay loop error: %s", exc, exc_info=True)

    def start_background_decay(self) -> asyncio.Task:
        """
        Convenience helper — creates and stores the decay background task.

        Returns:
            The running asyncio.Task. Cancel it to stop the loop.
        """
        self._decay_task = asyncio.create_task(
            self.start_decay_loop(),
            name="trust_score_decay",
        )
        return self._decay_task

    def stop_background_decay(self) -> None:
        """Cancel the background decay task if it is running."""
        if self._decay_task and not self._decay_task.done():
            self._decay_task.cancel()
            logger.info("Trust decay background task cancelled.")

    # ------------------------------------------------------------------
    # Batch operations
    # ------------------------------------------------------------------

    async def recalculate_all_scores(self) -> dict[str, float]:
        """
        Recalculate composite trust scores for every agent in the graph.

        Useful on startup or after bulk permission changes.

        Returns:
            Mapping of agent_id → new_score for all processed agents.
        """
        snapshot = await self._graph.get_full_graph()
        results: dict[str, float] = {}

        for agent in snapshot.nodes:
            try:
                new_score = await self.calculate_score(agent.id)
                results[agent.id] = new_score
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to recalculate score for agent %s: %s",
                    agent.id,
                    exc,
                    exc_info=True,
                )

        logger.info("Bulk score recalculation complete: %d agents processed.", len(results))
        return results

    async def score_report(self, agent_id: str) -> dict:
        """
        Return a detailed score breakdown for an agent (useful for API/debug endpoints).

        Args:
            agent_id: Target agent UUID.

        Returns:
            Dict with ``score``, ``classification``, ``components``, and ``thresholds``.
        """
        agent = await self._graph.get_agent(agent_id)
        snapshot = await self._graph.get_full_graph()
        outbound_edges = [e for e in snapshot.edges if e.from_agent_id == agent_id]

        total_interactions = sum(e.interaction_count for e in outbound_edges)
        total_anomalies = sum(e.anomaly_count for e in outbound_edges)
        anomaly_rate = total_anomalies / total_interactions if total_interactions else 0.0
        violations = self._enforcer.violation_count(agent_id)

        vol_score = self._interaction_volume_score(total_interactions)
        anom_score = self._anomaly_rate_score(anomaly_rate)
        age_score = self._agent_age_score(agent.created_at)
        viol_score = self._violation_penalty_score(violations)

        composite = round(
            W_INTERACTION_VOLUME * vol_score
            + W_ANOMALY_RATE * anom_score
            + W_AGENT_AGE * age_score
            + W_PERMISSION_VIOLATIONS * viol_score,
            4,
        )

        return {
            "agent_id": agent_id,
            "agent_name": agent.name,
            "score": composite,
            "classification": self.classify_score(composite),
            "components": {
                "interaction_volume": {
                    "raw": total_interactions,
                    "sub_score": round(vol_score, 4),
                    "weight": W_INTERACTION_VOLUME,
                    "weighted": round(W_INTERACTION_VOLUME * vol_score, 4),
                },
                "anomaly_rate": {
                    "raw": round(anomaly_rate, 4),
                    "sub_score": round(anom_score, 4),
                    "weight": W_ANOMALY_RATE,
                    "weighted": round(W_ANOMALY_RATE * anom_score, 4),
                },
                "agent_age_seconds": {
                    "raw": round(
                        (datetime.now(timezone.utc) - agent.created_at).total_seconds(), 1
                    ),
                    "sub_score": round(age_score, 4),
                    "weight": W_AGENT_AGE,
                    "weighted": round(W_AGENT_AGE * age_score, 4),
                },
                "permission_violations": {
                    "raw": violations,
                    "sub_score": round(viol_score, 4),
                    "weight": W_PERMISSION_VIOLATIONS,
                    "weighted": round(W_PERMISSION_VIOLATIONS * viol_score, 4),
                },
            },
            "thresholds": TRUST_THRESHOLDS,
        }
