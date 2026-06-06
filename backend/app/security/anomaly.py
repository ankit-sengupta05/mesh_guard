"""
anomaly.py — AnomalyDetector for the AgentOps Security Mesh.

Tracks behavioral baselines for agents and flags anomalies using a sliding
5-minute window and z-score thresholds.

Metrics tracked:
  - tool_call_rate (calls/min)
  - unique_domains_accessed
  - memory_write_rate (bytes/min)
  - api_error_rate (errors/min)
  - prompt_length_percentile

Thresholds:
  - Z-score >= 2.5 → WARN
  - Z-score >= 4.0 → PAUSE / SUSPEND
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Literal

import redis.asyncio as aioredis
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

Z_SCORE_WARN: float = 2.5
Z_SCORE_PAUSE: float = 4.0
BASELINE_TTL_SECONDS: int = 24 * 3600  # keep baselines for 24h
WINDOW_SIZE_MINUTES: int = 5


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AgentMetrics(BaseModel):
    """Raw metrics recorded for an agent in a given time window."""

    tool_call_rate: float = Field(default=0.0, description="Tool calls per minute")
    unique_domains_accessed: int = Field(default=0, description="Unique domains accessed")
    memory_write_rate: float = Field(default=0.0, description="Memory bytes written per minute")
    api_error_rate: float = Field(default=0.0, description="API errors per minute")
    prompt_length: int = Field(default=0, description="Length of last prompt in characters")


class AnomalyResult(BaseModel):
    """Output of an anomaly detection check."""

    is_anomalous: bool
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    max_z_score: float = Field(default=0.0)
    deviant_metrics: list[str] = Field(default_factory=list)
    recommended_action: Literal["ALLOW", "WARN", "PAUSE", "SUSPEND", "TERMINATE"]


class _MetricStats(BaseModel):
    """Running statistics for a single metric."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0  # Sum of squares of differences from the current mean (Welford's)

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def update(self, value: float) -> None:
        """Update running statistics using Welford's online algorithm."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2


class AgentBaseline(BaseModel):
    """Running baseline statistics for an agent."""

    agent_id: str
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stats: dict[str, _MetricStats] = Field(
        default_factory=lambda: {
            "tool_call_rate": _MetricStats(),
            "unique_domains_accessed": _MetricStats(),
            "memory_write_rate": _MetricStats(),
            "api_error_rate": _MetricStats(),
            "prompt_length": _MetricStats(),
        }
    )


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """
    Tracks and evaluates agent behavioral metrics.

    Args:
        redis_client: Async Redis client for persisting baselines.
    """

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client

    def _baseline_key(self, agent_id: str) -> str:
        return f"security:anomaly:baseline:{agent_id}"

    async def _get_baseline(self, agent_id: str) -> AgentBaseline:
        """Fetch the current baseline for an agent from Redis."""
        raw = await self._redis.get(self._baseline_key(agent_id))
        if raw:
            try:
                return AgentBaseline.model_validate_json(raw)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to parse baseline for %s: %s", agent_id, exc)
        return AgentBaseline(agent_id=agent_id)

    async def _save_baseline(self, baseline: AgentBaseline) -> None:
        """Save a baseline to Redis."""
        await self._redis.setex(
            self._baseline_key(baseline.agent_id),
            BASELINE_TTL_SECONDS,
            baseline.model_dump_json(),
        )

    async def update_baseline(self, agent_id: str, metrics: AgentMetrics) -> None:
        """
        Update the running baseline statistics for an agent with new metrics.
        """
        baseline = await self._get_baseline(agent_id)

        baseline.stats["tool_call_rate"].update(metrics.tool_call_rate)
        baseline.stats["unique_domains_accessed"].update(metrics.unique_domains_accessed)
        baseline.stats["memory_write_rate"].update(metrics.memory_write_rate)
        baseline.stats["api_error_rate"].update(metrics.api_error_rate)
        baseline.stats["prompt_length"].update(metrics.prompt_length)
        baseline.last_updated = datetime.now(timezone.utc)

        await self._save_baseline(baseline)
        logger.debug("Anomaly baseline updated for agent=%s", agent_id)

    async def detect_anomaly(self, agent_id: str, current_metrics: AgentMetrics) -> AnomalyResult:
        """
        Evaluate current metrics against the baseline to detect anomalies.

        Returns:
            AnomalyResult with z-scores and recommended action.
        """
        baseline = await self._get_baseline(agent_id)
        deviant_metrics: list[str] = []
        max_z = 0.0

        # We only have statistical confidence if count >= 5
        if baseline.stats["tool_call_rate"].count < 5:
            return AnomalyResult(
                is_anomalous=False,
                recommended_action="ALLOW",
            )

        metric_values = {
            "tool_call_rate": current_metrics.tool_call_rate,
            "unique_domains_accessed": current_metrics.unique_domains_accessed,
            "memory_write_rate": current_metrics.memory_write_rate,
            "api_error_rate": current_metrics.api_error_rate,
            "prompt_length": current_metrics.prompt_length,
        }

        for name, current_val in metric_values.items():
            stats = baseline.stats.get(name)
            if not stats or stats.std_dev == 0:
                continue

            # Calculate Z-score
            z_score = (current_val - stats.mean) / stats.std_dev

            # Only care about positive deviations (spikes) for these security metrics
            if z_score > max_z:
                max_z = z_score

            if z_score >= Z_SCORE_WARN:
                deviant_metrics.append(f"{name} (z={z_score:.2f})")

        # Map max Z-score to an action
        action: Literal["ALLOW", "WARN", "PAUSE", "SUSPEND", "TERMINATE"] = "ALLOW"
        is_anomalous = False

        if max_z >= Z_SCORE_PAUSE:
            is_anomalous = True
            action = "PAUSE"
        elif max_z >= Z_SCORE_WARN:
            is_anomalous = True
            action = "WARN"

        # Map Z-score roughly to a 0-1 anomaly score probability
        # CDF of 2.5 is ~0.9938
        score = min(1.0, max(0.0, (max_z - 1.0) / 3.0)) if max_z > 1.0 else 0.0

        result = AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=round(score, 3),
            max_z_score=round(max_z, 2),
            deviant_metrics=deviant_metrics,
            recommended_action=action,
        )

        if is_anomalous:
            logger.warning(
                "Anomaly detected for agent=%s max_z=%.2f action=%s deviants=%s",
                agent_id,
                max_z,
                action,
                deviant_metrics,
            )

        return result
