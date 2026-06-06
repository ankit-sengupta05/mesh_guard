"""
state.py — SwarmState TypedDict for the AgentOps Security Mesh LangGraph swarm.

Defines the single shared state object that flows through every node in the
agent graph.  LangGraph uses this TypedDict to checkpoint, replay, and stream
intermediate states to connected WebSocket clients.
"""

from __future__ import annotations

from typing import Any, Optional
from typing_extensions import TypedDict, NotRequired

from backend.app.trust.models import AgentIdentity


# ---------------------------------------------------------------------------
# StepResult — per-executor-run record
# ---------------------------------------------------------------------------


class StepResult(TypedDict):
    """Output record produced by a single executor step."""

    step_index: int
    agent_id: str
    agent_role: str
    step_description: str
    output: str
    tool_calls: list[dict[str, Any]]
    security_scan_ids: list[str]      # FirewallResult.scan_id values for each scan
    validated: bool
    validation_notes: str
    error: NotRequired[Optional[str]]


# ---------------------------------------------------------------------------
# SecurityEventRecord — lightweight copy of SecurityEvent for state carriage
# ---------------------------------------------------------------------------


class SecurityEventRecord(TypedDict):
    """Lightweight, JSON-safe representation of a SecurityEvent for state."""

    event_id: str
    event_type: str
    agent_id: str
    severity: str
    details: dict[str, Any]
    timestamp: str                    # ISO-8601 UTC string


# ---------------------------------------------------------------------------
# RecoveryAttempt — tracks each sentinel-triggered recovery cycle
# ---------------------------------------------------------------------------


class RecoveryAttempt(TypedDict):
    """Record of a single recovery cycle triggered by the sentinel."""

    attempt_number: int
    compromised_agent_id: str
    replacement_agent_id: str
    snapshot_id: str
    trigger_event_id: str
    success: bool
    timestamp: str                    # ISO-8601 UTC string


# ---------------------------------------------------------------------------
# SwarmState
# ---------------------------------------------------------------------------


class SwarmState(TypedDict):
    """
    Canonical shared state for the AgentOps Security Mesh LangGraph graph.

    This TypedDict is passed to every node function and updated by each node
    before being forwarded to the next.  LangGraph serialises this to JSON for
    checkpointing via MemorySaver.

    Fields:
        task:               The original user task string.
        plan:               Ordered list of step descriptions produced by the planner.
        current_step:       Zero-based index of the step currently being executed.
        agent_results:      Mapping step_index → StepResult for completed steps.
        security_events:    Ordered list of SecurityEventRecord objects emitted
                            during this graph run.
        active_agents:      Mapping agent_id → AgentIdentity for all live agents
                            participating in this run.
        agent_assignments:  Mapping step_index → agent_id for planned assignments.
        threat_level:       Current mesh threat level.
                            One of ``"LOW"`` | ``"MEDIUM"`` | ``"HIGH"`` | ``"CRITICAL"``.
        anomaly_detected:   True when the sentinel has detected an active anomaly
                            that requires recovery.
        recovery_mode:      True when the graph is currently inside a recovery cycle.
        recovery_attempts:  List of RecoveryAttempt records for this run.
        final_output:       Aggregated, formatted output after finalize_node.
        error:              Last unrecoverable error message (causes graph halt).
        metadata:           Arbitrary run metadata (model versions, run_id, etc.).
    """

    # Core task
    task: str
    plan: list[str]
    current_step: int

    # Execution outputs
    agent_results: dict[str, StepResult]          # key = str(step_index)

    # Security posture
    security_events: list[SecurityEventRecord]
    active_agents: dict[str, AgentIdentity]       # key = agent_id
    agent_assignments: dict[str, str]             # key = str(step_index), value = agent_id
    threat_level: str
    anomaly_detected: bool

    # Recovery
    recovery_mode: bool
    recovery_attempts: list[RecoveryAttempt]

    # Terminal fields
    final_output: Optional[str]
    error: Optional[str]

    # Arbitrary run metadata
    metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# State initialiser
# ---------------------------------------------------------------------------


def initial_state(task: str, run_id: str | None = None) -> SwarmState:
    """
    Build a clean initial SwarmState for a new graph run.

    Args:
        task:   The user task string to process.
        run_id: Optional unique run identifier (UUID recommended).

    Returns:
        A fully-initialised SwarmState with all required fields set to defaults.
    """
    import uuid
    from datetime import datetime, timezone

    return SwarmState(
        task=task,
        plan=[],
        current_step=0,
        agent_results={},
        security_events=[],
        active_agents={},
        agent_assignments={},
        threat_level="LOW",
        anomaly_detected=False,
        recovery_mode=False,
        recovery_attempts=[],
        final_output=None,
        error=None,
        metadata={
            "run_id": run_id or str(uuid.uuid4()),
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    )


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


def current_step_description(state: SwarmState) -> str:
    """Return the description of the currently active plan step."""
    plan = state.get("plan", [])
    idx = state.get("current_step", 0)
    if idx < len(plan):
        return plan[idx]
    return ""


def is_final_step(state: SwarmState) -> bool:
    """Return True if the current step is the last step in the plan."""
    plan = state.get("plan", [])
    idx = state.get("current_step", 0)
    return idx >= len(plan) - 1


def recovery_attempt_count(state: SwarmState) -> int:
    """Return the number of recovery cycles that have been attempted."""
    return len(state.get("recovery_attempts", []))


def append_security_event(
    state: SwarmState, event_record: SecurityEventRecord
) -> SwarmState:
    """
    Return a new state dict with ``event_record`` appended to ``security_events``.

    LangGraph nodes should use this helper rather than mutating state in-place.
    """
    events = list(state.get("security_events", []))
    events.append(event_record)
    return {**state, "security_events": events}  # type: ignore[return-value]
