"""
edges.py — Conditional edge functions for the AgentOps Security Mesh LangGraph swarm.

These functions route execution between nodes based on SwarmState.
LangGraph uses the returned string to determine the next node to execute.

Routing logic:
  route_after_sentinel   → [execute_step | recovery | halt]
  route_after_validation → [sentinel_check | next_step | finalize]
  route_after_recovery   → [execute_step | halt]
"""

from __future__ import annotations

import logging
from typing import Literal

from backend.app.graph.state import (
    SwarmState,
    is_final_step,
    recovery_attempt_count,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_RECOVERY_ATTEMPTS: int = 3


# ---------------------------------------------------------------------------
# Edge: route_after_sentinel
# ---------------------------------------------------------------------------


def route_after_sentinel(
    state: SwarmState,
) -> Literal["execute_step", "recovery", "halt", "__end__"]:
    """
    Decide the next action after the sentinel has evaluated the security posture.

    Logic:
    1. If threat_level == CRITICAL → halt (unrecoverable).
    2. If anomaly_detected == True → enter recovery phase.
    3. If current_step is past the plan length → end.
    4. Otherwise → proceed to execute the current step.

    Returns:
        Next node name.
    """
    threat = state.get("threat_level", "LOW")
    anomaly = state.get("anomaly_detected", False)

    logger.debug(
        "route_after_sentinel: threat=%s anomaly=%s step=%d",
        threat,
        anomaly,
        state.get("current_step", 0),
    )

    if threat == "CRITICAL":
        logger.warning("route_after_sentinel: CRITICAL threat detected. Halting graph.")
        return "halt"

    if anomaly:
        logger.info("route_after_sentinel: Anomaly detected. Routing to recovery.")
        return "recovery"

    # If the step is complete and we are past the end of the plan
    if state.get("current_step", 0) >= len(state.get("plan", [])):
        return "__end__"

    return "execute_step"


# ---------------------------------------------------------------------------
# Edge: route_after_validation
# ---------------------------------------------------------------------------


def route_after_validation(
    state: SwarmState,
) -> Literal["sentinel_check", "next_step", "finalize"]:
    """
    Decide the next action after an executor output has been validated.

    Note: We currently route *every* validated step to the sentinel for review
    before advancing the step index. The sentinel will check the validation
    violations and overall posture.

    Returns:
        "sentinel_check"
    """
    step_idx = state.get("current_step", 0)
    result = state.get("agent_results", {}).get(str(step_idx), {})

    logger.debug(
        "route_after_validation: step=%d validated=%s",
        step_idx,
        result.get("validated", False) if isinstance(result, dict) else False,
    )

    # In a fully-meshed architecture, the sentinel evaluates *after* validation
    # to catch policy violations identified by the validator.
    return "sentinel_check"


# ---------------------------------------------------------------------------
# Edge: advance_step (helper edge)
# ---------------------------------------------------------------------------


def advance_step(
    state: SwarmState,
) -> Literal["execute_step", "finalize"]:
    """
    Used after sentinel_check (if continue) to actually advance the step counter.
    However, LangGraph conditional edges don't easily allow mutating state *and*
    routing in the edge function itself.

    In our architecture, we increment `current_step` inside a dedicated
    pass-through node or update it at the end of `validate_output_node`.
    For simplicity, let's assume `sentinel_check_node` or a `next_step` node
    handles the increment, and this edge decides if we are done.

    Actually, let's keep the logic pure:
    If this is the final step, go to finalize.
    Else, go to execute_step.
    """
    if is_final_step(state):
        return "finalize"
    return "execute_step"


# ---------------------------------------------------------------------------
# Edge: route_after_recovery
# ---------------------------------------------------------------------------


def route_after_recovery(
    state: SwarmState,
) -> Literal["execute_step", "halt"]:
    """
    Decide what to do after a recovery cycle completes.

    Logic:
    1. If recovery_attempts > MAX_RECOVERY_ATTEMPTS → halt (too many failures).
    2. Otherwise → replay the failed step by routing back to execute_step.

    Returns:
        Next node name.
    """
    attempts = recovery_attempt_count(state)

    logger.debug("route_after_recovery: attempt=%d", attempts)

    if attempts > MAX_RECOVERY_ATTEMPTS:
        logger.error(
            "route_after_recovery: Exceeded max recovery attempts (%d > %d). Halting.",
            attempts,
            MAX_RECOVERY_ATTEMPTS,
        )
        return "halt"

    # Go back to executing the current step with the new replacement agent
    return "execute_step"
