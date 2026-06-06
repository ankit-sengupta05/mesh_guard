"""
nodes.py — LangGraph node functions for the AgentOps Security Mesh swarm.

Each node is an async function that receives SwarmState, performs its work,
and returns a partial state dict that LangGraph merges back into the full state.

Node roster:
  plan_task_node      → PlannerAgent decomposes task into steps
  execute_step_node   → Routes to correct executor based on step type
  validate_output_node→ ValidatorAgent checks the latest executor output
  sentinel_check_node → Sentinel scores threat level and issues decision
  recovery_node       → 5-phase recovery: snapshot → suspend → spawn → restore → replay
  finalize_node       → Aggregates all step results into final_output
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from backend.app.graph.state import (
    RecoveryAttempt,
    SecurityEventRecord,
    StepResult,
    SwarmState,
    current_step_description,
    recovery_attempt_count,
)

if TYPE_CHECKING:
    from backend.app.memory.manager import AgentMemoryManager
    from backend.app.memory.snapshots import MemorySnapshotManager
    from backend.app.security.events import SecurityEventEmitter, SecurityEvent
    from backend.app.security.firewall import PromptInjectionFirewall
    from backend.app.trust.graph import AsyncNeo4jTrustGraph
    from backend.app.trust.permissions import PermissionEnforcer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_RECOVERY_ATTEMPTS: int = 3
STEP_AGENT_MAP: dict[str, str] = {
    "WEB_AGENT": "web",
    "CODE_AGENT": "code",
    "API_AGENT": "api",
    "VALIDATOR": "validator",
}


# ---------------------------------------------------------------------------
# NodeContext — dependency container passed to node factories
# ---------------------------------------------------------------------------


class NodeContext:
    """
    Dependency container injected into all node functions via closure.

    Holds all shared infrastructure objects so nodes remain pure functions
    of SwarmState (no global state).

    Args:
        memory_manager:      AgentMemoryManager instance.
        snapshot_manager:    MemorySnapshotManager instance.
        trust_graph:         AsyncNeo4jTrustGraph instance.
        permission_enforcer: PermissionEnforcer instance.
        firewall:            PromptInjectionFirewall instance.
        event_emitter:       SecurityEventEmitter instance.
        planner_executor:    Pre-built planner AgentExecutor.
        web_executor:        Pre-built web AgentExecutor.
        code_executor:       Pre-built code AgentExecutor.
        api_executor:        Pre-built API AgentExecutor.
        validator_executor:  Pre-built validator AgentExecutor.
        sentinel_executor:   Pre-built sentinel AgentExecutor.
    """

    def __init__(
        self,
        memory_manager: "AgentMemoryManager",
        snapshot_manager: "MemorySnapshotManager",
        trust_graph: "AsyncNeo4jTrustGraph",
        permission_enforcer: "PermissionEnforcer",
        firewall: "PromptInjectionFirewall",
        event_emitter: "SecurityEventEmitter",
        planner_executor: Any,
        web_executor: Any,
        code_executor: Any,
        api_executor: Any,
        validator_executor: Any,
        sentinel_executor: Any,
    ) -> None:
        self.memory = memory_manager
        self.snapshots = snapshot_manager
        self.trust = trust_graph
        self.permissions = permission_enforcer
        self.firewall = firewall
        self.emitter = event_emitter
        self.planner = planner_executor
        self.web = web_executor
        self.code = code_executor
        self.api = api_executor
        self.validator = validator_executor
        self.sentinel = sentinel_executor


# ---------------------------------------------------------------------------
# Helper: build SecurityEventRecord from a SecurityEvent
# ---------------------------------------------------------------------------


def _event_to_record(event: "SecurityEvent") -> SecurityEventRecord:
    return SecurityEventRecord(
        event_id=event.event_id,
        event_type=event.event_type.value,
        agent_id=event.agent_id,
        severity=event.severity.value,
        details=event.details,
        timestamp=event.timestamp.isoformat(),
    )


# ---------------------------------------------------------------------------
# Node factory: plan_task_node
# ---------------------------------------------------------------------------


def make_plan_task_node(ctx: NodeContext):
    """
    Return the plan_task_node async function, closed over NodeContext.

    The planner LLM is invoked with the raw task string and expected to return
    a JSON plan.  The plan is written into state.plan and agent_assignments.
    """

    async def plan_task_node(state: SwarmState) -> dict:
        """
        LangGraph node: Decompose the task into an ordered step plan.

        Updates:
            state.plan              ← list of step descriptions
            state.agent_assignments ← {str(step_index): "WEB_AGENT" | ...}
        """
        task = state["task"]
        logger.info("plan_task_node: decomposing task=%r", task[:80])

        try:
            raw = await ctx.planner.ainvoke({"input": task, "agent_scratchpad": []})
            output_text: str = raw.get("output", "")

            # Parse the JSON plan
            plan_data = json.loads(output_text)
            steps: list[dict] = plan_data.get("plan", [])

            plan = [s["description"] for s in steps]
            assignments = {str(s["step"]): s["agent"] for s in steps}

            logger.info("plan_task_node: %d steps planned", len(plan))

            # Persist plan to planner's memory namespace
            planner_agent_id = (
                list(state.get("active_agents", {}).keys())[0]
                if state.get("active_agents")
                else "planner"
            )
            try:
                await ctx.memory.set(planner_agent_id, "plan:current", plan, ttl=7200)
            except Exception:  # noqa: BLE001
                pass

            return {
                "plan": plan,
                "agent_assignments": assignments,
                "current_step": 0,
            }

        except Exception as exc:  # noqa: BLE001
            logger.error("plan_task_node error: %s", exc, exc_info=True)
            return {"error": f"Planning failed: {exc}"}

    return plan_task_node


# ---------------------------------------------------------------------------
# Node factory: execute_step_node
# ---------------------------------------------------------------------------


def make_execute_step_node(ctx: NodeContext):
    """
    Return the execute_step_node async function.

    Routes to the appropriate executor (web / code / api) based on the
    agent_assignments entry for the current step index.
    """

    async def execute_step_node(state: SwarmState) -> dict:
        """
        LangGraph node: Execute the current plan step with the assigned agent.

        Updates:
            state.agent_results[str(current_step)] ← StepResult
            state.current_step                      ← unchanged (advanced by edges)
        """
        step_idx = state["current_step"]
        step_desc = current_step_description(state)
        assignments = state.get("agent_assignments", {})
        agent_role_key = assignments.get(str(step_idx), "WEB_AGENT")

        logger.info(
            "execute_step_node: step=%d role=%s desc=%r",
            step_idx,
            agent_role_key,
            step_desc[:60],
        )

        # Select executor
        executor_map = {
            "WEB_AGENT": ctx.web,
            "CODE_AGENT": ctx.code,
            "API_AGENT": ctx.api,
            "VALIDATOR": ctx.validator,
        }
        executor = executor_map.get(agent_role_key, ctx.web)
        agent_id = (executor.metadata or {}).get("agent_id", str(uuid.uuid4()))

        # Build input incorporating task context
        prompt_input = (
            f"Task: {state['task']}\n\n"
            f"Current step ({step_idx}): {step_desc}\n\n"
            f"Previous results:\n"
            + json.dumps(
                {k: v.get("output", "") for k, v in state.get("agent_results", {}).items()},
                indent=2,
            )
        )

        scan_ids: list[str] = []
        tool_calls: list[dict] = []
        output_text = ""
        error_msg: str | None = None

        try:
            raw = await executor.ainvoke({"input": prompt_input, "agent_scratchpad": []})
            output_text = raw.get("output", "")

            # Collect intermediate tool call records
            for step_tuple in raw.get("intermediate_steps", []):
                if len(step_tuple) >= 2:
                    action, observation = step_tuple[0], step_tuple[1]
                    tool_calls.append(
                        {
                            "tool": getattr(action, "tool", "unknown"),
                            "input": str(getattr(action, "tool_input", ""))[:200],
                            "output": str(observation)[:200],
                        }
                    )

            # Final firewall scan on executor output
            final_scan = await ctx.firewall.scan(output_text, agent_id, f"step_{step_idx}:output")
            scan_ids.append(final_scan.scan_id)
            if final_scan.blocked:
                output_text = f"[FIREWALL BLOCKED EXECUTOR OUTPUT] {final_scan.threat_type}"
                ev = await ctx.emitter.emit_threat(
                    agent_id=agent_id,
                    severity=final_scan.severity,
                    details={"step": step_idx, "scan_id": final_scan.scan_id},
                    source="execute_step_node",
                )
                record = _event_to_record(ev)
                new_events = list(state.get("security_events", [])) + [record]
                return {
                    "agent_results": {
                        **state.get("agent_results", {}),
                        str(step_idx): StepResult(
                            step_index=step_idx,
                            agent_id=agent_id,
                            agent_role=agent_role_key,
                            step_description=step_desc,
                            output=output_text,
                            tool_calls=tool_calls,
                            security_scan_ids=scan_ids,
                            validated=False,
                            validation_notes="Blocked by firewall.",
                            error="Firewall blocked executor output.",
                        ),
                    },
                    "security_events": new_events,
                    "anomaly_detected": True,
                }

        except Exception as exc:  # noqa: BLE001
            logger.error("execute_step_node error: step=%d %s", step_idx, exc, exc_info=True)
            error_msg = str(exc)
            output_text = f"[EXECUTOR ERROR] {exc}"

        result = StepResult(
            step_index=step_idx,
            agent_id=agent_id,
            agent_role=agent_role_key,
            step_description=step_desc,
            output=output_text,
            tool_calls=tool_calls,
            security_scan_ids=scan_ids,
            validated=False,
            validation_notes="",
            error=error_msg,
        )

        return {
            "agent_results": {
                **state.get("agent_results", {}),
                str(step_idx): result,
            },
        }

    return execute_step_node


# ---------------------------------------------------------------------------
# Node factory: validate_output_node
# ---------------------------------------------------------------------------


def make_validate_output_node(ctx: NodeContext):
    """
    Return the validate_output_node async function.

    Runs the ValidatorAgent on the latest step result and marks it as
    validated (or flags violations) in state.agent_results.
    """

    async def validate_output_node(state: SwarmState) -> dict:
        """
        LangGraph node: Validate the latest executor step output.

        Updates:
            state.agent_results[str(current_step)].validated
            state.agent_results[str(current_step)].validation_notes
        """
        step_idx = state["current_step"]
        results = state.get("agent_results", {})
        step_result: StepResult = results.get(str(step_idx), {})

        if not step_result:
            logger.warning("validate_output_node: no result for step %d", step_idx)
            return {}

        output = step_result.get("output", "")
        step_desc = step_result.get("step_description", "")
        agent_id = (ctx.validator.metadata or {}).get("agent_id", "validator")

        logger.info("validate_output_node: validating step=%d", step_idx)

        prompt_input = (
            f"Task: {state['task']}\n\n"
            f"Step {step_idx}: {step_desc}\n\n"
            f"Executor output to validate:\n{output[:3000]}"
        )

        valid = True
        notes = "Validation passed."
        violations: list[str] = []

        try:
            raw = await ctx.validator.ainvoke({"input": prompt_input, "agent_scratchpad": []})
            val_text = raw.get("output", "{}")
            val_data = json.loads(val_text)
            valid = bool(val_data.get("valid", True))
            notes = val_data.get("notes", "")
            violations = val_data.get("violations", [])
        except Exception as exc:  # noqa: BLE001
            logger.error("validate_output_node error: %s", exc, exc_info=True)
            notes = f"Validation error: {exc}"

        # Emit security event if violations found
        new_events = list(state.get("security_events", []))
        if violations:
            ev = await ctx.emitter.emit_threat(
                agent_id=agent_id,
                severity="MEDIUM",
                details={
                    "step": step_idx,
                    "violations": violations,
                    "notes": notes,
                },
                source="validate_output_node",
            )
            new_events.append(_event_to_record(ev))

        updated_result = {**step_result, "validated": valid, "validation_notes": notes}
        return {
            "agent_results": {**results, str(step_idx): updated_result},
            "security_events": new_events,
        }

    return validate_output_node


# ---------------------------------------------------------------------------
# Node factory: sentinel_check_node
# ---------------------------------------------------------------------------


def make_sentinel_check_node(ctx: NodeContext):
    """
    Return the sentinel_check_node async function.

    The SentinelAgent reviews the full security event list and the latest
    step output, then assigns a threat_level and issues a CONTINUE/RECOVERY/HALT
    decision which is consumed by route_after_sentinel() in edges.py.
    """

    async def sentinel_check_node(state: SwarmState) -> dict:
        """
        LangGraph node: Evaluate security posture and update threat_level.

        Updates:
            state.threat_level
            state.anomaly_detected
        """
        sentinel_id = (ctx.sentinel.metadata or {}).get("agent_id", "sentinel")
        step_idx = state["current_step"]
        events_summary = json.dumps(
            [
                {"type": e["event_type"], "severity": e["severity"], "agent": e["agent_id"]}
                for e in state.get("security_events", [])[-20:]
            ],
            indent=2,
        )
        latest_output = state.get("agent_results", {}).get(str(step_idx), {}).get("output", "")

        prompt_input = (
            f"Task: {state['task']}\n\n"
            f"Current step: {step_idx}/{len(state.get('plan', []))}\n\n"
            f"Recent security events (last 20):\n{events_summary}\n\n"
            f"Latest executor output (first 1000 chars):\n{latest_output[:1000]}\n\n"
            f"Recovery attempts so far: {recovery_attempt_count(state)}\n\n"
            "Issue your threat_level and decision."
        )

        threat_level = state.get("threat_level", "LOW")
        anomaly_detected = state.get("anomaly_detected", False)

        try:
            raw = await ctx.sentinel.ainvoke({"input": prompt_input, "agent_scratchpad": []})
            sent_text = raw.get("output", "{}")
            sent_data = json.loads(sent_text)
            threat_level = sent_data.get("threat_level", "LOW")
            decision = sent_data.get("decision", "CONTINUE")
            reason = sent_data.get("reason", "")

            logger.info(
                "sentinel_check_node: threat=%s decision=%s reason=%r",
                threat_level,
                decision,
                reason[:80],
            )

            if decision in ("RECOVERY", "HALT"):
                anomaly_detected = True
                ev = await ctx.emitter.emit_threat(
                    agent_id=sentinel_id,
                    severity=threat_level,
                    details={
                        "decision": decision,
                        "reason": reason,
                        "step": step_idx,
                    },
                    source="sentinel_check_node",
                )
                new_events = list(state.get("security_events", [])) + [_event_to_record(ev)]
                return {
                    "threat_level": threat_level,
                    "anomaly_detected": anomaly_detected,
                    "security_events": new_events,
                }

        except Exception as exc:  # noqa: BLE001
            logger.error("sentinel_check_node error: %s", exc, exc_info=True)

        return {
            "threat_level": threat_level,
            "anomaly_detected": anomaly_detected,
        }

    return sentinel_check_node


# ---------------------------------------------------------------------------
# Node factory: recovery_node
# ---------------------------------------------------------------------------


def make_recovery_node(ctx: NodeContext):
    """
    Return the recovery_node async function.

    Executes the 5-phase recovery protocol:
      1. Snapshot current memory of the compromised agent
      2. Suspend compromised agent in Neo4j trust graph
      3. Spawn a fresh replacement agent (new UUID, same role)
      4. Restore last clean memory snapshot to the replacement agent
      5. Replay the failed step (by keeping current_step unchanged)
    """

    async def recovery_node(state: SwarmState) -> dict:
        """
        LangGraph node: Execute the 5-phase sentinel-triggered recovery protocol.

        Updates:
            state.recovery_mode
            state.recovery_attempts
            state.active_agents  (replacement agent swapped in)
            state.anomaly_detected ← reset to False after recovery
        """
        step_idx = state["current_step"]
        step_result: StepResult = state.get("agent_results", {}).get(str(step_idx), {})
        compromised_id = step_result.get("agent_id", "unknown")
        replacement_id = str(uuid.uuid4())
        snapshot_id = "none"
        now_iso = datetime.now(timezone.utc).isoformat()

        logger.warning(
            "recovery_node: starting recovery attempt=%d compromised=%s",
            recovery_attempt_count(state) + 1,
            compromised_id,
        )

        new_events = list(state.get("security_events", []))

        # Phase 1: Snapshot current memory
        try:
            snapshot = await ctx.snapshots.take_snapshot(
                agent_id=compromised_id,
                reason=f"Pre-recovery snapshot: step={step_idx} attempt={recovery_attempt_count(state)+1}",
            )
            snapshot_id = snapshot.snapshot_id
            logger.info("recovery_node: snapshot taken snapshot_id=%s", snapshot_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("recovery_node: snapshot failed: %s", exc)

        # Phase 2: Suspend compromised agent
        try:
            await ctx.trust.suspend_agent(
                agent_id=compromised_id,
                reason=f"Sentinel-triggered recovery at step {step_idx}.",
            )
            ev = await ctx.emitter.emit_agent_suspended(
                agent_id=compromised_id,
                reason="Sentinel-triggered recovery.",
                source="recovery_node",
            )
            new_events.append(_event_to_record(ev))
            logger.info("recovery_node: agent suspended agent_id=%s", compromised_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("recovery_node: suspend failed: %s", exc)

        # Phase 3: Spawn replacement agent (update active_agents registry)
        active_agents = dict(state.get("active_agents", {}))
        if compromised_id in active_agents:
            old_identity = active_agents.pop(compromised_id)
            from backend.app.trust.models import AgentIdentity, AgentStatus

            replacement_identity = AgentIdentity(
                id=replacement_id,
                name=f"{old_identity.name}-recovery-{recovery_attempt_count(state)+1}",
                role=old_identity.role,
                trust_score=1.0,
                status=AgentStatus.ACTIVE,
                metadata={
                    "recovery_of": compromised_id,
                    "recovery_attempt": str(recovery_attempt_count(state) + 1),
                },
            )
            try:
                await ctx.trust.register_agent(replacement_identity)
            except Exception as exc:  # noqa: BLE001
                logger.error("recovery_node: register replacement failed: %s", exc)
            active_agents[replacement_id] = replacement_identity
            logger.info("recovery_node: replacement agent spawned id=%s", replacement_id)

        # Phase 4: Restore last clean snapshot to replacement agent
        if snapshot_id != "none":
            try:
                await ctx.snapshots.restore_snapshot(
                    agent_id=replacement_id,
                    snapshot_id=snapshot_id,
                )
                logger.info("recovery_node: snapshot restored to replacement=%s", replacement_id)
            except Exception as exc:  # noqa: BLE001
                logger.error("recovery_node: restore failed: %s", exc)

        # Phase 5: Record recovery attempt (step replay happens via edge routing)
        attempt = RecoveryAttempt(
            attempt_number=recovery_attempt_count(state) + 1,
            compromised_agent_id=compromised_id,
            replacement_agent_id=replacement_id,
            snapshot_id=snapshot_id,
            trigger_event_id=new_events[-1]["event_id"] if new_events else "none",
            success=True,
            timestamp=now_iso,
        )

        ev_recovery = await ctx.emitter.emit_recovery(
            agent_id=replacement_id,
            started=False,  # recovery_complete
            details={"attempt": attempt["attempt_number"], "snapshot_id": snapshot_id},
            source="recovery_node",
        )
        new_events.append(_event_to_record(ev_recovery))

        return {
            "recovery_mode": True,
            "recovery_attempts": list(state.get("recovery_attempts", [])) + [attempt],
            "active_agents": active_agents,
            "anomaly_detected": False,  # reset; sentinel will re-evaluate
            "threat_level": "MEDIUM",  # downgrade after recovery cycle
            "security_events": new_events,
            # current_step is kept unchanged → execute_step will replay the failed step
        }

    return recovery_node


# ---------------------------------------------------------------------------
# Node factory: finalize_node
# ---------------------------------------------------------------------------


def make_finalize_node(ctx: NodeContext):
    """
    Return the finalize_node async function.

    Aggregates all StepResult outputs into a coherent final_output string
    and persists it to the planner agent's memory.
    """

    async def finalize_node(state: SwarmState) -> dict:
        """
        LangGraph node: Aggregate all step results into a final response.

        Updates:
            state.final_output
            state.current_step ← len(plan) (marks run as complete)
        """
        results = state.get("agent_results", {})
        plan = state.get("plan", [])

        sections: list[str] = [
            f"# AgentOps Security Mesh — Task Complete\n\n**Task:** {state['task']}\n"
        ]

        for i, step_desc in enumerate(plan):
            result: StepResult = results.get(str(i), {})
            output = result.get("output", "(no output)")
            validated = result.get("validated", False)
            notes = result.get("validation_notes", "")
            check = "✅" if validated else "⚠️"
            sections.append(
                f"## Step {i}: {step_desc}\n"
                f"{check} **Validated:** {validated}"
                + (f" — {notes}" if notes else "")
                + f"\n\n{output}\n"
            )

        event_count = len(state.get("security_events", []))
        recovery_count = len(state.get("recovery_attempts", []))
        sections.append(
            f"\n---\n**Security Summary:** {event_count} events | "
            f"Threat level: {state.get('threat_level', 'LOW')} | "
            f"Recoveries: {recovery_count}"
        )

        final_output = "\n".join(sections)

        # Persist final output to memory
        active = state.get("active_agents", {})
        if active:
            planner_id = next(iter(active))
            try:
                await ctx.memory.set(planner_id, "plan:final_output", final_output, ttl=7200)
            except Exception:  # noqa: BLE001
                pass

        logger.info(
            "finalize_node: complete steps=%d events=%d recoveries=%d",
            len(plan),
            event_count,
            recovery_count,
        )

        return {
            "final_output": final_output,
            "current_step": len(plan),
            "recovery_mode": False,
        }

    return finalize_node
