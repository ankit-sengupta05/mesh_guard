"""
orchestrator.py — SwarmOrchestrator for the AgentOps Security Mesh LangGraph swarm.

Ties together all node functions, agents, and conditional edges into a compiled
StateGraph. Uses MemorySaver for state checkpointing.

Graph structure:
  __start__ → plan_task
  plan_task → execute_step
  execute_step → validate_output
  validate_output → sentinel_check
  sentinel_check → [execute_step | recovery | halt | finalize]
  recovery → [execute_step | halt]
  halt → __end__
  finalize → __end__
"""

from __future__ import annotations

import logging
import uuid
from typing import AsyncIterator

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from backend.app.graph.agents import (
    build_llm,
    create_api_agent,
    create_code_agent,
    create_planner_agent,
    create_sentinel_agent,
    create_validator_agent,
    create_web_agent,
)
from backend.app.graph.edges import (
    route_after_recovery,
    route_after_sentinel,
)
from backend.app.graph.nodes import (
    NodeContext,
    make_execute_step_node,
    make_finalize_node,
    make_plan_task_node,
    make_recovery_node,
    make_sentinel_check_node,
    make_validate_output_node,
)
from backend.app.graph.state import SwarmState, initial_state
from backend.app.api.routes.settings import LLMSettings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper node: next_step_node
# ---------------------------------------------------------------------------


async def next_step_node(state: SwarmState) -> dict:
    """
    Simple pass-through node to increment current_step.
    """
    return {"current_step": state.get("current_step", 0) + 1}


async def halt_node(state: SwarmState) -> dict:
    """
    Terminal node triggered when the graph must be aborted (e.g. CRITICAL threat).
    """
    logger.error("halt_node: Graph execution halted due to unrecoverable condition.")
    return {"error": "Graph execution halted due to security policy or max recoveries."}


# ---------------------------------------------------------------------------
# SwarmOrchestrator
# ---------------------------------------------------------------------------


class SwarmOrchestrator:
    """
    Builds and manages the AgentOps Security Mesh LangGraph workflow.

    Args:
        memory_manager:      AgentMemoryManager instance.
        snapshot_manager:    MemorySnapshotManager instance.
        trust_graph:         AsyncNeo4jTrustGraph instance.
        permission_enforcer: PermissionEnforcer instance.
        firewall:            PromptInjectionFirewall instance.
        event_emitter:       SecurityEventEmitter instance.
    """

    def __init__(
        self,
        memory_manager,
        snapshot_manager,
        trust_graph,
        permission_enforcer,
        firewall,
        event_emitter,
    ) -> None:
        self.memory = memory_manager
        self.snapshots = snapshot_manager
        self.trust = trust_graph
        self.permissions = permission_enforcer
        self.firewall = firewall
        self.emitter = event_emitter

        # Initialize the agents and graph
        self.rebuild_swarm(None)

    def rebuild_swarm(self, llm_settings: LLMSettings | None) -> None:
        """
        Re-initialize the entire agent swarm using the provided LLM settings.
        Useful for hot-swapping between Azure, OpenAI, and local LM Studio models.
        """
        logger.info(
            "Rebuilding swarm with settings: %s",
            llm_settings.provider if llm_settings else "default",
        )

        # 1. Build LLMs
        planner_llm = build_llm(settings=llm_settings, temperature=0.2)
        executor_llm = build_llm(settings=llm_settings, temperature=0.0)
        sentinel_llm = build_llm(settings=llm_settings, temperature=0.0)

        # 2. Build AgentExecutors
        logger.info("Initializing AgentExecutors...")
        self.planner_agent = create_planner_agent(planner_llm, self.memory, self.trust)
        self.web_agent = create_web_agent(executor_llm, self.firewall, self.memory)
        self.code_agent = create_code_agent(executor_llm, self.firewall, self.memory)
        self.api_agent = create_api_agent(executor_llm, self.firewall, self.trust, self.permissions)
        self.validator_agent = create_validator_agent(executor_llm, self.memory)
        self.sentinel_agent = create_sentinel_agent(
            sentinel_llm, self.firewall, self.trust, self.memory, self.emitter
        )

        # 3. Create NodeContext
        self.ctx = NodeContext(
            memory_manager=self.memory,
            snapshot_manager=self.snapshots,
            trust_graph=self.trust,
            permission_enforcer=self.permissions,
            firewall=self.firewall,
            event_emitter=self.emitter,
            planner_executor=self.planner_agent,
            web_executor=self.web_agent,
            code_executor=self.code_agent,
            api_executor=self.api_agent,
            validator_executor=self.validator_agent,
            sentinel_executor=self.sentinel_agent,
        )

        # 4. Compile Graph
        self.app = self._build_graph()

    def _build_graph(self):
        """Construct the StateGraph with all nodes and edges."""
        builder = StateGraph(SwarmState)

        # Add Nodes
        builder.add_node("plan_task", make_plan_task_node(self.ctx))
        builder.add_node("execute_step", make_execute_step_node(self.ctx))
        builder.add_node("validate_output", make_validate_output_node(self.ctx))
        builder.add_node("sentinel_check", make_sentinel_check_node(self.ctx))
        builder.add_node("recovery", make_recovery_node(self.ctx))
        builder.add_node("next_step", next_step_node)
        builder.add_node("finalize", make_finalize_node(self.ctx))
        builder.add_node("halt", halt_node)

        # Build Graph
        # START -> plan_task -> execute_step -> validate_output -> sentinel_check
        builder.add_edge(START, "plan_task")
        builder.add_edge("plan_task", "execute_step")
        builder.add_edge("execute_step", "validate_output")
        builder.add_edge("validate_output", "sentinel_check")

        # After Sentinel Check
        builder.add_conditional_edges(
            "sentinel_check",
            route_after_sentinel,
            {
                "execute_step": "next_step",  # Threat level ok, move to next step logic
                "recovery": "recovery",  # Anomaly detected -> recover
                "halt": "halt",  # CRITICAL threat -> abort
                "__end__": "finalize",  # Finished all steps
            },
        )

        # Next Step Logic -> either loop back to execute_step or finalize
        def _route_next_step(state: SwarmState):
            if state.get("current_step", 0) >= len(state.get("plan", [])):
                return "finalize"
            return "execute_step"

        builder.add_conditional_edges(
            "next_step", _route_next_step, {"execute_step": "execute_step", "finalize": "finalize"}
        )

        # Recovery Logic
        builder.add_conditional_edges(
            "recovery", route_after_recovery, {"execute_step": "execute_step", "halt": "halt"}
        )

        # Terminal edges
        builder.add_edge("finalize", END)
        builder.add_edge("halt", END)

        # Compile with checkpointer for pause/resume and streaming capability
        memory_saver = MemorySaver()
        return builder.compile(checkpointer=memory_saver)

    async def run_task(self, task: str, run_id: str | None = None) -> AsyncIterator[SwarmState]:
        """
        Execute the agent swarm graph asynchronously and yield state updates.

        Args:
            task:   The user request/task string.
            run_id: Optional unique run identifier.

        Yields:
            SwarmState snapshots as each node completes (useful for WebSockets).
        """
        config = {"configurable": {"thread_id": run_id or str(uuid.uuid4())}}
        state = initial_state(task, run_id)

        logger.info("Starting SwarmOrchestrator run for task: %r", task[:50])

        async for chunk in self.app.astream(state, config=config, stream_mode="values"):
            # chunk is the entire merged SwarmState dict
            yield chunk
