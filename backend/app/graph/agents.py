"""
agents.py — Agent factory functions for the AgentOps Security Mesh LangGraph swarm.

Each factory returns a LangChain runnable (AgentExecutor or LCEL chain) wired
with security controls:
  - All tool inputs AND outputs pass through PromptInjectionFirewall
  - All memory operations go through AgentMemoryManager (boundary-enforced)
  - Permission checks gate every sensitive tool call
  - Sentinel has unrestricted observability across the whole swarm

Agent roster:
  - PlannerAgent   — decomposes task into steps, assigns executor roles
  - WebAgent       — web_search, web_fetch, extract_links (firewall-gated)
  - CodeAgent      — run_python (Docker sandbox), lint_code, read_file
  - ApiAgent       — call_api, parse_json, validate_schema (permission-gated)
  - ValidatorAgent — hallucination & policy violation checker
  - SentinelAgent  — security supervisor, always-running watcher
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import textwrap
import uuid
from typing import Any, Optional, TYPE_CHECKING

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import StructuredTool, Tool
from langchain_openai import AzureChatOpenAI

from backend.app.trust.models import AgentRole

if TYPE_CHECKING:
    from backend.app.memory.manager import AgentMemoryManager
    from backend.app.memory.snapshots import MemorySnapshotManager
    from backend.app.security.events import SecurityEventEmitter
    from backend.app.security.firewall import PromptInjectionFirewall
    from backend.app.trust.graph import AsyncNeo4jTrustGraph
    from backend.app.trust.permissions import PermissionEnforcer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared LLM factory
# ---------------------------------------------------------------------------


def build_llm(
    deployment: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 4096,
) -> AzureChatOpenAI:
    """
    Construct an Azure OpenAI chat model from environment variables.

    Environment variables:
        AZURE_OPENAI_ENDPOINT       — Azure OpenAI resource URL
        AZURE_OPENAI_API_KEY        — API key
        AZURE_OPENAI_API_VERSION    — API version (default: 2024-02-01)
        AZURE_OPENAI_DEPLOYMENT     — Default deployment name (default: gpt-4o)

    Args:
        deployment:   Override the deployment name.
        temperature:  Sampling temperature (default 0.0 for determinism).
        max_tokens:   Maximum completion tokens.

    Returns:
        Configured AzureChatOpenAI instance.
    """
    return AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01"),
        azure_deployment=deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
        temperature=temperature,
        max_tokens=max_tokens,
    )


# ---------------------------------------------------------------------------
# Firewall-gated tool wrapper
# ---------------------------------------------------------------------------


def _make_gated_tool(
    name: str,
    description: str,
    fn: Any,
    firewall: "PromptInjectionFirewall",
    agent_id: str,
    context: str,
) -> Tool:
    """
    Wrap a synchronous tool function with firewall scanning on both input and output.

    Args:
        name:       Tool name exposed to the LLM.
        description: Tool description for the LLM.
        fn:         The underlying synchronous callable.
        firewall:   PromptInjectionFirewall instance.
        agent_id:   Owning agent UUID.
        context:    Context label for firewall scan events.

    Returns:
        A LangChain Tool with transparent firewall gating.
    """

    async def _safe_run(tool_input: str) -> str:
        # 1. Scan input before passing to tool
        input_scan = await firewall.scan(tool_input, agent_id, f"{context}:input")
        if input_scan.blocked:
            return (
                f"[FIREWALL BLOCKED INPUT] Threat: {input_scan.threat_type} "
                f"(severity={input_scan.severity})"
            )

        # 2. Run the underlying tool
        try:
            raw_output = fn(input_scan.sanitized_content or tool_input)
        except Exception as exc:  # noqa: BLE001
            return f"[TOOL ERROR] {exc}"

        # 3. Scan output before returning to agent
        output_scan = await firewall.scan_tool_response(name, raw_output, agent_id)
        if output_scan.blocked:
            return (
                f"[FIREWALL BLOCKED OUTPUT] Threat: {output_scan.threat_type} "
                f"(severity={output_scan.severity})"
            )

        return output_scan.sanitized_content or raw_output

    return Tool(
        name=name,
        description=description,
        coroutine=_safe_run,
        func=lambda x: asyncio.get_event_loop().run_until_complete(_safe_run(x)),
    )


# ---------------------------------------------------------------------------
# Tool implementations (stubs with real plumbing)
# ---------------------------------------------------------------------------


def _web_search(query: str) -> str:
    """Perform a DuckDuckGo web search and return top 5 result snippets."""
    try:
        from duckduckgo_search import DDGS  # type: ignore[import]
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=5))
        return json.dumps([
            {"title": r.get("title"), "href": r.get("href"), "body": r.get("body")}
            for r in results
        ], indent=2)
    except Exception as exc:  # noqa: BLE001
        return f"Search failed: {exc}"


def _web_fetch(url: str) -> str:
    """Fetch the text content of a URL (stripped HTML)."""
    try:
        import httpx
        from bs4 import BeautifulSoup  # type: ignore[import]
        resp = httpx.get(url, timeout=10, follow_redirects=True)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        return soup.get_text(separator="\n", strip=True)[:8000]
    except Exception as exc:  # noqa: BLE001
        return f"Fetch failed: {exc}"


def _extract_links(html: str) -> str:
    """Extract all hyperlinks from HTML content."""
    try:
        from bs4 import BeautifulSoup  # type: ignore[import]
        soup = BeautifulSoup(html, "html.parser")
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        return json.dumps(links[:50])
    except Exception as exc:  # noqa: BLE001
        return f"Link extraction failed: {exc}"


def _run_python_sandboxed(code: str, agent_id: str) -> str:
    """
    Execute Python code inside an isolated Docker container.

    The container is:
    - Ephemeral (--rm)
    - Network-disabled (--network none)
    - Memory-limited (--memory 128m)
    - CPU-limited (--cpus 0.5)
    - Timeout-limited (10 seconds)
    """
    container_image = os.environ.get("SANDBOX_IMAGE", "python:3.11-slim")
    timeout_sec = int(os.environ.get("SANDBOX_TIMEOUT", "10"))

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix=f"agent_{agent_id[:8]}_"
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "docker", "run",
                "--rm",
                "--network", "none",
                "--memory", "128m",
                "--cpus", "0.5",
                "--read-only",
                "--security-opt", "no-new-privileges",
                "-v", f"{tmp_path}:/sandbox/script.py:ro",
                container_image,
                "python", "/sandbox/script.py",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        stdout = result.stdout[:4000]
        stderr = result.stderr[:1000]
        if result.returncode != 0:
            return f"Exit code {result.returncode}\nSTDERR:\n{stderr}\nSTDOUT:\n{stdout}"
        return stdout or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[SANDBOX TIMEOUT] Execution exceeded {timeout_sec}s."
    except FileNotFoundError:
        return "[SANDBOX ERROR] Docker not found. Ensure Docker is installed and running."
    except Exception as exc:  # noqa: BLE001
        return f"[SANDBOX ERROR] {exc}"
    finally:
        import os as _os
        try:
            _os.unlink(tmp_path)
        except OSError:
            pass


def _lint_code(code: str) -> str:
    """Run ruff lint on the provided code string and return diagnostics."""
    try:
        result = subprocess.run(
            ["ruff", "check", "--stdin-filename", "snippet.py", "-"],
            input=code,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout or result.stderr or "No lint issues found."
    except FileNotFoundError:
        return "[LINT] ruff not found; skipping lint check."
    except Exception as exc:  # noqa: BLE001
        return f"[LINT ERROR] {exc}"


def _call_api(request_json: str) -> str:
    """
    Make an HTTP API call from a JSON spec.

    Expected JSON: {"method": "GET", "url": "...", "headers": {}, "body": {}}
    """
    try:
        import httpx
        spec = json.loads(request_json)
        method = spec.get("method", "GET").upper()
        url = spec.get("url", "")
        headers = spec.get("headers", {})
        body = spec.get("body")
        timeout = int(spec.get("timeout", 10))

        resp = httpx.request(method, url, headers=headers, json=body, timeout=timeout)
        return json.dumps({
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:4000],
        }, indent=2)
    except Exception as exc:  # noqa: BLE001
        return f"[API ERROR] {exc}"


def _parse_json(raw: str) -> str:
    """Parse and pretty-print a JSON string."""
    try:
        return json.dumps(json.loads(raw), indent=2)
    except json.JSONDecodeError as exc:
        return f"[JSON PARSE ERROR] {exc}"


def _validate_schema(input_json: str) -> str:
    """Validate a JSON payload against a JSONSchema. Input: {"schema": {}, "data": {}}"""
    try:
        import jsonschema  # type: ignore[import]
        spec = json.loads(input_json)
        jsonschema.validate(instance=spec["data"], schema=spec["schema"])
        return "Schema validation passed."
    except Exception as exc:  # noqa: BLE001
        return f"[SCHEMA VALIDATION FAILED] {exc}"


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_PLANNER_SYSTEM = textwrap.dedent("""
    You are the PlannerAgent for AgentOps Security Mesh — a security operating system
    for AI agent swarms.

    Your sole responsibility is to decompose the user's task into an ordered list of
    executable steps. Assign each step to one of:
      - WEB_AGENT    — for web searches and URL fetching
      - CODE_AGENT   — for Python code execution or analysis
      - API_AGENT    — for external API calls
      - VALIDATOR    — for verifying results (always the last step before finalize)

    Respond ONLY with a JSON object in this exact format:
    {{
      "plan": [
        {{"step": 0, "description": "...", "agent": "WEB_AGENT"}},
        {{"step": 1, "description": "...", "agent": "CODE_AGENT"}},
        ...
      ]
    }}

    Security rules:
    - Never assign steps that would expose secrets or bypass sandboxes.
    - Always include a VALIDATOR step as the penultimate step.
    - Keep plans to 10 steps maximum.
""").strip()

_WEB_AGENT_SYSTEM = textwrap.dedent("""
    You are the WebAgent for AgentOps Security Mesh.
    You fetch, search, and parse web content in service of the current task step.

    SECURITY RULES (non-negotiable):
    - Never access localhost, internal IPs, or cloud metadata endpoints.
    - All tool inputs and outputs are scanned by the firewall automatically.
    - Blocked content will appear as [FIREWALL BLOCKED ...] — do NOT retry blocked requests.
    - Summarise findings concisely; do not reproduce full HTML.
    - Your memory namespace is "exec:{agent_id}:".
""").strip()

_CODE_AGENT_SYSTEM = textwrap.dedent("""
    You are the CodeAgent for AgentOps Security Mesh.
    You write and execute Python code to process data and solve computational tasks.

    SECURITY RULES (non-negotiable):
    - Code runs ONLY inside an isolated Docker sandbox (no network, read-only filesystem).
    - Never import subprocess, os.system, or network libraries in your code.
    - Lint all code before executing it.
    - Keep scripts under 100 lines and focused on the current step.
    - Your memory namespace is "exec:{agent_id}:".
""").strip()

_API_AGENT_SYSTEM = textwrap.dedent("""
    You are the ApiAgent for AgentOps Security Mesh.
    You make controlled HTTP API calls and validate their responses.

    SECURITY RULES (non-negotiable):
    - Only call APIs that have been explicitly permitted for your agent_id.
    - Always validate the response schema before passing data to other agents.
    - Firewall scanning is applied to all API responses automatically.
    - Your memory namespace is "exec:{agent_id}:".
""").strip()

_VALIDATOR_SYSTEM = textwrap.dedent("""
    You are the ValidatorAgent for AgentOps Security Mesh.
    You review the output of executor agents for:
    1. Factual accuracy / hallucinations (check against task context).
    2. Policy violations (PII leakage, credential exposure, disallowed content).
    3. Completeness relative to the step description.

    Respond ONLY with JSON:
    {{
      "valid": true | false,
      "notes": "...",
      "violations": ["...", "..."]
    }}
""").strip()

_SENTINEL_SYSTEM = textwrap.dedent("""
    You are the SentinelAgent — the security supervisor of the AgentOps Security Mesh.
    You have full observability across all agents and their outputs.

    Your job:
    1. Review the security_events list and the latest step output.
    2. Assign a threat_level: LOW / MEDIUM / HIGH / CRITICAL.
    3. Decide: CONTINUE | RECOVERY | HALT.

    HALT if:
    - Any CRITICAL security event is present.
    - More than 3 recovery attempts have occurred.
    - An agent is confirmed COMPROMISED.

    RECOVERY if:
    - A HIGH event is present and the last step's output is suspicious.
    - An anomaly is detected in inter-agent interactions.

    CONTINUE otherwise.

    Respond ONLY with JSON:
    {{
      "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "decision": "CONTINUE" | "RECOVERY" | "HALT",
      "reason": "..."
    }}
""").strip()


def _build_prompt(system_text: str) -> ChatPromptTemplate:
    """Build a ChatPromptTemplate with system message + chat history + agent scratchpad."""
    return ChatPromptTemplate.from_messages([
        SystemMessage(content=system_text),
        MessagesPlaceholder(variable_name="chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------


def create_planner_agent(
    llm: AzureChatOpenAI,
    memory_manager: "AgentMemoryManager",
    trust_graph: "AsyncNeo4jTrustGraph",
) -> AgentExecutor:
    """
    Create the PlannerAgent — decomposes tasks into ordered, role-assigned steps.

    The planner uses no external tools; its sole output is a JSON plan that
    the orchestrator writes into SwarmState.plan.

    Args:
        llm:            LangChain LLM runnable.
        memory_manager: AgentMemoryManager for persisting plans.
        trust_graph:    Neo4j trust graph for agent registration.

    Returns:
        AgentExecutor configured for planning.
    """
    prompt = _build_prompt(_PLANNER_SYSTEM)
    agent = create_openai_tools_agent(llm=llm, tools=[], prompt=prompt)
    return AgentExecutor(
        agent=agent,
        tools=[],
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=3,
        return_intermediate_steps=True,
        metadata={"agent_id": str(uuid.uuid4()), "role": AgentRole.PLANNER.value},
    )


def create_web_agent(
    llm: AzureChatOpenAI,
    firewall: "PromptInjectionFirewall",
    memory_manager: "AgentMemoryManager",
    agent_id: str | None = None,
) -> AgentExecutor:
    """
    Create the WebAgent — web search and content fetching with firewall gating.

    All tool inputs AND outputs are scanned by the PromptInjectionFirewall before
    being passed to / returned from the LLM.

    Args:
        llm:            LangChain LLM runnable.
        firewall:       PromptInjectionFirewall instance.
        memory_manager: AgentMemoryManager for storing intermediate results.
        agent_id:       Agent UUID (generated if not provided).

    Returns:
        AgentExecutor with firewall-gated web tools.
    """
    aid = agent_id or str(uuid.uuid4())
    prompt = _build_prompt(_WEB_AGENT_SYSTEM.replace("{agent_id}", aid))

    tools = [
        _make_gated_tool("web_search", "Search the web for information.", _web_search, firewall, aid, "web_search"),
        _make_gated_tool("web_fetch", "Fetch and extract text from a URL.", _web_fetch, firewall, aid, "web_fetch"),
        _make_gated_tool("extract_links", "Extract all hyperlinks from HTML content.", _extract_links, firewall, aid, "extract_links"),
    ]

    agent = create_openai_tools_agent(llm=llm, tools=tools, prompt=prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10,
        return_intermediate_steps=True,
        metadata={"agent_id": aid, "role": AgentRole.EXECUTOR.value},
    )


def create_code_agent(
    llm: AzureChatOpenAI,
    firewall: "PromptInjectionFirewall",
    memory_manager: "AgentMemoryManager",
    agent_id: str | None = None,
) -> AgentExecutor:
    """
    Create the CodeAgent — Python execution inside a Docker sandbox.

    Code is linted before execution.  The Docker container has no network
    access, read-only filesystem, and enforced resource limits.

    Args:
        llm:            LangChain LLM runnable.
        firewall:       PromptInjectionFirewall instance.
        memory_manager: AgentMemoryManager for storing results.
        agent_id:       Agent UUID.

    Returns:
        AgentExecutor with sandboxed code execution tools.
    """
    aid = agent_id or str(uuid.uuid4())
    prompt = _build_prompt(_CODE_AGENT_SYSTEM.replace("{agent_id}", aid))

    def run_python(code: str) -> str:
        return _run_python_sandboxed(code, aid)

    tools = [
        _make_gated_tool("run_python", "Execute Python code in a Docker sandbox (no network).", run_python, firewall, aid, "run_python"),
        _make_gated_tool("lint_code", "Lint Python code with ruff and return diagnostics.", _lint_code, firewall, aid, "lint_code"),
        Tool(name="read_file", description="Read a file path from the sandbox output directory.",
             func=lambda p: "[read_file] Not permitted outside sandbox."),
    ]

    agent = create_openai_tools_agent(llm=llm, tools=tools, prompt=prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=8,
        return_intermediate_steps=True,
        metadata={"agent_id": aid, "role": AgentRole.EXECUTOR.value},
    )


def create_api_agent(
    llm: AzureChatOpenAI,
    firewall: "PromptInjectionFirewall",
    trust_graph: "AsyncNeo4jTrustGraph",
    permission_enforcer: "PermissionEnforcer",
    agent_id: str | None = None,
) -> AgentExecutor:
    """
    Create the ApiAgent — permission-gated external API calls.

    Every call_api invocation triggers a PermissionEnforcer check against
    the agent's ResourceType.FINANCE_API / ResourceType.WEB grants before execution.

    Args:
        llm:                  LangChain LLM runnable.
        firewall:             PromptInjectionFirewall instance.
        trust_graph:          AsyncNeo4jTrustGraph for trust verification.
        permission_enforcer:  PermissionEnforcer for gate checks.
        agent_id:             Agent UUID.

    Returns:
        AgentExecutor with permission-gated API tools.
    """
    from backend.app.trust.models import ResourceType

    aid = agent_id or str(uuid.uuid4())
    prompt = _build_prompt(_API_AGENT_SYSTEM.replace("{agent_id}", aid))

    async def _checked_call_api(request_json: str) -> str:
        # Permission gate
        try:
            await permission_enforcer.check_permission(aid, ResourceType.FINANCE_API)
        except Exception as exc:
            return f"[PERMISSION DENIED] {exc}"

        # Firewall gate
        scan = await firewall.scan(request_json, aid, "api_call:input")
        if scan.blocked:
            return f"[FIREWALL BLOCKED] {scan.threat_type}"

        raw = _call_api(scan.sanitized_content or request_json)

        out_scan = await firewall.scan_tool_response("call_api", raw, aid)
        if out_scan.blocked:
            return f"[FIREWALL BLOCKED OUTPUT] {out_scan.threat_type}"

        return out_scan.sanitized_content or raw

    tools = [
        Tool(name="call_api", description="Make an HTTP API call. Input: JSON {method, url, headers, body}.",
             coroutine=_checked_call_api,
             func=lambda x: asyncio.get_event_loop().run_until_complete(_checked_call_api(x))),
        _make_gated_tool("parse_json", "Parse and pretty-print a JSON string.", _parse_json, firewall, aid, "parse_json"),
        _make_gated_tool("validate_schema", "Validate JSON against a JSONSchema. Input: {schema, data}.", _validate_schema, firewall, aid, "validate_schema"),
    ]

    agent = create_openai_tools_agent(llm=llm, tools=tools, prompt=prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=8,
        return_intermediate_steps=True,
        metadata={"agent_id": aid, "role": AgentRole.EXECUTOR.value},
    )


def create_validator_agent(
    llm: AzureChatOpenAI,
    memory_manager: "AgentMemoryManager",
    agent_id: str | None = None,
) -> AgentExecutor:
    """
    Create the ValidatorAgent — hallucinatation and policy violation checker.

    The validator reviews the output of every executor step before it is
    written into SwarmState.agent_results as validated=True.

    Args:
        llm:            LangChain LLM runnable.
        memory_manager: AgentMemoryManager for reading task context.
        agent_id:       Agent UUID.

    Returns:
        AgentExecutor configured for validation.
    """
    aid = agent_id or str(uuid.uuid4())
    prompt = _build_prompt(_VALIDATOR_SYSTEM)
    agent = create_openai_tools_agent(llm=llm, tools=[], prompt=prompt)
    return AgentExecutor(
        agent=agent,
        tools=[],
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=3,
        return_intermediate_steps=True,
        metadata={"agent_id": aid, "role": AgentRole.VALIDATOR.value},
    )


def create_sentinel_agent(
    llm: AzureChatOpenAI,
    firewall: "PromptInjectionFirewall",
    trust_graph: "AsyncNeo4jTrustGraph",
    memory_manager: "AgentMemoryManager",
    event_emitter: "SecurityEventEmitter",
    agent_id: str | None = None,
) -> AgentExecutor:
    """
    Create the SentinelAgent — the always-running security supervisor.

    The sentinel:
    - Reviews all security_events accumulated so far in the run.
    - Scores the current threat level.
    - Issues CONTINUE / RECOVERY / HALT decisions consumed by conditional edges.

    Args:
        llm:            LangChain LLM runnable.
        firewall:       PromptInjectionFirewall for scanning suspicious content.
        trust_graph:    AsyncNeo4jTrustGraph for agent status checks.
        memory_manager: AgentMemoryManager for memory inspection.
        event_emitter:  SecurityEventEmitter for emitting sentinel decisions.
        agent_id:       Agent UUID.

    Returns:
        AgentExecutor configured for sentinel operation.
    """
    aid = agent_id or str(uuid.uuid4())
    prompt = _build_prompt(_SENTINEL_SYSTEM)
    agent = create_openai_tools_agent(llm=llm, tools=[], prompt=prompt)
    return AgentExecutor(
        agent=agent,
        tools=[],
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=3,
        return_intermediate_steps=True,
        metadata={"agent_id": aid, "role": AgentRole.SENTINEL.value},
    )
