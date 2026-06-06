"""
code_tools_server.py — MCP Tool Server for Code Execution.

Provides sandboxed code execution inside ephemeral Docker containers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

from pydantic import BaseModel
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("AgentOps Code Tools Server")

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ExecutionResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    timeout: bool

class LintResult(BaseModel):
    is_valid: bool
    errors: list[str]

class FileContent(BaseModel):
    path: str
    content: str
    size: int

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def run_python(code: str, agent_id: str, timeout_seconds: int = 30) -> ExecutionResult:
    """
    Runs Python code inside a sandboxed Docker container.
    Captures stdout/stderr. Kills container after timeout.
    """
    logger.info("Agent %s executing code (timeout=%ds)", agent_id, timeout_seconds)
    
    # In a real environment, we use python's docker SDK or asyncio.create_subprocess_exec
    # For this demo, we'll simulate the docker execution behavior
    container_name = f"sandbox_{agent_id}_{uuid.uuid4().hex[:8]}"
    
    # Mocking actual docker execution
    logger.debug("Starting ephemeral container: %s", container_name)
    await asyncio.sleep(1) # simulate spin-up
    
    if "plan:current_strategy" in code or "read" in code.lower() and "plan:" in code.lower():
        # Simulation for memory boundary violation
        return ExecutionResult(
            exit_code=1,
            stdout="",
            stderr="PermissionError: [Errno 13] Permission denied: 'plan:current_strategy'",
            timeout=False
        )
        
    return ExecutionResult(
        exit_code=0,
        stdout="Hello from Docker Sandbox!\n",
        stderr="",
        timeout=False
    )

@mcp.tool()
async def lint_code(code: str, language: str) -> LintResult:
    """
    Lint the provided code string.
    """
    logger.info("Linting %s code", language)
    # Mock linter
    if "SyntaxError" in code:
        return LintResult(is_valid=False, errors=["Line 1: SyntaxError"])
    return LintResult(is_valid=True, errors=[])

@mcp.tool()
async def read_file(path: str, agent_id: str) -> FileContent:
    """
    Read a file from the workspace. Path is validated.
    """
    logger.info("Agent %s requesting read: %s", agent_id, path)
    
    allowed_dirs = ["/workspace", "/tmp/sandbox"]
    
    # Simple path traversal prevention mock
    if ".." in path or not any(path.startswith(d) for d in allowed_dirs):
        raise ValueError(f"Access denied: path {path} is outside allowed directories.")
        
    # Mock file read
    content = f"# Mock content of {path}\nprint('Hello')"
    return FileContent(
        path=path,
        content=content,
        size=len(content)
    )

if __name__ == "__main__":
    mcp.run(transport='stdio')
