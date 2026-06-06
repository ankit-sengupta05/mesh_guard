"""
settings.py — FastAPI routes for application settings.

Provides endpoints to view and update the active LLM configuration.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/settings", tags=["Settings"])


class LLMSettings(BaseModel):
    provider: str = Field(..., description="azure, openai, or lm_studio")
    base_url: str = Field(
        default="", description="Base URL for the API (LM Studio or Azure Endpoint)"
    )
    api_key: str = Field(default="", description="API key (optional for LM Studio)")
    model: str = Field(default="", description="Deployment name or Model name")


@router.get("/llm")
async def get_llm_settings(request: Request) -> LLMSettings:
    """Return the current active LLM settings."""
    # Read from app state. If not set, return defaults.
    if hasattr(request.app.state, "llm_settings"):
        return request.app.state.llm_settings

    # Default to azure if no state is present
    return LLMSettings(provider="azure", base_url="", api_key="", model="")


@router.post("/llm")
async def update_llm_settings(settings: LLMSettings, request: Request) -> dict[str, Any]:
    """
    Update the active LLM settings and trigger a swarm rebuild in the orchestrator.
    """
    request.app.state.llm_settings = settings

    orchestrator = request.app.state.orchestrator
    if not orchestrator:
        raise HTTPException(status_code=500, detail="Orchestrator not initialized")

    try:
        orchestrator.rebuild_swarm(settings)
        return {"status": "success", "message": "Swarm successfully rebuilt with new LLM settings."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to rebuild swarm: {exc}")
