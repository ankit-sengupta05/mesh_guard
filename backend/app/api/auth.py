"""
AgentOps Security Mesh — API Key Authentication.

Provides a FastAPI dependency for API key validation.
All protected routes depend on `require_api_key`.
"""

from __future__ import annotations

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from backend.app.config import get_settings

# Header name: Authorization: Bearer <key>  OR  X-API-Key: <key>
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str = Security(_api_key_header)) -> str:
    """
    FastAPI dependency that validates the X-API-Key header.

    Raises HTTP 401 if the key is missing or invalid.
    In development mode (ENV=development), accepts 'dev-api-key' without
    checking against the configured value — so tooling just works locally.

    Usage:
        @router.get("/protected", dependencies=[Depends(require_api_key)])
    """
    settings = get_settings()

    # Development shortcut
    if not settings.is_production and api_key == "dev-api-key":
        return api_key

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

    return api_key
