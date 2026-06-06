"""
trust/__init__.py — Public surface of the AgentOps Security Mesh trust package.

Re-exports the key classes and exceptions so callers only need to import from
``backend.app.trust``.

Example::

    from backend.app.trust import (
        AgentIdentity, AgentRole, AgentStatus,
        Permission, ResourceType, TrustEdge,
        AsyncNeo4jTrustGraph,
        PermissionEnforcer, PermissionDenied, AgentSuspended,
        TrustScorer, TRUST_THRESHOLDS,
    )
"""

from backend.app.trust.graph import AsyncNeo4jTrustGraph
from backend.app.trust.models import (
    AgentIdentity,
    AgentRole,
    AgentStatus,
    Permission,
    ResourceType,
    TrustEdge,
    TrustGraphSnapshot,
)
from backend.app.trust.permissions import (
    AgentSuspended,
    DEFAULT_PERMISSION_MATRIX,
    PermissionDenied,
    PermissionEnforcer,
)
from backend.app.trust.scoring import (
    TRUST_THRESHOLDS,
    TrustScorer,
)

__all__ = [
    # Models
    "AgentIdentity",
    "AgentRole",
    "AgentStatus",
    "Permission",
    "ResourceType",
    "TrustEdge",
    "TrustGraphSnapshot",
    # Graph
    "AsyncNeo4jTrustGraph",
    # Permissions
    "PermissionEnforcer",
    "PermissionDenied",
    "AgentSuspended",
    "DEFAULT_PERMISSION_MATRIX",
    # Scoring
    "TrustScorer",
    "TRUST_THRESHOLDS",
]
