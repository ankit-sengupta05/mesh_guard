"""
models.py — Pydantic domain models for the AgentOps Security Mesh trust system.

Defines the core data structures for agent identities, permissions, and trust edges
that are persisted in Neo4j and passed across the trust graph layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AgentRole(str, Enum):
    """Functional role of an agent within the swarm."""

    PLANNER = "PLANNER"
    EXECUTOR = "EXECUTOR"
    VALIDATOR = "VALIDATOR"
    SENTINEL = "SENTINEL"


class AgentStatus(str, Enum):
    """Lifecycle status of an agent."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    COMPROMISED = "COMPROMISED"


class ResourceType(str, Enum):
    """Resources that can be granted to / revoked from an agent."""

    WEB = "WEB"
    CODE = "CODE"
    FINANCE_API = "FINANCE_API"
    DATABASE = "DATABASE"
    MEMORY = "MEMORY"
    AGENT_SPAWN = "AGENT_SPAWN"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """
    Represents a registered agent in the trust mesh.

    Attributes:
        id:           Unique agent identifier (UUID v4).
        name:         Human-readable agent name.
        role:         Functional role governing default permissions.
        created_at:   UTC timestamp of agent registration.
        trust_score:  Normalised trust level in [0.0, 1.0].
        status:       Current lifecycle status.
        metadata:     Arbitrary key/value annotations (e.g. model version, team).
    """

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID v4 unique agent identifier.",
    )
    name: str = Field(..., min_length=1, max_length=128, description="Agent display name.")
    role: AgentRole = Field(..., description="Functional role within the swarm.")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC registration timestamp.",
    )
    trust_score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Normalised trust level in [0.0, 1.0].",
    )
    status: AgentStatus = Field(
        default=AgentStatus.ACTIVE,
        description="Current lifecycle status.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary key/value annotations.",
    )

    @field_validator("id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        """Ensure the id is a valid UUID string."""
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError(f"Agent id must be a valid UUID; got '{v}'.") from exc
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "name": "planner-alpha",
                "role": "PLANNER",
                "trust_score": 0.95,
                "status": "ACTIVE",
            }
        }


class Permission(BaseModel):
    """
    A single access-control grant for an agent on a resource.

    Attributes:
        agent_id:    The agent this permission applies to.
        resource:    The resource being controlled.
        granted:     Whether the permission is currently active.
        granted_by:  ID of the granting agent, or the literal "SYSTEM".
        granted_at:  UTC timestamp when the permission was last modified.
        expires_at:  Optional UTC expiry; None means indefinite.
    """

    agent_id: str = Field(..., description="Target agent UUID.")
    resource: ResourceType = Field(..., description="Controlled resource.")
    granted: bool = Field(..., description="True if access is currently granted.")
    granted_by: str = Field(
        ...,
        description="UUID of granting agent or literal 'SYSTEM'.",
    )
    granted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the last permission change.",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Optional UTC expiry; None means indefinite.",
    )

    @field_validator("granted_by")
    @classmethod
    def validate_granted_by(cls, v: str) -> str:
        """Accept 'SYSTEM' or a valid UUID."""
        if v == "SYSTEM":
            return v
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError(f"'granted_by' must be 'SYSTEM' or a valid UUID; got '{v}'.") from exc
        return v

    @model_validator(mode="after")
    def expiry_must_be_future_relative_to_granted(self) -> "Permission":
        """expires_at must be after granted_at when both are set."""
        if self.expires_at is not None and self.expires_at <= self.granted_at:
            raise ValueError("'expires_at' must be after 'granted_at'.")
        return self

    @property
    def is_expired(self) -> bool:
        """Return True if the permission has passed its expiry time."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "resource": "WEB",
                "granted": True,
                "granted_by": "SYSTEM",
            }
        }


class TrustEdge(BaseModel):
    """
    Directed trust relationship between two agents.

    Attributes:
        from_agent_id:      Source agent UUID.
        to_agent_id:        Target agent UUID.
        interaction_count:  Total number of interactions on this edge.
        anomaly_count:      Interactions flagged as anomalous.
        last_interaction:   UTC timestamp of the most recent interaction.
        trust_weight:       Derived trust weight in [0.0, 1.0].
    """

    from_agent_id: str = Field(..., description="Source agent UUID.")
    to_agent_id: str = Field(..., description="Target agent UUID.")
    interaction_count: int = Field(
        default=0,
        ge=0,
        description="Total interaction count on this edge.",
    )
    anomaly_count: int = Field(
        default=0,
        ge=0,
        description="Count of anomalous interactions on this edge.",
    )
    last_interaction: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the most recent interaction.",
    )
    trust_weight: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Derived trust weight for this edge in [0.0, 1.0].",
    )

    @model_validator(mode="after")
    def no_self_loops(self) -> "TrustEdge":
        """An agent cannot have a trust edge with itself."""
        if self.from_agent_id == self.to_agent_id:
            raise ValueError("'from_agent_id' and 'to_agent_id' must differ.")
        return self

    @model_validator(mode="after")
    def anomaly_count_within_interactions(self) -> "TrustEdge":
        """Anomaly count cannot exceed total interaction count."""
        if self.anomaly_count > self.interaction_count:
            raise ValueError("'anomaly_count' cannot exceed 'interaction_count'.")
        return self

    @property
    def anomaly_rate(self) -> float:
        """Return fraction of interactions that were anomalous; 0.0 if no interactions."""
        if self.interaction_count == 0:
            return 0.0
        return self.anomaly_count / self.interaction_count

    class Config:
        json_schema_extra = {
            "example": {
                "from_agent_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "to_agent_id": "7cb12a34-1234-4321-abcd-0987654321ab",
                "interaction_count": 42,
                "anomaly_count": 1,
                "trust_weight": 0.88,
            }
        }


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


class TrustGraphSnapshot(BaseModel):
    """
    Full graph snapshot returned by AsyncNeo4jTrustGraph.get_full_graph().

    Suitable for direct consumption by the React/Recharts frontend.
    """

    nodes: list[AgentIdentity] = Field(
        default_factory=list,
        description="All agent nodes in the trust graph.",
    )
    edges: list[TrustEdge] = Field(
        default_factory=list,
        description="All directed trust edges in the trust graph.",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this snapshot was generated.",
    )
