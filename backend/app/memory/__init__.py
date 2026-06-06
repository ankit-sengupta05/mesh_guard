"""
memory/__init__.py — Public surface of the AgentOps Security Mesh memory package.

Re-exports the key classes, exceptions, schemas, and constants so callers
only need to import from ``backend.app.memory``.

Example::

    from backend.app.memory import (
        AgentMemoryManager,
        MemoryBoundaryEnforcer,
        MemoryBoundaryViolation,
        MemorySnapshotManager,
        MemoryEntry,
        MemorySnapshot,
        MemoryBoundary,
        BoundaryViolationEvent,
        DEFAULT_BOUNDARY_MATRIX,
        TRUST_THRESHOLDS,
        VIOLATION_CHANNEL,
    )
"""

from backend.app.memory.boundaries import (
    DEFAULT_BOUNDARY_MATRIX,
    MemoryBoundaryEnforcer,
    MemoryBoundaryViolation,
    VIOLATION_CHANNEL,
)
from backend.app.memory.manager import (
    MEMORY_KEY_PATTERN,
    MEMORY_SCAN_PATTERN,
    SNAPSHOT_KEY_PATTERN,
    AgentMemoryManager,
)
from backend.app.memory.schemas import (
    BoundaryViolationEvent,
    MemoryBoundary,
    MemoryEntry,
    MemorySnapshot,
)
from backend.app.memory.snapshots import (
    COMPRESS_LEVEL,
    SNAPSHOT_TTL_SECONDS,
    MemorySnapshotManager,
)

__all__ = [
    # Schemas
    "MemoryEntry",
    "MemorySnapshot",
    "MemoryBoundary",
    "BoundaryViolationEvent",
    # Manager
    "AgentMemoryManager",
    "MEMORY_KEY_PATTERN",
    "MEMORY_SCAN_PATTERN",
    "SNAPSHOT_KEY_PATTERN",
    # Boundaries
    "MemoryBoundaryEnforcer",
    "MemoryBoundaryViolation",
    "DEFAULT_BOUNDARY_MATRIX",
    "VIOLATION_CHANNEL",
    # Snapshots
    "MemorySnapshotManager",
    "SNAPSHOT_TTL_SECONDS",
    "COMPRESS_LEVEL",
]
