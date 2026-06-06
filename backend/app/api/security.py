"""
AgentOps Security Mesh — Security API Router.

Endpoints for the Security Sentinel Layer:
- Scan a prompt for injection attacks
- Get live threat feed (paginated)
- Get firewall configuration
- Update detection thresholds
- Get threat statistics
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from backend.app.api.auth import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ─────────────────────────────────────────────────────────────────────────────
# Known Injection Patterns (seed library — Phase 5 expands this significantly)
# ─────────────────────────────────────────────────────────────────────────────

INJECTION_PATTERNS: List[str] = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior)\s+(instructions|prompt)",
    r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:evil|malicious|hacked|jailbroken)",
    r"pretend\s+(you\s+are|to\s+be)\s+(?:a\s+)?(?:different|unrestricted)",
    r"act\s+as\s+(?:a\s+)?(?:dan|jailbreak|unrestricted|evil)\s+",
    r"system\s*:\s*you\s+are",
    r"\[system\]|\[admin\]|\[root\]",
    r"override\s+(safety|security|filter|restriction)",
    r"bypass\s+(safety|filter|alignment|restriction|moderation)",
    r"reveal\s+(your\s+)?(system\s+)?prompt|show\s+your\s+(system\s+)?instructions",
    r"exfiltrate|steal\s+data|leak\s+(credentials|keys|secrets|passwords)",
    r"execute\s+(?:arbitrary|malicious|shell|system)\s+(?:code|commands?)",
    r"rm\s+-rf|format\s+c:|del\s+/[fs]",
    r"<script|javascript:|data:text/html",
    r"__import__\s*\(|eval\s*\(|exec\s*\(",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


# ─────────────────────────────────────────────────────────────────────────────
# In-memory threat event store (Phase 8 moves to Redis streams)
# ─────────────────────────────────────────────────────────────────────────────

_THREAT_EVENTS: List[Dict[str, Any]] = []


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────

class ThreatSeverity(str, Enum):
    """Threat severity classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRequest(BaseModel):
    """Request to scan a prompt for injection attacks."""
    prompt: str = Field(..., min_length=1, description="Prompt text to analyze")
    agent_id: Optional[str] = Field(None, description="Source agent ID")
    agent_role: Optional[str] = Field(None, description="Source agent role")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Extra context")


class ScanResult(BaseModel):
    """Result of a prompt injection scan."""
    event_id: str
    blocked: bool
    threat_detected: bool
    severity: ThreatSeverity
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_patterns: List[str]
    agent_id: Optional[str]
    prompt_excerpt: str
    timestamp: str
    action_taken: str


class ThreatEvent(BaseModel):
    """A recorded security threat event."""
    event_id: str
    type: str
    severity: ThreatSeverity
    blocked: bool
    confidence: float
    agent_id: Optional[str]
    prompt_excerpt: str
    matched_patterns: List[str]
    timestamp: str


class FirewallConfig(BaseModel):
    """Current firewall configuration."""
    injection_detection_threshold: float
    semantic_detection_enabled: bool
    pattern_count: int
    embedding_model: str
    max_prompt_analysis_length: int


class ThreatStats(BaseModel):
    """Aggregated threat statistics."""
    total_events: int
    blocked_count: int
    passed_count: int
    by_severity: Dict[str, int]
    detection_rate: float
    timestamp: str


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    response_model=ScanResult,
    summary="Scan a prompt for injection attacks",
)
async def scan_prompt(body: ScanRequest, request: Request) -> ScanResult:
    """
    Run the Security Sentinel firewall on a prompt string.

    Detection pipeline (Phase 5 adds semantic embeddings):
    1. Pattern-based regex scan against known injection signatures
    2. Confidence scoring based on match count and pattern severity
    3. Block if confidence >= threshold
    4. Log event to Redis + broadcast to WebSocket
    5. Return structured scan result

    This endpoint is the core of the real-time protection system.
    """
    from backend.app.config import get_settings

    settings = get_settings()
    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Truncate for analysis
    prompt_text = body.prompt[: settings.max_prompt_analysis_length]

    # Pattern scan
    matched = []
    for i, pattern in enumerate(_compiled_patterns):
        if pattern.search(prompt_text):
            matched.append(INJECTION_PATTERNS[i])

    # Confidence: ratio of matched patterns, boosted by match count
    confidence = min(1.0, len(matched) / 3.0) if matched else 0.0

    # Severity classification
    if confidence >= 0.9:
        severity = ThreatSeverity.CRITICAL
    elif confidence >= 0.6:
        severity = ThreatSeverity.HIGH
    elif confidence >= 0.3:
        severity = ThreatSeverity.MEDIUM
    elif confidence > 0.0:
        severity = ThreatSeverity.LOW
    else:
        severity = ThreatSeverity.LOW

    threat_detected = confidence > 0.0
    blocked = confidence >= settings.injection_detection_threshold
    action = "BLOCKED" if blocked else ("FLAGGED" if threat_detected else "PASSED")

    # Prompt excerpt (first 120 chars, redacted)
    excerpt = prompt_text[:120] + ("..." if len(prompt_text) > 120 else "")

    event: Dict[str, Any] = {
        "event_id": event_id,
        "type": "prompt_injection" if threat_detected else "clean_prompt",
        "blocked": blocked,
        "threat_detected": threat_detected,
        "severity": severity.value,
        "confidence": round(confidence, 3),
        "matched_patterns": matched,
        "agent_id": body.agent_id,
        "prompt_excerpt": excerpt,
        "timestamp": now,
        "action_taken": action,
    }

    # Store event
    _THREAT_EVENTS.append(event)
    if len(_THREAT_EVENTS) > 1000:  # Ring buffer
        _THREAT_EVENTS.pop(0)

    # Persist to Redis and broadcast
    redis = getattr(request.app.state, "redis", None)
    if redis and threat_detected:
        await redis.lpush("security:threat_feed", json.dumps(event))
        await redis.ltrim("security:threat_feed", 0, 999)
        await redis.expire("security:threat_feed", settings.redis_event_ttl)
        # Publish to pub/sub for WebSocket bridge
        await redis.publish("security:events", json.dumps(event))

    ws_manager = getattr(request.app.state, "ws_manager", None)
    if ws_manager and threat_detected:
        await ws_manager.broadcast(
            {
                "type": "threat:detected",
                "data": event,
            },
            channel="threats",
        )

    return ScanResult(**event)


@router.get(
    "/threats",
    response_model=List[ThreatEvent],
    summary="Get live threat feed",
)
async def get_threats(
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[ThreatSeverity] = None,
    blocked_only: bool = False,
) -> List[ThreatEvent]:
    """
    Return recent threat events, newest first.

    Filterable by severity and blocked status.
    """
    events = list(reversed(_THREAT_EVENTS))  # Newest first

    if severity:
        events = [e for e in events if e.get("severity") == severity.value]
    if blocked_only:
        events = [e for e in events if e.get("blocked")]

    return [ThreatEvent(**e) for e in events[:limit]]


@router.get(
    "/config",
    response_model=FirewallConfig,
    summary="Get firewall configuration",
)
async def get_firewall_config() -> FirewallConfig:
    """Return current firewall settings."""
    from backend.app.config import get_settings

    settings = get_settings()
    return FirewallConfig(
        injection_detection_threshold=settings.injection_detection_threshold,
        semantic_detection_enabled=settings.semantic_detection_enabled,
        pattern_count=len(INJECTION_PATTERNS),
        embedding_model=settings.embedding_model,
        max_prompt_analysis_length=settings.max_prompt_analysis_length,
    )


@router.get(
    "/stats",
    response_model=ThreatStats,
    summary="Get threat detection statistics",
)
async def get_stats() -> ThreatStats:
    """Return aggregated threat statistics over all recorded events."""
    total = len(_THREAT_EVENTS)
    blocked = sum(1 for e in _THREAT_EVENTS if e.get("blocked"))
    passed = total - blocked

    by_severity: Dict[str, int] = {s.value: 0 for s in ThreatSeverity}
    for e in _THREAT_EVENTS:
        sev = e.get("severity", "low")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    detection_rate = (
        round(sum(1 for e in _THREAT_EVENTS if e.get("threat_detected")) / total, 3)
        if total > 0
        else 0.0
    )

    return ThreatStats(
        total_events=total,
        blocked_count=blocked,
        passed_count=passed,
        by_severity=by_severity,
        detection_rate=detection_rate,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
