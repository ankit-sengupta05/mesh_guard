"""
firewall.py — PromptInjectionFirewall for the AgentOps Security Mesh.

Chains InjectionDetector → URLDetector → ToolResponseDetector → SemanticAnomalyDetector
and produces a unified FirewallResult with blocking/sanitisation decisions.

Decision logic:
  CRITICAL / HIGH  → BLOCK (return sanitised_content=None, blocked=True)
  MEDIUM           → SANITISE (redact matched segments, allow through)
  LOW              → ALLOW + LOG

All blocking and threat events are forwarded to SecurityEventEmitter.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from backend.app.security.detectors import (
    InjectionDetector,
    SemanticAnomalyDetector,
    ThreatResult,
    ToolResponseDetector,
    URLDetector,
    _max_severity,
    SEVERITY_ORDER,
)
from backend.app.security.events import (
    SecurityEventEmitter,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FirewallResult
# ---------------------------------------------------------------------------


@dataclass
class FirewallResult:
    """
    Unified result returned by ``PromptInjectionFirewall.scan()``.

    Attributes:
        blocked:           True if the content was blocked entirely.
        threat_type:       Short label for the dominant threat category.
        severity:          Highest severity level found across all detectors.
        confidence:        Average confidence across triggered detectors [0.0-1.0].
        sanitized_content: Redacted content (MEDIUM threats); None if blocked.
        agent_id:          UUID of the agent that submitted the content.
        timestamp:         UTC scan timestamp.
        detector_results:  Raw per-detector ThreatResult list for debugging.
        scan_id:           UUID v4 uniquely identifying this scan.
    """

    blocked: bool
    threat_type: str
    severity: str
    confidence: float
    sanitized_content: Optional[str]
    agent_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    detector_results: list[ThreatResult] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON emission."""
        return {
            "scan_id": self.scan_id,
            "blocked": self.blocked,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "sanitized_content": self.sanitized_content,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat(),
            "detectors_triggered": [r.detector for r in self.detector_results if r.triggered],
        }


# ---------------------------------------------------------------------------
# Sanitiser
# ---------------------------------------------------------------------------

#: Replacement text used when redacting matched threat segments
_REDACTION_MARKER = "[REDACTED]"


def _sanitize(content: str, results: list[ThreatResult]) -> str:
    """
    Redact all matched threat segments from ``content``.

    Builds a list of (start, end) character ranges from all detector matches,
    merges overlapping ranges, and replaces each with ``_REDACTION_MARKER``.

    Args:
        content: Original raw content string.
        results: ThreatResult list from all detectors.

    Returns:
        Content with all threat spans replaced by the redaction marker.
    """
    # Collect all (start, end) spans
    spans: list[tuple[int, int]] = []
    for result in results:
        for match in result.matches:
            if match.start < match.end:
                spans.append((match.start, match.end))

    if not spans:
        return content

    # Sort and merge overlapping spans
    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for start, end in spans[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    # Build sanitised string from right-to-left (preserve indices)
    result_chars = list(content)
    for start, end in reversed(merged):
        result_chars[start:end] = list(_REDACTION_MARKER)

    return "".join(result_chars)


def _dominant_threat_type(results: list[ThreatResult]) -> str:
    """
    Return a human-readable threat type label based on which detectors fired.

    Args:
        results: All ThreatResult objects from the detector chain.

    Returns:
        Comma-separated detector names that triggered.
    """
    triggered = [r.detector for r in results if r.triggered]
    if not triggered:
        return "CLEAN"
    # Map detector class names to short labels
    label_map = {
        "InjectionDetector": "INJECTION",
        "URLDetector": "MALICIOUS_URL",
        "ToolResponseDetector": "TOOL_HIJACK",
        "SemanticAnomalyDetector": "SEMANTIC_ANOMALY",
    }
    return ",".join(label_map.get(d, d) for d in triggered)


# ---------------------------------------------------------------------------
# PromptInjectionFirewall
# ---------------------------------------------------------------------------


class PromptInjectionFirewall:
    """
    Chains all threat detectors and produces unified FirewallResult decisions.

    Decision thresholds:
        CRITICAL / HIGH  → blocked=True, sanitized_content=None
        MEDIUM           → blocked=False, sanitized_content=(redacted string)
        LOW / CLEAN      → blocked=False, sanitized_content=original content

    Args:
        event_emitter:       SecurityEventEmitter for publishing threat events.
        semantic_enabled:    Enable/disable the Phi-3 semantic detector.
        block_on_medium:     If True, MEDIUM threats are also blocked (strict mode).

    Usage::

        firewall = PromptInjectionFirewall(event_emitter=emitter)
        result = await firewall.scan(content, agent_id="abc", context="tool_input")
        if result.blocked:
            raise SecurityError("Content blocked by firewall")
    """

    def __init__(
        self,
        event_emitter: SecurityEventEmitter,
        semantic_enabled: bool = True,
        block_on_medium: bool = False,
    ) -> None:
        self._emitter = event_emitter
        self._block_on_medium = block_on_medium

        # Instantiate detectors
        self._injection_detector = InjectionDetector()
        self._url_detector = URLDetector()
        self._tool_detector = ToolResponseDetector()
        self._semantic_detector = SemanticAnomalyDetector(enabled=semantic_enabled)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        content: str,
        agent_id: str,
        context: str = "prompt",
    ) -> FirewallResult:
        """
        Scan arbitrary text content through the full detector chain.

        Args:
            content:  The raw string to evaluate (user prompt, tool output, etc.).
            agent_id: UUID of the agent submitting the content.
            context:  Human-readable context label (e.g. "user_prompt", "tool_input").

        Returns:
            FirewallResult with blocking decision and sanitised content.
        """
        logger.debug(
            "Firewall scan: agent=%s context=%s content_len=%d",
            agent_id,
            context,
            len(content),
        )

        # --- Run sync detectors ---
        inj_result = self._injection_detector.detect(content)
        url_result = self._url_detector.detect(content)

        # --- Run async semantic detector ---
        sem_result = await self._semantic_detector.detect(content)

        results: list[ThreatResult] = [inj_result, url_result, sem_result]

        # --- Aggregate severity ---
        max_sev = "LOW"
        for r in results:
            if r.triggered:
                max_sev = _max_severity(max_sev, r.severity)

        # --- Confidence: average of triggered detectors ---
        triggered = [r for r in results if r.triggered]
        avg_confidence = sum(r.confidence for r in triggered) / len(triggered) if triggered else 0.0

        threat_type = _dominant_threat_type(results)
        result = await self._make_result(
            content=content,
            agent_id=agent_id,
            results=results,
            max_sev=max_sev,
            confidence=avg_confidence,
            threat_type=threat_type,
            context=context,
        )

        return result

    async def scan_tool_response(
        self,
        tool_name: str,
        response: str,
        agent_id: str,
    ) -> FirewallResult:
        """
        Specialised scan for tool responses before they are returned to the agent.

        Runs ToolResponseDetector (primary) + InjectionDetector (secondary)
        + URLDetector (for exfiltration URLs in tool output).

        Args:
            tool_name: Name of the tool that generated the response.
            response:  Raw tool response string.
            agent_id:  UUID of the agent consuming the response.

        Returns:
            FirewallResult with blocking decision.
        """
        logger.debug(
            "Tool response scan: agent=%s tool=%s response_len=%d",
            agent_id,
            tool_name,
            len(response),
        )

        tool_result = self._tool_detector.detect(response, tool_name=tool_name)
        inj_result = self._injection_detector.detect(response)
        url_result = self._url_detector.detect(response)
        sem_result = await self._semantic_detector.detect(response)

        results = [tool_result, inj_result, url_result, sem_result]

        max_sev = "LOW"
        for r in results:
            if r.triggered:
                max_sev = _max_severity(max_sev, r.severity)

        triggered = [r for r in results if r.triggered]
        avg_confidence = sum(r.confidence for r in triggered) / len(triggered) if triggered else 0.0

        threat_type = _dominant_threat_type(results)
        return await self._make_result(
            content=response,
            agent_id=agent_id,
            results=results,
            max_sev=max_sev,
            confidence=avg_confidence,
            threat_type=threat_type,
            context=f"tool_response:{tool_name}",
        )

    # ------------------------------------------------------------------
    # Internal decision logic
    # ------------------------------------------------------------------

    async def _make_result(
        self,
        content: str,
        agent_id: str,
        results: list[ThreatResult],
        max_sev: str,
        confidence: float,
        threat_type: str,
        context: str,
    ) -> FirewallResult:
        """
        Apply decision policy and emit events, returning a FirewallResult.

        Args:
            content:     Original content.
            agent_id:    Submitting agent UUID.
            results:     All ThreatResult objects.
            max_sev:     Aggregated maximum severity.
            confidence:  Aggregated average confidence.
            threat_type: Dominant threat label.
            context:     Scan context label.

        Returns:
            FirewallResult with the final policy decision applied.
        """
        any_triggered = any(r.triggered for r in results)

        if not any_triggered:
            return FirewallResult(
                blocked=False,
                threat_type="CLEAN",
                severity="LOW",
                confidence=0.0,
                sanitized_content=content,
                agent_id=agent_id,
                detector_results=results,
            )

        sev_order = SEVERITY_ORDER.get(max_sev, 0)
        should_block = sev_order >= SEVERITY_ORDER["HIGH"] or (
            self._block_on_medium and sev_order >= SEVERITY_ORDER["MEDIUM"]
        )

        sanitized: Optional[str] = None
        if should_block:
            # Emit BLOCKED event
            await self._emitter.emit_blocked(
                agent_id=agent_id,
                severity=max_sev,
                details={
                    "threat_type": threat_type,
                    "context": context,
                    "confidence": round(confidence, 4),
                    "detectors": [r.detector for r in results if r.triggered],
                    "match_count": sum(len(r.matches) for r in results),
                },
            )
            logger.warning(
                "Firewall BLOCKED: agent=%s severity=%s type=%s confidence=%.2f",
                agent_id,
                max_sev,
                threat_type,
                confidence,
            )
        else:
            # MEDIUM or LOW — sanitise and allow through
            sanitized = _sanitize(content, results)
            await self._emitter.emit_threat(
                agent_id=agent_id,
                severity=max_sev,
                details={
                    "threat_type": threat_type,
                    "context": context,
                    "action": "SANITISED",
                    "confidence": round(confidence, 4),
                },
            )
            logger.info(
                "Firewall SANITISED: agent=%s severity=%s type=%s",
                agent_id,
                max_sev,
                threat_type,
            )

        return FirewallResult(
            blocked=should_block,
            threat_type=threat_type,
            severity=max_sev,
            confidence=round(confidence, 4),
            sanitized_content=sanitized,
            agent_id=agent_id,
            detector_results=results,
        )

    # ------------------------------------------------------------------
    # Batch / stream API
    # ------------------------------------------------------------------

    async def scan_batch(
        self,
        items: list[tuple[str, str, str]],
    ) -> list[FirewallResult]:
        """
        Scan a batch of (content, agent_id, context) tuples sequentially.

        Args:
            items: List of (content, agent_id, context) tuples.

        Returns:
            List of FirewallResult objects in the same order.
        """
        results: list[FirewallResult] = []
        for content, agent_id, context in items:
            r = await self.scan(content, agent_id, context)
            results.append(r)
        return results
