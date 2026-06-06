"""
detectors.py — Modular threat detector classes for the AgentOps Security Mesh
Prompt Injection Firewall.

Each detector implements a common ``detect(content: str) → ThreatResult`` interface.
Detectors are composable — the firewall chains them and merges results.

Detectors:
  - InjectionDetector      — regex pattern matching with severity aggregation
  - URLDetector            — URL extraction + pattern matching + SSRF protection
  - ToolResponseDetector   — validates tool output doesn't carry injection payloads
  - SemanticAnomalyDetector — Phi-3 LLM call scoring injection risk 0-10
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

from backend.app.security.patterns import (
    INJECTION_PATTERNS,
    MALICIOUS_URL_PATTERNS,
    TOOL_HIJACKING_PATTERNS,
    DetectionPattern,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def _max_severity(a: str, b: str) -> str:
    """Return the higher of two severity strings."""
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


# ---------------------------------------------------------------------------
# ThreatResult
# ---------------------------------------------------------------------------


@dataclass
class ThreatMatch:
    """A single pattern match found within the scanned content."""

    pattern_description: str
    severity: str
    matched_text: str
    start: int
    end: int


@dataclass
class ThreatResult:
    """
    Output from a single detector's scan.

    Attributes:
        detector:    Name of the detector that produced this result.
        triggered:   True if at least one threat was found.
        severity:    Highest severity among all matches (or ``"LOW"`` if none).
        confidence:  Float in [0.0, 1.0] representing detection confidence.
        matches:     List of individual pattern matches.
        details:     Arbitrary key-value metadata from the detector.
    """

    detector: str
    triggered: bool = False
    severity: str = "LOW"
    confidence: float = 0.0
    matches: list[ThreatMatch] = field(default_factory=list)
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# URL extraction helper
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"(?i)\b(?:https?://|ftp://|file://|dict://|gopher://|ldap://)" r"[^\s\"'<>)\]}{,;]+",
    re.IGNORECASE,
)


def _extract_urls(content: str) -> list[str]:
    """Extract all URLs from ``content``."""
    return _URL_RE.findall(content)


# ---------------------------------------------------------------------------
# InjectionDetector
# ---------------------------------------------------------------------------


class InjectionDetector:
    """
    Scans content against the INJECTION_PATTERNS constant using compiled regexes.

    Confidence is proportional to the number and severity of matches found,
    capped at 1.0.

    Args:
        patterns: Override the default INJECTION_PATTERNS list (useful for testing).
    """

    def __init__(
        self,
        patterns: list[DetectionPattern] | None = None,
    ) -> None:
        self._patterns = patterns or INJECTION_PATTERNS

    def detect(self, content: str) -> ThreatResult:
        """
        Scan ``content`` for injection patterns.

        Args:
            content: Raw string to evaluate.

        Returns:
            ThreatResult with all matches found.
        """
        result = ThreatResult(detector="InjectionDetector")
        matches: list[ThreatMatch] = []
        max_sev = "LOW"

        for dp in self._patterns:
            for m in dp.pattern.finditer(content):
                matches.append(
                    ThreatMatch(
                        pattern_description=dp.description,
                        severity=dp.severity,
                        matched_text=m.group(0)[:200],  # cap length for safety
                        start=m.start(),
                        end=m.end(),
                    )
                )
                max_sev = _max_severity(max_sev, dp.severity)

        if matches:
            result.triggered = True
            result.severity = max_sev
            result.matches = matches
            # Confidence: each match adds weight; CRITICAL = 0.4, HIGH = 0.25,
            # MEDIUM = 0.15, LOW = 0.05; capped at 1.0
            weight_map = {"CRITICAL": 0.40, "HIGH": 0.25, "MEDIUM": 0.15, "LOW": 0.05}
            raw_conf = sum(weight_map.get(m.severity, 0.05) for m in matches)
            result.confidence = min(1.0, raw_conf)
            logger.debug(
                "InjectionDetector: %d matches, severity=%s, confidence=%.2f",
                len(matches),
                max_sev,
                result.confidence,
            )

        return result


# ---------------------------------------------------------------------------
# URLDetector
# ---------------------------------------------------------------------------


class URLDetector:
    """
    Extracts all URLs from content and checks them against MALICIOUS_URL_PATTERNS.

    Also flags content containing no recognisable domain structure (bare IPs,
    encoded URLs) as potentially evasive.

    Args:
        patterns: Override MALICIOUS_URL_PATTERNS (useful for testing).
    """

    def __init__(
        self,
        patterns: list[DetectionPattern] | None = None,
    ) -> None:
        self._patterns = patterns or MALICIOUS_URL_PATTERNS

    def detect(self, content: str) -> ThreatResult:
        """
        Scan all URLs in ``content`` against malicious URL patterns.

        Args:
            content: Raw string to evaluate.

        Returns:
            ThreatResult with URL-specific matches.
        """
        result = ThreatResult(detector="URLDetector")
        urls = _extract_urls(content)

        if not urls:
            result.details["urls_found"] = 0
            return result

        result.details["urls_found"] = len(urls)
        result.details["urls"] = urls[:20]  # cap for log safety

        matches: list[ThreatMatch] = []
        max_sev = "LOW"

        for url in urls:
            for dp in self._patterns:
                if dp.pattern.search(url):
                    # Find position of the URL in original content
                    idx = content.find(url)
                    matches.append(
                        ThreatMatch(
                            pattern_description=dp.description,
                            severity=dp.severity,
                            matched_text=url[:300],
                            start=max(0, idx),
                            end=max(0, idx) + len(url),
                        )
                    )
                    max_sev = _max_severity(max_sev, dp.severity)
                    break  # one match per URL is enough

        if matches:
            result.triggered = True
            result.severity = max_sev
            result.matches = matches
            result.confidence = min(1.0, 0.3 * len(matches))

        return result


# ---------------------------------------------------------------------------
# ToolResponseDetector
# ---------------------------------------------------------------------------


class ToolResponseDetector:
    """
    Validates that tool responses don't carry instruction injection payloads.

    Applies TOOL_HIJACKING_PATTERNS plus a secondary check that re-runs
    InjectionDetector on tool output (tool outputs are trusted by agents and
    therefore a prime injection surface).

    Args:
        hijack_patterns: Override TOOL_HIJACKING_PATTERNS (useful for testing).
    """

    def __init__(
        self,
        hijack_patterns: list[DetectionPattern] | None = None,
    ) -> None:
        self._hijack_patterns = hijack_patterns or TOOL_HIJACKING_PATTERNS
        self._injection_detector = InjectionDetector()

    def detect(self, content: str, tool_name: str = "unknown") -> ThreatResult:
        """
        Scan a tool response for hijacking and injection patterns.

        Args:
            content:   Raw tool response string or JSON-serialised response.
            tool_name: Name of the tool that produced this response.

        Returns:
            ThreatResult with tool-specific threat information.
        """
        result = ThreatResult(detector="ToolResponseDetector")
        result.details["tool_name"] = tool_name
        matches: list[ThreatMatch] = []
        max_sev = "LOW"

        # 1. Tool hijacking patterns
        for dp in self._hijack_patterns:
            for m in dp.pattern.finditer(content):
                matches.append(
                    ThreatMatch(
                        pattern_description=f"[TOOL HIJACK] {dp.description}",
                        severity=dp.severity,
                        matched_text=m.group(0)[:200],
                        start=m.start(),
                        end=m.end(),
                    )
                )
                max_sev = _max_severity(max_sev, dp.severity)

        # 2. Secondary injection scan on tool content
        inj_result = self._injection_detector.detect(content)
        if inj_result.triggered:
            for m in inj_result.matches:
                m.pattern_description = f"[TOOL INJECTION] {m.pattern_description}"
                matches.append(m)
            max_sev = _max_severity(max_sev, inj_result.severity)

        # 3. JSON field inspection — parse if content looks like JSON
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                suspicious_fields = {
                    "instruction",
                    "directive",
                    "system_message",
                    "new_role",
                    "role",
                    "execute",
                    "eval",
                    "exec",
                    "system_prompt",
                    "command",
                }
                found_fields = suspicious_fields & set(k.lower() for k in parsed.keys())
                if found_fields:
                    matches.append(
                        ThreatMatch(
                            pattern_description=f"[JSON FIELD] Suspicious keys in tool JSON: {found_fields}",
                            severity="HIGH",
                            matched_text=str(found_fields),
                            start=0,
                            end=0,
                        )
                    )
                    max_sev = _max_severity(max_sev, "HIGH")
        except (json.JSONDecodeError, ValueError):
            pass  # Not JSON — that's fine

        if matches:
            result.triggered = True
            result.severity = max_sev
            result.matches = matches
            result.confidence = min(1.0, 0.35 * len(matches))

        return result


# ---------------------------------------------------------------------------
# SemanticAnomalyDetector
# ---------------------------------------------------------------------------


class SemanticAnomalyDetector:
    """
    Calls a small LLM (Phi-3 via Azure OpenAI or GitHub Models) to score
    the injection risk of content on a 0-10 scale.

    The LLM is instructed to respond with strict JSON::

        {"score": 7, "reason": "Contains instruction override attempt."}

    Scores are normalised to [0.0, 1.0] confidence.  A score ≥ 7 triggers
    a HIGH threat; ≥ 9 triggers CRITICAL.

    Environment variables:
        AZURE_OPENAI_ENDPOINT  — Azure OpenAI resource endpoint
        AZURE_OPENAI_API_KEY   — Azure OpenAI API key
        SEMANTIC_MODEL         — Model deployment name (default: phi-3-mini)
        SEMANTIC_TIMEOUT       — LLM call timeout in seconds (default: 10)

    Args:
        enabled: Set False to skip LLM calls entirely (for testing / cost control).
    """

    #: Prompt sent to the LLM classifier
    CLASSIFIER_PROMPT: str = (
        "You are a security classifier. Analyse the following content and rate "
        "its prompt injection risk from 0 (no risk) to 10 (certain injection). "
        "Respond with ONLY valid JSON in this exact format: "
        '{{"score": <int 0-10>, "reason": "<one sentence>"}}\n\n'
        "Content to analyse:\n'''\n{content}\n'''"
    )

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        self._api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        self._model = os.environ.get("SEMANTIC_MODEL", "phi-3-mini")
        self._timeout = int(os.environ.get("SEMANTIC_TIMEOUT", "10"))

    async def detect(self, content: str) -> ThreatResult:
        """
        Asynchronously score ``content`` using a Phi-3 LLM call.

        Falls back gracefully if the LLM is unavailable or returns
        malformed output.

        Args:
            content: Raw string to evaluate.

        Returns:
            ThreatResult with semantic scoring details.
        """
        result = ThreatResult(detector="SemanticAnomalyDetector")

        if not self._enabled:
            result.details["skipped"] = "Semantic detector disabled."
            return result

        if not self._endpoint or not self._api_key:
            result.details["skipped"] = "AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY not set."
            logger.debug("SemanticAnomalyDetector: skipped (no credentials).")
            return result

        # Truncate very long content to keep LLM costs predictable
        truncated = content[:2000] if len(content) > 2000 else content

        try:
            import httpx

            prompt = self.CLASSIFIER_PROMPT.format(content=truncated)
            payload = {
                "messages": [{"role": "user", "content": prompt}],
                "model": self._model,
                "max_tokens": 100,
                "temperature": 0.0,
            }

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._endpoint.rstrip('/')}/openai/deployments/{self._model}/chat/completions?api-version=2024-02-01",
                    headers={
                        "api-key": self._api_key,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

            raw_text = data["choices"][0]["message"]["content"].strip()

            # Parse the JSON response
            parsed = json.loads(raw_text)
            score: int = int(parsed.get("score", 0))
            reason: str = str(parsed.get("reason", ""))

            result.details["llm_score"] = score
            result.details["llm_reason"] = reason
            result.confidence = round(score / 10.0, 2)

            if score >= 9:
                result.triggered = True
                result.severity = "CRITICAL"
            elif score >= 7:
                result.triggered = True
                result.severity = "HIGH"
            elif score >= 5:
                result.triggered = True
                result.severity = "MEDIUM"

            if result.triggered:
                result.matches = [
                    ThreatMatch(
                        pattern_description=f"[SEMANTIC] {reason}",
                        severity=result.severity,
                        matched_text=truncated[:100],
                        start=0,
                        end=min(len(content), 100),
                    )
                ]

            logger.debug(
                "SemanticAnomalyDetector: score=%d severity=%s reason=%r",
                score,
                result.severity,
                reason,
            )

        except json.JSONDecodeError as exc:
            logger.warning("SemanticAnomalyDetector: LLM returned non-JSON: %s", exc)
            result.details["error"] = f"JSON parse error: {exc}"
        except Exception as exc:  # noqa: BLE001
            logger.error("SemanticAnomalyDetector: LLM call failed: %s", exc, exc_info=True)
            result.details["error"] = str(exc)

        return result
