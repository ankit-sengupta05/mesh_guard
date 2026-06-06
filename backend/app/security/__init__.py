"""
security/__init__.py — Public surface of the AgentOps Security Mesh security package.
"""

from backend.app.security.detectors import (
    InjectionDetector,
    SemanticAnomalyDetector,
    ThreatMatch,
    ThreatResult,
    ToolResponseDetector,
    URLDetector,
)
from backend.app.security.events import (
    EventSeverity,
    EventType,
    SecurityEvent,
    SecurityEventEmitter,
)
from backend.app.security.firewall import (
    FirewallResult,
    PromptInjectionFirewall,
)
from backend.app.security.patterns import (
    DetectionPattern,
    INJECTION_PATTERNS,
    MALICIOUS_URL_PATTERNS,
    TOOL_HIJACKING_PATTERNS,
)

__all__ = [
    # Patterns
    "DetectionPattern",
    "INJECTION_PATTERNS",
    "MALICIOUS_URL_PATTERNS",
    "TOOL_HIJACKING_PATTERNS",
    # Detectors
    "ThreatMatch",
    "ThreatResult",
    "InjectionDetector",
    "URLDetector",
    "ToolResponseDetector",
    "SemanticAnomalyDetector",
    # Events
    "EventType",
    "EventSeverity",
    "SecurityEvent",
    "SecurityEventEmitter",
    # Firewall
    "FirewallResult",
    "PromptInjectionFirewall",
]
