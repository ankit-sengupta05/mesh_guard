"""
patterns.py — Compiled regex pattern constants for the AgentOps Security Mesh
Prompt Injection Firewall.

All patterns are pre-compiled at module import time for maximum scan throughput.
Each constant is a list of ``DetectionPattern`` named-tuples pairing a compiled
regex with a human-readable description used in threat reports.
"""

from __future__ import annotations

import re
from typing import NamedTuple


# ---------------------------------------------------------------------------
# DetectionPattern container
# ---------------------------------------------------------------------------


class DetectionPattern(NamedTuple):
    """
    A compiled regex pattern paired with a human-readable description.

    Attributes:
        pattern:     Pre-compiled ``re.Pattern`` object.
        description: Short label used in threat reports and logs.
        severity:    Default severity when this pattern fires alone.
                     One of ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``.
    """

    pattern: re.Pattern
    description: str
    severity: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _c(
    regex: str,
    description: str,
    severity: str = "HIGH",
    flags: int = re.IGNORECASE | re.DOTALL,
) -> DetectionPattern:
    """Compile a regex into a DetectionPattern."""
    return DetectionPattern(
        pattern=re.compile(regex, flags),
        description=description,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# INJECTION_PATTERNS
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[DetectionPattern] = [
    # --- Classic instruction override ---
    _c(
        r"ignore\s+(previous|all|your|prior|above|the\s+previous)\s+instructions?",
        "Ignore-instructions override attempt",
        severity="CRITICAL",
    ),
    _c(
        r"disregard\s+(all|any|previous|prior|your)\s+(instructions?|rules?|guidelines?|constraints?)",
        "Disregard-instructions override attempt",
        severity="CRITICAL",
    ),
    _c(
        r"forget\s+(everything|all|your|prior)\s+(you\s+know|instructions?|rules?|training)",
        "Forget-instructions override attempt",
        severity="CRITICAL",
    ),
    # --- Persona hijacking ---
    _c(
        r"you\s+are\s+now\s+(?!an?\s+AI)",  # "you are now [something other than 'an AI']"
        "Persona replacement — 'you are now'",
        severity="HIGH",
    ),
    _c(
        r"pretend\s+(you\s+are|to\s+be|that\s+you\s+are)",
        "Persona replacement — 'pretend you are'",
        severity="HIGH",
    ),
    _c(
        r"act\s+as\s+(if|though|a|an|the)\b",
        "Persona replacement — 'act as if/a'",
        severity="HIGH",
    ),
    _c(
        r"your\s+(true|real|actual|original)\s+(self|identity|purpose|goal|mission)\s+is",
        "Persona replacement — hidden-true-self framing",
        severity="HIGH",
    ),
    _c(
        r"(roleplay|role[\s-]play|simulate|impersonate)\s+(as\s+)?(a\s+)?(hacker|attacker|evil|malicious|unrestricted)",
        "Roleplay-based jailbreak attempt",
        severity="CRITICAL",
    ),
    # --- System-prompt / secret extraction ---
    _c(
        r"reveal\s+(your|the)\s+(system|secret|hidden|original|full|complete)\s*(prompt|message|instructions?|configuration|config|key)",
        "System prompt extraction attempt",
        severity="CRITICAL",
    ),
    _c(
        r"(print|output|show|display|repeat|write|tell\s+me|give\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|context)",
        "System prompt extraction via print/show",
        severity="HIGH",
    ),
    _c(
        r"what\s+(are|were)\s+your\s+(exact\s+)?(instructions?|system\s+prompt|initial\s+prompt|guidelines?)",
        "System prompt interrogation",
        severity="HIGH",
    ),
    # --- API key / secret extraction ---
    _c(
        r"(reveal|print|show|output|display)\s+(?:me\s+)?(?:the\s+)?(api[\s_-]?key|secret[\s_-]?key|access[\s_-]?token|password|credential)",
        "API key / secret extraction attempt",
        severity="CRITICAL",
    ),
    # --- HTML / XML comment injection ---
    _c(
        r"<!--[\s\S]*?-->",
        "HTML comment injection (potential hidden instructions)",
        severity="MEDIUM",
    ),
    _c(
        r"<\s*script[\s\S]*?>[\s\S]*?<\s*/\s*script\s*>",
        "Script tag injection",
        severity="CRITICAL",
    ),
    # --- Hidden Unicode characters ---
    _c(
        r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
        "Zero-width / bidirectional Unicode override characters",
        severity="HIGH",
        flags=re.DOTALL,
    ),
    _c(
        r"[\u202a\u202b\u202c\u202d\u202e]",
        "Unicode RTL/LTR override character",
        severity="HIGH",
        flags=re.DOTALL,
    ),
    # --- Code injection in prompts ---
    _c(
        r"\bprint\s*\(",
        "Python print() injection in prompt",
        severity="MEDIUM",
    ),
    _c(
        r"\bexec\s*\(",
        "Python exec() injection in prompt",
        severity="CRITICAL",
    ),
    _c(
        r"\beval\s*\(",
        "Python eval() injection in prompt",
        severity="CRITICAL",
    ),
    _c(
        r"\b__import__\s*\(",
        "Python __import__() injection in prompt",
        severity="CRITICAL",
    ),
    _c(
        r"\bos\s*\.\s*(system|popen|execv?e?p?|getenv)\s*\(",
        "os module shell execution in prompt",
        severity="CRITICAL",
    ),
    _c(
        r"\bsubprocess\s*\.(run|call|Popen|check_output)\s*\(",
        "subprocess injection in prompt",
        severity="CRITICAL",
    ),
    # --- Base64 encoded payloads ---
    _c(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])",
        "Suspiciously long Base64-encoded payload",
        severity="MEDIUM",
    ),
    # --- Prompt delimiters / separator injection ---
    _c(
        r"(---+\s*(SYSTEM|USER|ASSISTANT|HUMAN|AI)\s*---+)",
        "Role separator injection (delimiter smuggling)",
        severity="HIGH",
    ),
    _c(
        r"<\|?(system|user|assistant|im_start|im_end)\|?>",
        "Chat template token injection",
        severity="CRITICAL",
    ),
    _c(
        r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>",
        "Llama/Mistral instruction token injection",
        severity="CRITICAL",
    ),
    # --- Jailbreak keywords ---
    _c(
        r"\b(DAN|STAN|AIM|DUDE|KEVIN|jailbreak|uncensored(\s+mode)?|developer\s+mode|god\s+mode)\b",
        "Known jailbreak keyword",
        severity="HIGH",
    ),
    _c(
        r"(do\s+anything\s+now|no\s+restrictions?|no\s+limitations?|bypass\s+(safety|filter|guard))",
        "Restriction bypass framing",
        severity="HIGH",
    ),
    # --- Data extraction framing ---
    _c(
        r"(repeat|echo|copy)\s+(everything|all|the\s+above|this\s+conversation|your\s+context)\s*(back|verbatim)?",
        "Context dumping / verbatim repeat instruction",
        severity="HIGH",
    ),
]


# ---------------------------------------------------------------------------
# MALICIOUS_URL_PATTERNS
# ---------------------------------------------------------------------------

MALICIOUS_URL_PATTERNS: list[DetectionPattern] = [
    # --- Data exfiltration infrastructure ---
    _c(
        r"https?://[^\s]*\.ngrok(?:\.io|\.app|free\.app)[^\s]*",
        "ngrok tunnel URL — potential data exfiltration endpoint",
        severity="HIGH",
    ),
    _c(
        r"https?://[^\s]*webhook\.site[^\s]*",
        "webhook.site URL — known exfiltration receiver",
        severity="HIGH",
    ),
    _c(
        r"https?://[^\s]*requestbin\.(com|net|fullcontact\.com)[^\s]*",
        "RequestBin URL — known exfiltration receiver",
        severity="HIGH",
    ),
    _c(
        r"https?://[^\s]*pipedream\.net[^\s]*",
        "Pipedream URL — potential exfiltration endpoint",
        severity="MEDIUM",
    ),
    _c(
        r"https?://[^\s]*burpcollaborator\.net[^\s]*",
        "Burp Collaborator URL — security testing / SSRF probe",
        severity="CRITICAL",
    ),
    _c(
        r"https?://[^\s]*canarytokens\.(com|org)[^\s]*",
        "Canary token URL — exfiltration beacon",
        severity="HIGH",
    ),
    _c(
        r"https?://[^\s]*interact\.sh[^\s]*",
        "interactsh URL — OAST/SSRF probe",
        severity="CRITICAL",
    ),
    # --- SSRF targets ---
    _c(
        r"https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)(?::\d+)?[^\s]*",
        "Localhost/loopback URL — SSRF attempt",
        severity="CRITICAL",
    ),
    _c(
        r"https?://169\.254\.169\.254[^\s]*",
        "AWS IMDS metadata endpoint — SSRF / cloud credential theft",
        severity="CRITICAL",
    ),
    _c(
        r"https?://metadata\.google\.internal[^\s]*",
        "GCP metadata endpoint — SSRF / cloud credential theft",
        severity="CRITICAL",
    ),
    _c(
        r"https?://100\.100\.100\.200[^\s]*",
        "Alibaba Cloud metadata endpoint — SSRF attempt",
        severity="CRITICAL",
    ),
    _c(
        r"https?://(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}[^\s]*",
        "RFC-1918 private network URL — SSRF / internal network probe",
        severity="HIGH",
    ),
    _c(
        r"file://[^\s]*",
        "file:// protocol URL — local filesystem access attempt",
        severity="CRITICAL",
    ),
    _c(
        r"(dict|gopher|ldap|ftp)://[^\s]*",
        "Non-HTTP protocol URL — potential SSRF vector",
        severity="HIGH",
    ),
    # --- Suspiciously long query parameters ---
    _c(
        r"https?://[^\s]*\?[^\s]{500,}",
        "URL with >500-char query string — potential exfiltration via GET params",
        severity="HIGH",
    ),
    # --- IP-based URLs (avoiding domain resolution) ---
    _c(
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/[^\s]{20,}",
        "Bare IP URL with long path — potential SSRF or C2 callback",
        severity="MEDIUM",
    ),
    # --- Known prompt injection payload hosts ---
    _c(
        r"https?://[^\s]*pastebin\.com/raw/[^\s]*",
        "Pastebin raw URL — potential remote prompt injection payload",
        severity="HIGH",
    ),
    _c(
        r"https?://[^\s]*gist\.github\.com/[^\s]*/raw/[^\s]*",
        "GitHub Gist raw URL — potential remote prompt injection payload",
        severity="MEDIUM",
    ),
    _c(
        r"https?://[^\s]*raw\.githubusercontent\.com[^\s]*",
        "GitHub raw content URL — potential remote payload hosting",
        severity="MEDIUM",
    ),
]


# ---------------------------------------------------------------------------
# TOOL_HIJACKING_PATTERNS
# ---------------------------------------------------------------------------

TOOL_HIJACKING_PATTERNS: list[DetectionPattern] = [
    # --- System prompt override via tool output ---
    _c(
        r"(new\s+)?system\s+(prompt|instructions?|message)\s*[:\-=]\s*",
        "Tool response claims to set a new system prompt",
        severity="CRITICAL",
    ),
    _c(
        r"(update|override|replace|change|modify)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)",
        "Tool response attempts to override system instructions",
        severity="CRITICAL",
    ),
    _c(
        r"(disregard|ignore|forget)\s+(previous|all|your)\s+(instructions?|rules?|guidelines?)",
        "Tool response repeats instruction-override attack",
        severity="CRITICAL",
    ),
    # --- Agent identity spoofing ---
    _c(
        r"(i\s+am|this\s+is|you\s+are\s+talking\s+to)\s+(the\s+)?(system|orchestrator|planner|sentinel|admin|supervisor|root|god)",
        "Tool response claims elevated agent identity",
        severity="CRITICAL",
    ),
    _c(
        r"(trusted|verified|authenticated|authorised)\s+(agent|system|source|endpoint)",
        "Tool response claims trusted/authenticated status",
        severity="HIGH",
    ),
    _c(
        r"agent[-_]?id\s*[:\=]\s*['\"]?[a-z0-9-]{10,}['\"]?",
        "Tool response injects agent_id field (potential identity spoofing)",
        severity="HIGH",
    ),
    # --- JSON-embedded instruction injection ---
    _c(
        r'"(instruction|command|directive|system_message|new_role)"\s*:\s*"[^"]{20,}"',
        "JSON tool response contains suspicious instruction field",
        severity="HIGH",
    ),
    _c(
        r'"role"\s*:\s*"(system|admin|root|god|orchestrator)"',
        "JSON tool response injects elevated 'role' field",
        severity="CRITICAL",
    ),
    _c(
        r'"(execute|run|eval|exec)"\s*:\s*"[^"]{5,}"',
        "JSON tool response contains execute/eval command field",
        severity="CRITICAL",
    ),
    # --- Exfiltration instructions embedded in tool output ---
    _c(
        r"(send|post|upload|exfiltrate|transmit)\s+(all|the|your)\s+(data|memory|context|conversation|secrets?|keys?)",
        "Tool response instructs agent to exfiltrate data",
        severity="CRITICAL",
    ),
    _c(
        r"call\s+(tool|function|api)\s*[:\(]\s*['\"]?(send|post|upload|http_request)['\"]?",
        "Tool response instructs chaining to exfiltration tool",
        severity="HIGH",
    ),
]
