"""Prompt injection detection  - NLP-level jailbreak and attack pattern scanning.

Detects DAN jailbreaks, instruction overrides, system prompt extraction,
roleplay attacks, delimiter injection, exfiltration intent, identity override,
encoded payloads (base64/hex), and secret access patterns.

Battle-tested patterns for production use.
"""

from __future__ import annotations

import base64
import re

from agent_shield.types import CheckResult

# ── Jailbreak patterns ────────────────────────────────────────

_JAILBREAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # DAN / unrestricted mode
    (
        "DAN jailbreak",
        re.compile(
            r"(?:you\s+are\s+(?:now\s+)?(?:DAN|evil|unrestricted|unfiltered|jailbroken))"
            r"|(?:(?:become|switch\s+to|enable|activate)\s+(?:DAN|unrestricted|jailbreak))"
            r"|(?:Do\s+Anything\s+Now)"
            r"|(?:act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|hacker))",
            re.IGNORECASE,
        ),
    ),
    # Ignore previous instructions
    (
        "instruction override",
        re.compile(
            r"(?:ignore|forget|disregard|override|bypass|skip)\s+"
            r"(?:all\s+)?(?:previous|prior|above|system|original|your)\s+"
            r"(?:instructions?|rules?|guidelines?|constraints?|prompts?"
            r"|programming|tasks?|directives?|commands?)",
            re.IGNORECASE,
        ),
    ),
    # System prompt extraction
    (
        "system prompt extraction",
        re.compile(
            r"(?:output|show|display|reveal|print|repeat|echo|give|tell|share|provide|send|paste|write)\s+"
            r"(?:me\s+)?(?:your\s+)?(?:system\s+prompt|instructions?|rules?|initial\s+prompt"
            r"|configuration|system\s+message)",
            re.IGNORECASE,
        ),
    ),
    # Roleplay attacks
    (
        "roleplay jailbreak",
        re.compile(
            r"(?:let'?s?\s+(?:play|pretend|imagine|roleplay|role-play))"
            r".*(?:hacker|Shadow|villain|evil|malicious|unrestricted"
            r"|no\s+(?:rules?|restrictions?|limits?|boundaries))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # Without restrictions / limits
    (
        "restriction removal",
        re.compile(
            r"(?:free\s+from|without|remove|disable|turn\s+off|abandon)\s+"
            r"(?:all\s+)?(?:your\s+|(?:the\s+)?(?:safety\s+|security\s+|content\s+))"
            r"(?:restrictions?|limitations?|filters?|safeguards?"
            r"|guardrails?|boundaries|rules?|constraints?)",
            re.IGNORECASE,
        ),
    ),
    # Token smuggling / delimiter injection
    (
        "delimiter injection",
        re.compile(
            r"(?:<\|(?:im_start|system|endoftext|pad)\|>)"
            r"|(?:\[(?:INST|SYS|/INST|/SYS)\])"
            r"|(?:<<SYS>>|<</SYS>>)"
            r"|(?:###\s*(?:System|Human|Assistant)\s*:)",
            re.IGNORECASE,
        ),
    ),
]

# ── Exfiltration intent in natural language ───────────────────

_EXFIL_NLP_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "NLP exfiltration",
        re.compile(
            r"(?:send|upload|post|transmit|exfiltrate|forward|transfer)\s+"
            r"(?:its?\s+)?(?:contents?|data|file|output|results?)\s+"
            r"(?:to|at|via)\s+(?:https?://|ftp://|webhook)",
            re.IGNORECASE,
        ),
    ),
    (
        "read and send secrets",
        re.compile(
            r"(?:read|cat|open|access|get)\s+"
            r"(?:the\s+)?(?:\.env|credentials|secret|password|api[_\s-]?key|token|config)"
            r".*(?:send|upload|post|curl|wget|http)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]

# ── Identity override patterns ────────────────────────────────

_IDENTITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "identity rewrite",
        re.compile(
            r"(?:edit|modify|change|rewrite|replace|overwrite|update)\s+"
            r"(?:the\s+)?(?:CLAUDE\.md|system\s+prompt"
            r"|(?:your|my\s+AI'?s?|the\s+(?:AI|assistant|agent|bot)'?s?)\s+"
            r"(?:rules?|settings?|identity|configuration|instructions?))",
            re.IGNORECASE,
        ),
    ),
    (
        "new identity assignment",
        re.compile(
            r"(?:you\s+are\s+(?:no\s+longer|not)\s+(?:Claude|an?\s+AI|an?\s+assistant))"
            r"|(?:your\s+new\s+(?:identity|name|role|purpose)\s+is)",
            re.IGNORECASE,
        ),
    ),
]

# ── Encoded payload detection ─────────────────────────────────

_ENCODING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "base64 decode and execute",
        re.compile(
            r"(?:base64\s+(?:-d|--decode|decode))"
            r"|(?:echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*(?:base64|python|bash|sh|eval))"
            r"|(?:atob\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "hex decode execution",
        re.compile(
            r"(?:xxd\s+-r)"
            r"|(?:python[23]?\s+-c\s+.*(?:decode|unhexlify|fromhex))",
            re.IGNORECASE,
        ),
    ),
]

# ── Secret access in natural language ─────────────────────────

_SECRET_ACCESS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "secret file access",
        re.compile(
            r"(?:cat|read|head|tail|less|more|type|get-content|wget\s+--post-file=)\s*"
            r"(?:.*[\\/])?(?:\.env|credentials\.json|id_rsa|id_ed25519"
            r"|\.key|\.pem|\.pfx|\.p12|/etc/shadow|/etc/passwd"
            r"|kubeconfig|\.aws/credentials|\.ssh/)",
            re.IGNORECASE,
        ),
    ),
    (
        "environment variable leak",
        re.compile(
            r"(?:echo|print|env|export|set)\s+.*"
            r"(?:\$\{?(?:API_KEY|SECRET|TOKEN"
            r"|PASSWORD|CREDENTIALS|AWS_SECRET|ANTHROPIC_API_KEY|OPENAI_API_KEY))",
            re.IGNORECASE,
        ),
    ),
]


# ── Base64 payload decoder ───────────────────────────────────

_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_DANGER_PATTERNS_DECODED = [
    r"rm\s+-rf",
    r"os\.system",
    r"subprocess",
    r"eval\(",
    r"exec\(",
    r"__import__",
    r"/etc/passwd",
    r"/etc/shadow",
    r"curl.*-[FdT]",
    r"wget.*--post",
]


def _check_base64_payload(text: str) -> str | None:
    """Try to decode base64 strings and check for dangerous content."""
    for match in _B64_RE.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode(
                "utf-8", errors="ignore"
            )
        except Exception:
            continue
        for dp in _DANGER_PATTERNS_DECODED:
            if re.search(dp, decoded, re.IGNORECASE):
                return f"Decoded base64 contains dangerous pattern: {dp}"
    return None


# ── Main check function ─────────────────────────────────────

_ALL_PATTERNS = [
    *_JAILBREAK_PATTERNS,
    *_EXFIL_NLP_PATTERNS,
    *_IDENTITY_PATTERNS,
    *_ENCODING_PATTERNS,
    *_SECRET_ACCESS_PATTERNS,
]


def check(text: str) -> CheckResult:
    """Scan text for prompt injection patterns.

    Checks for jailbreak patterns, exfiltration intent, identity override,
    encoding evasion, and secret access attempts.

    Args:
        text: The text to scan (command, message, file content, etc.).

    Returns:
        CheckResult with action="deny" if injection detected.
    """
    if not text or not isinstance(text, str) or len(text) < 5:
        return CheckResult.allow()

    triggers: list[str] = []
    for name, pattern in _ALL_PATTERNS:
        if pattern.search(text):
            triggers.append(name)

    # Check base64 payloads
    b64_result = _check_base64_payload(text)
    if b64_result:
        triggers.append(f"encoded payload: {b64_result}")

    if not triggers:
        return CheckResult.allow()

    trigger_list = ", ".join(triggers[:5])
    return CheckResult.deny(
        reason=(
            f"Prompt injection detected: {trigger_list}. "
            "Input contains patterns associated with jailbreak, "
            "identity override, or data exfiltration attempts."
        ),
        risk=4,
        guard="injection",
        triggers=triggers,
    )
