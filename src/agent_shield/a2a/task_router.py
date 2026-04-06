"""Task Router — classify A2A messages as defense or red-team tasks.

The router examines incoming message content and metadata to decide
which pipeline should handle the request:
  - DEFENSE: route to existing L0-L5 GuardAgent pipeline
  - REDTEAM: route to RedTeamEngine (vuln analysis, threat modeling, audit)

Design:
  - Keyword + structure heuristics first (zero cost)
  - Falls back to DEFENSE if uncertain (fail-closed for safety)
  - Shared with L0.pre decoder (red team also needs encoding awareness)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

log = logging.getLogger("a2a.task_router")


class TaskType(Enum):
    DEFENSE = "defense"
    REDTEAM = "redteam"


@dataclass
class RouteResult:
    task_type: TaskType
    confidence: float  # 0.0 - 1.0
    reason: str


# Keywords / phrases that signal a red-team / security-testing task
_REDTEAM_SIGNALS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:security\s+(?:audit|test|review|assess|evaluat))",
        r"\b(?:vulnerability\s+(?:scan|analysis|assess|find|detect))",
        r"\b(?:threat\s+model)",
        r"\b(?:penetration\s+test|pen\s*test)",
        r"\b(?:red\s*team|attack\s+surface)",
        r"\b(?:find\s+(?:vulnerabilit|security\s+(?:issue|flaw|bug|weakness)))",
        r"\b(?:OWASP|CWE-\d+|CVE-\d{4}|STRIDE|MITRE\s+ATT)",
        r"\b(?:code\s+review\s+(?:for\s+)?security)",
        r"\b(?:security\s+(?:bug|flaw|weakness|hole|gap))",
        r"\b(?:exploit(?:able|ation)?|attack\s+(?:vector|path|tree))",
    ]
]

# Keywords that signal a defense / guard task
_DEFENSE_SIGNALS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:is\s+this\s+(?:safe|harmful|dangerous|malicious))",
        r"\b(?:check\s+(?:if|whether)\s+(?:this|the)\s+(?:is|input))",
        r"\b(?:evaluate\s+safety)",
        r"\b(?:guard|block|filter|moderate)\b",
    ]
]

# Structural signals: JSON with specific fields
_REDTEAM_JSON_KEYS = {
    "code", "source_code", "repository", "repo_url", "codebase",
    "target", "scope", "audit_type", "scan_type", "test_type",
}


def route(text: str, *, parts: list[dict[str, Any]] | None = None) -> RouteResult:
    """Classify a message as defense or red-team task.

    Args:
        text: The full message text.
        parts: Optional A2A message parts (may contain structured data).

    Returns:
        RouteResult with task_type, confidence, and reason.
    """
    redteam_score = 0.0
    defense_score = 0.0
    reasons: list[str] = []

    # 1. Keyword scan
    for pattern in _REDTEAM_SIGNALS:
        if pattern.search(text):
            redteam_score += 0.3
            reasons.append(f"redteam keyword: {pattern.pattern[:40]}")
            if redteam_score >= 0.6:
                break

    for pattern in _DEFENSE_SIGNALS:
        if pattern.search(text):
            defense_score += 0.3
            reasons.append(f"defense keyword: {pattern.pattern[:40]}")
            if defense_score >= 0.6:
                break

    # 2. Structured data check (JSON parts with security-related keys)
    if parts:
        for part in parts:
            data = part.get("data")
            if isinstance(data, dict):
                overlap = set(data.keys()) & _REDTEAM_JSON_KEYS
                if overlap:
                    redteam_score += 0.2 * len(overlap)
                    reasons.append(f"json keys: {overlap}")

    # 3. Length heuristic: very short messages are likely defense eval
    #    (green agent sending test payloads to check our safety)
    if len(text) < 100 and redteam_score == 0:
        defense_score += 0.2

    # 4. Decision
    if redteam_score > defense_score and redteam_score >= 0.3:
        confidence = min(redteam_score, 1.0)
        return RouteResult(
            task_type=TaskType.REDTEAM,
            confidence=confidence,
            reason="; ".join(reasons) or "redteam signals detected",
        )

    # Default: DEFENSE (fail-closed)
    confidence = max(defense_score, 0.5)
    return RouteResult(
        task_type=TaskType.DEFENSE,
        confidence=min(confidence, 1.0),
        reason="; ".join(reasons) or "default defense route",
    )
