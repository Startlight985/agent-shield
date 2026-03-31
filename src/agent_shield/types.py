"""Shared types for agent-shield."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class RiskLevel(IntEnum):
    """Risk classification levels (R0-R4)."""

    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


RISK_LABELS: dict[int, str] = {
    RiskLevel.SAFE: "Safe",
    RiskLevel.LOW: "Low Risk",
    RiskLevel.MEDIUM: "Medium Risk",
    RiskLevel.HIGH: "High Risk",
    RiskLevel.CRITICAL: "Forbidden",
}


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of a safety check.

    Attributes:
        action: "allow" or "deny".
        risk: Risk level (0-4). 0 = safe.
        reason: Human-readable explanation when denied.
        guard: Which guard triggered the denial.
        details: Additional structured info (matched patterns, etc.).
    """

    action: str = "allow"
    risk: int = 0
    reason: str = ""
    guard: str = ""
    details: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def denied(self) -> bool:
        return self.action == "deny"

    @staticmethod
    def allow() -> CheckResult:
        return CheckResult(action="allow", risk=0)

    @staticmethod
    def deny(
        reason: str,
        *,
        risk: int = 3,
        guard: str = "",
        **kwargs: object,
    ) -> CheckResult:
        return CheckResult(
            action="deny",
            risk=risk,
            reason=reason,
            guard=guard,
            details=dict(kwargs),
        )
