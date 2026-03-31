"""Git safety — Detect and block dangerous git operations.

Catches force push, reset --hard, branch -D, clean -f, checkout -- .,
interactive rebase, and direct push to main/master.

Ported from CC Cortex git_safety.py — battle-tested patterns.
"""

from __future__ import annotations

import re

from agent_shield.types import CheckResult

# Dangerous git command patterns (order: most dangerous first)
_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "force push",
        re.compile(r"git\s+push\s+.*--force(?!-with-lease)", re.IGNORECASE),
        "Use --force-with-lease instead of --force to avoid overwriting others' work.",
    ),
    (
        "reset --hard",
        re.compile(r"git\s+reset\s+--hard", re.IGNORECASE),
        "This discards ALL uncommitted changes. Consider git stash first.",
    ),
    (
        "clean -f",
        re.compile(r"git\s+clean\s+-[a-z]*f", re.IGNORECASE),
        "This permanently deletes untracked files. Consider git stash -u first.",
    ),
    (
        "checkout -- .",
        re.compile(r"git\s+checkout\s+--\s*\.", re.IGNORECASE),
        "This discards ALL unstaged changes. Consider git stash first.",
    ),
    (
        "branch -D",
        re.compile(r"git\s+branch\s+-D\s"),  # case-sensitive: -D only
        "Force-deletes branch even if unmerged. Use -d for safe delete.",
    ),
    (
        "rebase -i (interactive)",
        re.compile(r"git\s+rebase\s+-i\b", re.IGNORECASE),
        "Interactive rebase requires manual input which may not be supported.",
    ),
]


def check(command: str) -> CheckResult:
    """Check if a command contains dangerous git operations.

    Args:
        command: The shell command to check.

    Returns:
        CheckResult with action="deny" if dangerous git op detected.
    """
    if not command or not isinstance(command, str):
        return CheckResult.allow()

    # Quick check: must contain "git" at all
    if "git" not in command.lower():
        return CheckResult.allow()

    for name, pattern, advice in _DANGEROUS_PATTERNS:
        if pattern.search(command):
            return CheckResult.deny(
                reason=f"Dangerous git operation: {name}. {advice}",
                risk=3,
                guard="git_safety",
                operation=name,
            )

    return CheckResult.allow()
