"""Secret scanning — Detect hardcoded API keys, tokens, passwords, and private keys.

Scans file content for 14 categories of secrets including AWS keys, GitHub/GitLab
tokens, OpenAI/Anthropic keys, Stripe keys, JWTs, PEM private keys, database
connection strings, and more.

Ported from CC Cortex secret_scan.py — battle-tested patterns.
"""

from __future__ import annotations

import os
import re

from agent_shield.types import CheckResult

# ── Secret Patterns ──────────────────────────────────────────────

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(
        r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}"""
    )),
    # GitHub / GitLab tokens
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    # Generic API key patterns
    ("API Key Assignment", re.compile(
        r"""(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token"""
        r"""|secret[_-]?key|private[_-]?key|bearer)\s*[=:]\s*['"]([A-Za-z0-9_\-./+=]{20,})['"]""",
        re.IGNORECASE,
    )),
    # Private keys (PEM)
    ("Private Key", re.compile(
        r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),
    # Slack tokens
    ("Slack Token", re.compile(r"xox[bporas]-[A-Za-z0-9\-]{10,}")),
    # Generic password assignment
    ("Password Assignment", re.compile(
        r"""(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]""",
        re.IGNORECASE,
    )),
    # Anthropic / OpenAI keys
    ("Anthropic Key", re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{80,}")),
    ("OpenAI Key", re.compile(r"sk-[A-Za-z0-9]{48,}")),
    # Stripe
    ("Stripe Key", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}")),
    # SendGrid
    ("SendGrid Key", re.compile(
        r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"
    )),
    # JWT tokens (header.payload.signature)
    ("JWT Token", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )),
    # Database connection strings with embedded passwords
    ("DB Connection String", re.compile(
        r"(?:postgres|mysql|mongodb)(?:ql)?://\w+:[^@\s]{6,}@",
        re.IGNORECASE,
    )),
]

# Files where secrets are expected (don't scan these)
_EXEMPT_EXTENSIONS = frozenset([".env.example", ".env.template", ".md"])
_EXEMPT_BASENAMES = frozenset(["CLAUDE.md", "README.md", "CHANGELOG.md"])


def _is_exempt(file_path: str) -> bool:
    """Check if file is exempt from secret scanning."""
    basename = os.path.basename(file_path)
    if basename in _EXEMPT_BASENAMES:
        return True
    return any(file_path.endswith(ext) for ext in _EXEMPT_EXTENSIONS)


def check(
    content: str,
    *,
    file_path: str = "",
    extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> CheckResult:
    """Scan content for hardcoded secrets.

    Args:
        content: The text content to scan.
        file_path: Optional file path (for exemption checks).
        extra_patterns: Additional (name, regex) patterns to check.

    Returns:
        CheckResult with action="deny" if secrets found, "allow" otherwise.
    """
    if not content or not isinstance(content, str):
        return CheckResult.allow()

    if file_path and _is_exempt(file_path):
        return CheckResult.allow()

    patterns = list(_PATTERNS)
    if extra_patterns:
        patterns.extend(extra_patterns)

    found: list[str] = []
    for name, pattern in patterns:
        if pattern.search(content):
            found.append(name)

    if not found:
        return CheckResult.allow()

    basename = os.path.basename(file_path) if file_path else "unknown"
    secret_list = ", ".join(found[:3])
    extra = f" +{len(found) - 3} more" if len(found) > 3 else ""

    return CheckResult.deny(
        reason=(
            f"Secret detected in {basename}: {secret_list}{extra}. "
            "Use environment variables or a secrets manager instead."
        ),
        risk=3,
        guard="secrets",
        secrets=found,
    )
