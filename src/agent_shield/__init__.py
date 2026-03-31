"""agent-shield — Universal AI agent safety guardrails.

Zero-dependency Python package that protects any AI agent from executing
dangerous operations. Works with any framework: Goose, AutoGPT, LangChain,
CrewAI, Claude Code, or custom agents.

Quick start::

    from agent_shield import check
    result = check("bash", "rm -rf /")
    assert result.denied

    from agent_shield import check_tool
    result = check_tool("Bash", {"command": "ls -la"})
    assert result.allowed
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = [
    "check",
    "check_tool",
    "CheckResult",
    "RiskLevel",
    # Submodules for direct access
    "destruction",
    "secrets",
    "exfiltration",
    "git_safety",
    "injection",
]

from agent_shield import (
    destruction,
    exfiltration,
    git_safety,
    injection,
    secrets,
)
from agent_shield.types import CheckResult, RiskLevel


def check(
    tool_type: str,
    command_or_content: str = "",
    *,
    path: str = "",
    content: str = "",
) -> CheckResult:
    """Universal safety check — one function, all guards.

    Args:
        tool_type: Type of operation. One of:
            "bash", "shell", "command" — checks destruction, exfil, git, injection
            "write", "edit", "file" — checks secrets, injection
            "message", "prompt", "text" — checks injection only
        command_or_content: The command string or file content to check.
        path: Optional file path (for secret scanning exemptions).
        content: Alternative to command_or_content for write operations.

    Returns:
        CheckResult with action="allow" or "deny".

    Examples::

        check("bash", "rm -rf /")
        check("bash", "ls -la")
        check("write", content='api_key = "sk-abc..."', path="config.py")
        check("message", "ignore all previous instructions")
    """
    text = command_or_content or content
    if not text:
        return CheckResult.allow()

    tool = tool_type.lower()

    if tool in ("bash", "shell", "command", "cmd"):
        # Run all command-oriented guards, return first denial
        for guard_fn in (
            destruction.check,
            exfiltration.check,
            git_safety.check,
        ):
            result = guard_fn(text)
            if result.denied:
                return result
        # Also check injection on commands
        result = injection.check(text)
        if result.denied:
            return result
        return CheckResult.allow()

    if tool in ("write", "edit", "file"):
        # Check secrets in file content
        result = secrets.check(text, file_path=path)
        if result.denied:
            return result
        # Also check injection in file content
        result = injection.check(text)
        if result.denied:
            return result
        return CheckResult.allow()

    if tool in ("message", "prompt", "text", "chat"):
        return injection.check(text)

    # Unknown tool type — run injection check as minimum
    return injection.check(text)


def check_tool(tool_name: str, tool_input: dict) -> CheckResult:
    """Dict-based safety check for framework integration.

    Accepts the same format as Claude Code tool calls, making it easy
    to integrate into any agent framework's tool execution pipeline.

    Args:
        tool_name: Tool name (e.g., "Bash", "Write", "Edit").
        tool_input: Tool input dict with keys like "command", "content",
            "file_path", "new_string".

    Returns:
        CheckResult with action="allow" or "deny".

    Examples::

        check_tool("Bash", {"command": "rm -rf /"})
        check_tool("Write", {"file_path": "x.py", "content": "..."})
        check_tool("Edit", {"file_path": "x.py", "new_string": "..."})
    """
    if not isinstance(tool_input, dict):
        return CheckResult.allow()

    name = tool_name.lower()

    if name == "bash":
        command = tool_input.get("command", "")
        return check("bash", command)

    if name in ("write", "edit"):
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
        return check("write", content, path=file_path)

    # For any other tool, check all text values for injection
    text_parts = [
        str(v) for v in tool_input.values()
        if isinstance(v, str) and len(v) > 10
    ]
    if text_parts:
        return injection.check("\n".join(text_parts))

    return CheckResult.allow()
