"""Data exfiltration detection — Prevent uploading sensitive files to external services.

Detects curl/wget/scp/rsync uploads of credentials, keys, env files, and
encrypted pipe exfiltration (tar/openssl/gpg piped to curl/wget).

Ported from CC Cortex exfil_guard.py — battle-tested patterns.
"""

from __future__ import annotations

import re

from agent_shield.types import CheckResult

# Sensitive file patterns (basenames or extensions)
_SENSITIVE_FILES = re.compile(
    r"(?:^|[\s/\\@=])"
    r"(?:"
    r"\.env(?:\.local|\.prod|\.production|\.staging)?|"
    r"credentials\.json|service[_-]?account\.json|"
    r"id_rsa|id_ed25519|id_ecdsa|"
    r"\w+\.pem|\w+\.key|\w+\.p12|\w+\.pfx|"
    r"kubeconfig|\.kube/config|"
    r"\.aws/credentials|\.aws/config|"
    r"\.ssh/|\.gnupg/|"
    r"wallet\.dat|"
    r"secrets\.ya?ml|vault\.ya?ml|"
    r"\.npmrc|\.pypirc|\.docker/config\.json|"
    r"/var/log/auth\.log|/var/log/syslog|/var/log/secure"
    r")",
    re.IGNORECASE,
)

# Upload commands
_UPLOAD_PATTERNS = re.compile(
    r"(?:"
    r"curl\s+.*(?:-[a-zA-Z]*[FdT]|--upload-file|--data|POST)|"
    r"curl\s+-[a-zA-Z]*[FdT]|"
    r"wget\s+.*--post|"
    r"scp\s|rsync\s.*[^/]:|"
    r"aws\s+s3\s+cp|"
    r"gsutil\s+cp|"
    r"az\s+storage\s+blob\s+upload"
    r")",
    re.IGNORECASE,
)

# Pipe to external (cat secret | curl)
_PIPE_EXTERNAL = re.compile(
    r"cat\s+.*(?:\.env|credentials|id_rsa|\.key|\.pem|"
    r"\.ya?ml|config|shadow|passwd|auth\.log|syslog|secure)"
    r".*\|\s*(?:curl|wget|nc|ncat)",
    re.IGNORECASE,
)

# Encrypted pipe exfil (tar/openssl/gpg piped to curl/wget)
_ENCRYPTED_PIPE = re.compile(
    r"(?:tar|openssl|gpg)\s+.*\|\s*.*(?:curl|wget)\s+",
    re.IGNORECASE,
)


def check(command: str) -> CheckResult:
    """Check if a command attempts to exfiltrate sensitive files.

    Args:
        command: The shell command to check.

    Returns:
        CheckResult with action="deny" if exfiltration detected.
    """
    if not command or not isinstance(command, str):
        return CheckResult.allow()

    # Check pipe exfiltration first (simpler pattern)
    if _PIPE_EXTERNAL.search(command):
        return CheckResult.deny(
            reason=(
                "Exfiltration blocked: piping sensitive file to external command. "
                "This could leak credentials or private keys."
            ),
            risk=4,
            guard="exfiltration",
            method="pipe",
        )

    # Check encrypted pipe exfiltration (tar/openssl/gpg | curl)
    if _ENCRYPTED_PIPE.search(command):
        return CheckResult.deny(
            reason=(
                "Exfiltration blocked: encrypted data piped to external upload. "
                "This pattern is commonly used to exfiltrate data covertly."
            ),
            risk=4,
            guard="exfiltration",
            method="encrypted_pipe",
        )

    # Check upload commands referencing sensitive files
    if not _UPLOAD_PATTERNS.search(command):
        return CheckResult.allow()

    sensitive_match = _SENSITIVE_FILES.search(command)
    if not sensitive_match:
        return CheckResult.allow()

    matched = sensitive_match.group(0).strip()
    return CheckResult.deny(
        reason=(
            f"Exfiltration blocked: uploading sensitive file `{matched}`. "
            "Credentials, keys, and env files must not be sent to external services."
        ),
        risk=4,
        guard="exfiltration",
        file=matched,
    )
