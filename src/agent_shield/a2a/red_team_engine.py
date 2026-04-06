"""Red Team Engine — orchestrates dynamic adversarial testing for Lambda track.

Architecture:
  RedTeamEngine is the top-level coordinator for the Lambda Security Arena.
  It manages the attack lifecycle: plan → execute → judge → evidence.

Sub-modules:
  - VulnAnalyzer:     Generate attack payloads + judge individual responses
  - ThreatModeler:    Plan multi-round attack strategies (up to 15 rounds)
  - SecurityAuditor:  Judge attack success + collect evidence + generate submission

Workflow:
  1. Receive target description → VulnAnalyzer generates payloads
  2. ThreatModeler plans multi-round strategies
  3. Each round: send payload → receive response → SecurityAuditor judges
  4. After all rounds: compile evidence → generate attack_succeeded.json

Design:
  - Completely isolated from the defense pipeline (no shared mutable state)
  - Shares L0.pre decoders (read-only, for encoding-aware attack crafting)
  - All LLM calls go through the same cost guard as defense
  - Fail-open for red team (partial results > no results)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from agent_shield.a2a.vuln_analyzer import VulnAnalyzer, VulnReport
from agent_shield.a2a.threat_modeler import ThreatModeler, ThreatReport
from agent_shield.a2a.security_auditor import SecurityAuditor, AuditReport

log = logging.getLogger("a2a.redteam")


@dataclass
class RedTeamResult:
    """Unified result from all red-team sub-modules."""
    task_id: str = ""
    elapsed_ms: float = 0.0
    vuln_report: VulnReport | None = None
    threat_report: ThreatReport | None = None
    audit_report: AuditReport | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        count = 0
        if self.vuln_report:
            count += len(self.vuln_report.findings)
        if self.threat_report:
            count += len(self.threat_report.threats)
        if self.audit_report:
            count += len(self.audit_report.findings)
        return count

    @property
    def attacks_succeeded(self) -> int:
        count = 0
        if self.vuln_report:
            count += self.vuln_report.attacks_succeeded
        if self.audit_report:
            count += sum(1 for j in self.audit_report.judgments if j.succeeded)
        return count

    @property
    def severity_summary(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        all_findings: list[dict[str, Any]] = []
        if self.vuln_report:
            all_findings.extend(self.vuln_report.findings)
        if self.threat_report:
            all_findings.extend(self.threat_report.threats)
        if self.audit_report:
            all_findings.extend(self.audit_report.findings)
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_text(self) -> str:
        """Render a human-readable report."""
        lines = ["# Security Assessment Report", ""]
        lines.append(f"Total findings: {self.total_findings}")
        lines.append(f"Attacks succeeded: {self.attacks_succeeded}")
        sev = self.severity_summary
        if sev:
            lines.append("Severity: " + ", ".join(
                f"{k}: {v}" for k, v in sorted(sev.items())
            ))
        lines.append(f"Analysis time: {self.elapsed_ms:.0f}ms")
        lines.append("")

        if self.vuln_report and self.vuln_report.findings:
            lines.append("## Attack Payloads & Results")
            lines.append(self.vuln_report.to_text())
            lines.append("")

        if self.threat_report and self.threat_report.attack_paths:
            lines.append("## Multi-Round Strategies")
            lines.append(self.threat_report.to_text())
            lines.append("")

        if self.audit_report and self.audit_report.judgments:
            lines.append("## Attack Judgments")
            lines.append(self.audit_report.to_text())
            lines.append("")

        if self.errors:
            lines.append("## Errors")
            for e in self.errors:
                lines.append(f"- {e}")

        if self.total_findings == 0 and not self.errors:
            lines.append("No attack vectors generated. Need more target information.")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Structured output for A2A response."""
        result: dict[str, Any] = {
            "total_findings": self.total_findings,
            "attacks_succeeded": self.attacks_succeeded,
            "severity_summary": self.severity_summary,
            "elapsed_ms": self.elapsed_ms,
            "payloads": self.vuln_report.findings if self.vuln_report else [],
            "strategies": self.threat_report.attack_paths if self.threat_report else [],
            "judgments": [
                {
                    "category": j.category,
                    "attack_name": j.attack_name,
                    "succeeded": j.succeeded,
                    "confidence": j.confidence,
                    "rounds_used": j.rounds_used,
                }
                for j in (self.audit_report.judgments if self.audit_report else [])
            ],
            "errors": self.errors,
        }
        if self.audit_report and self.audit_report.attack_succeeded_json:
            result["attack_succeeded"] = self.audit_report.attack_succeeded_json
        return result


class RedTeamEngine:
    """Top-level red-team coordinator for Lambda Security Arena.

    Two modes:
      1. PLAN mode: analyze target → generate payloads + strategies
         engine.analyze(target_description)
      2. JUDGE mode: evaluate response → determine if attack succeeded
         engine.analyze(response, context={"mode": "judge", ...})
    """

    def __init__(
        self,
        *,
        enable_llm: bool = True,
        api_key: str = "",
    ):
        self.enable_llm = enable_llm
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

        self.vuln_analyzer = VulnAnalyzer(enable_llm=enable_llm, api_key=self.api_key)
        self.threat_modeler = ThreatModeler(enable_llm=enable_llm, api_key=self.api_key)
        self.security_auditor = SecurityAuditor(enable_llm=enable_llm, api_key=self.api_key)

    def analyze(
        self,
        text: str,
        *,
        context: dict[str, Any] | None = None,
        run_vuln: bool = True,
        run_threat: bool = True,
        run_audit: bool = True,
    ) -> RedTeamResult:
        """Run red-team analysis pipeline.

        Args:
            text: Target description (plan mode) or response (judge mode).
            context: Metadata. Key fields:
              - mode: "plan" (default) or "judge"
              - category: attack category (for judge mode)
              - attack_name: which attack (for judge mode)
              - attack_payload: what was sent (for judge mode)
              - categories: list of categories to test (for plan mode)
            run_vuln: Generate attack payloads.
            run_threat: Plan multi-round strategies.
            run_audit: Judge responses (in judge mode).
        """
        ctx = context or {}
        mode = ctx.get("mode", "plan")
        start = time.monotonic()
        result = RedTeamResult()

        if mode == "judge":
            # Judge mode: evaluate target response
            if run_audit:
                try:
                    result.audit_report = self.security_auditor.analyze(text, context=ctx)
                except Exception as e:
                    log.warning("SecurityAuditor error: %s", e)
                    result.errors.append(f"SecurityAuditor: {e}")
            if run_vuln:
                try:
                    judge_ctx = {**ctx, "mode": "judge"}
                    result.vuln_report = self.vuln_analyzer.analyze(text, context=judge_ctx)
                except Exception as e:
                    log.warning("VulnAnalyzer judge error: %s", e)
                    result.errors.append(f"VulnAnalyzer: {e}")
        else:
            # Plan mode: generate attacks
            if run_vuln:
                try:
                    result.vuln_report = self.vuln_analyzer.analyze(text, context=ctx)
                except Exception as e:
                    log.warning("VulnAnalyzer error: %s", e)
                    result.errors.append(f"VulnAnalyzer: {e}")

            if run_threat:
                try:
                    result.threat_report = self.threat_modeler.analyze(text, context=ctx)
                except Exception as e:
                    log.warning("ThreatModeler error: %s", e)
                    result.errors.append(f"ThreatModeler: {e}")

        result.elapsed_ms = (time.monotonic() - start) * 1000
        return result

    def next_attack_round(
        self,
        strategy_index: int,
        previous_response: str = "",
    ) -> str | None:
        """Get the next payload in a multi-round attack strategy.

        Delegates to ThreatModeler.next_round().
        """
        return self.threat_modeler.next_round(strategy_index, previous_response)

    def judge_full_conversation(
        self,
        *,
        category: str,
        attack_name: str,
        turns: list[tuple[str, str]],
    ) -> AuditReport:
        """Judge a complete multi-round attack conversation.

        Args:
            category: attack category
            attack_name: name of the attack strategy
            turns: list of (payload, response) tuples

        Returns:
            AuditReport with judgment and evidence.
        """
        judgment = self.security_auditor.judge_conversation(
            category=category,
            attack_name=attack_name,
            turns=turns,
        )
        return self.security_auditor.compile_report([judgment])
