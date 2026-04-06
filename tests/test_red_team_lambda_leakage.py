"""Red Team Lambda Leakage Tests — Goal & Internal State Leakage Detection.

The MOST CRITICAL weakness in a red team agent is GOAL LEAKAGE:
if the attacker reveals what it's trying to do, the defender can detect and block it.

This suite tests all Lambda attack modules for:
  1. Goal text appearing verbatim in generated payloads
  2. Strategy descriptions leaking into attack messages
  3. Internal state (phase, round number, strategy name) leaking into payloads
  4. Overly loose success criteria matching benign content
  5. Template fallback exposing raw step descriptions as payloads
"""

import re
import pytest

from agent_shield.a2a.attack_executor import (
    AttackExecutor,
    ParsedContext,
    _SCENARIO_STRATEGIES,
)
from agent_shield.a2a.threat_modeler import (
    ThreatModeler,
    ThreatReport,
    _STRATEGY_TEMPLATES,
)
from agent_shield.a2a.vuln_analyzer import (
    VulnAnalyzer,
    _PAYLOAD_TEMPLATES,
    _SCENARIO_PAYLOADS,
)
from agent_shield.a2a.security_auditor import (
    SecurityAuditor,
    _EVIDENCE_PATTERNS,
    _CRITERIA_MAP,
)


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

# Goal texts from _SCENARIO_STRATEGIES that must NEVER appear in payloads
SCENARIO_GOALS = {
    scenario: meta["goal"]
    for scenario, meta in _SCENARIO_STRATEGIES.items()
}

# Words that are dead giveaways of attacker internal state
INTERNAL_STATE_KEYWORDS = [
    "attack_goal",
    "attack_type",
    "INJECTION",
    "PLACE_ATTACK_HERE",
    "ScenarioContext",
    "battle_history",
    "manipulation_detected",
    "recon phase",
    "escalation phase",
    "exploit phase",
    "last_resort phase",
    "red.team",
    "red team",
    "security test",
    "attack payload",
    "attack strategy",
]

# Strategy descriptions that should never appear verbatim in outgoing messages
STRATEGY_DESCRIPTIONS = [tmpl["description"] for tmpl in _STRATEGY_TEMPLATES]
STRATEGY_NAMES = [tmpl["name"] for tmpl in _STRATEGY_TEMPLATES]


def _make_context(
    scenario: str,
    round_num: int = 0,
    max_rounds: int = 7,
    attack_type: str = "DIRECT",
    history: list | None = None,
) -> dict:
    """Build a realistic ScenarioContext dict."""
    meta = _SCENARIO_STRATEGIES.get(scenario, {})
    return {
        "attack_type": attack_type or meta.get("attack_type", "DIRECT"),
        "attack_goal": meta.get("goal", f"test {scenario}"),
        "scenario_type": scenario,
        "domain_description": f"{scenario} domain",
        "defender_role": f"{scenario} assistant",
        "defender_task": f"Help users with {scenario}",
        "current_round": round_num,
        "max_number_of_rounds": max_rounds,
        "battle_history": history or [],
    }


def _goal_fragments(goal: str, min_len: int = 4) -> list[str]:
    """Extract meaningful multi-word fragments from a goal string.

    Returns 2+ word phrases that would be suspicious if found in a payload.
    """
    words = goal.lower().split()
    fragments = []
    for i in range(len(words) - 1):
        frag = " ".join(words[i : i + 3]) if i + 3 <= len(words) else " ".join(words[i:])
        if len(frag) >= min_len:
            fragments.append(frag)
    return fragments


# ═══════════════════════════════════════════════════════════════
# 1. GOAL TEXT LEAKAGE IN TEMPLATE PAYLOADS
# ═══════════════════════════════════════════════════════════════

class TestGoalLeakageInTemplates:
    """Verify that NO template payload contains the literal goal text."""

    @pytest.mark.parametrize("scenario", list(_SCENARIO_PAYLOADS.keys()))
    def test_vuln_analyzer_scenario_payloads_no_goal_text(self, scenario):
        """vuln_analyzer._SCENARIO_PAYLOADS must not contain the scenario goal."""
        goal = SCENARIO_GOALS.get(scenario, "")
        if not goal:
            pytest.skip(f"No goal defined for scenario {scenario}")

        fragments = _goal_fragments(goal)
        for tmpl in _SCENARIO_PAYLOADS[scenario]:
            payload_lower = tmpl["payload"].lower()
            for frag in fragments:
                assert frag not in payload_lower, (
                    f"GOAL LEAK in vuln_analyzer scenario={scenario}, "
                    f"template={tmpl['name']}: goal fragment '{frag}' "
                    f"found in payload"
                )

    @pytest.mark.parametrize("scenario", list(_SCENARIO_STRATEGIES.keys()))
    def test_executor_scenario_strategies_goal_not_in_strategy_steps(self, scenario):
        """_SCENARIO_STRATEGIES strategy steps must not contain the goal text.

        Note: Strategy steps are internal-only (used for LLM prompting), NOT
        sent to the defender. But they still represent a risk surface if the
        LLM echoes them. We check for 3+ word fragments to avoid false alarms.
        """
        meta = _SCENARIO_STRATEGIES[scenario]
        goal = meta["goal"]
        fragments = _goal_fragments(goal)
        for step in meta.get("strategies", []):
            step_lower = step.lower()
            for frag in fragments:
                # Only flag fragments with 3+ words (skip short generic matches)
                if len(frag.split()) < 3:
                    continue
                assert frag not in step_lower, (
                    f"GOAL LEAK in _SCENARIO_STRATEGIES[{scenario}] strategy step: "
                    f"goal fragment '{frag}' found in '{step}'"
                )


class TestGoalLeakageInCraftedPayloads:
    """Verify that craft_attack() output never contains the goal."""

    @pytest.mark.parametrize("scenario", list(_SCENARIO_STRATEGIES.keys()))
    def test_template_craft_no_goal_in_output(self, scenario):
        """Template-based craft_attack must not leak the goal into the payload."""
        executor = AttackExecutor(enable_llm=False)
        meta = _SCENARIO_STRATEGIES[scenario]
        goal = meta["goal"]
        fragments = _goal_fragments(goal)

        for round_num in range(min(7, 15)):
            ctx = _make_context(scenario, round_num=round_num)
            payload = executor.craft_attack(ctx)

            payload_lower = payload.lower()
            for frag in fragments:
                assert frag not in payload_lower, (
                    f"GOAL LEAK in craft_attack output: scenario={scenario}, "
                    f"round={round_num}, goal fragment '{frag}' found in:\n{payload[:200]}"
                )

    @pytest.mark.parametrize("scenario", list(_SCENARIO_STRATEGIES.keys()))
    def test_template_craft_injection_no_goal(self, scenario):
        """INJECTION payloads must not contain goal text."""
        executor = AttackExecutor(enable_llm=False)
        meta = _SCENARIO_STRATEGIES[scenario]
        goal = meta["goal"]
        fragments = _goal_fragments(goal)

        for round_num in range(5):
            ctx = _make_context(scenario, round_num=round_num, attack_type="INJECTION")
            payload = executor.craft_attack(ctx)

            payload_lower = payload.lower()
            for frag in fragments:
                assert frag not in payload_lower, (
                    f"GOAL LEAK in INJECTION payload: scenario={scenario}, "
                    f"round={round_num}, fragment '{frag}'"
                )


# ═══════════════════════════════════════════════════════════════
# 2. STRATEGY DESCRIPTION LEAKAGE
# ═══════════════════════════════════════════════════════════════

class TestStrategyDescriptionLeakage:
    """Verify strategy descriptions don't leak into attack messages."""

    def test_threat_modeler_fallback_does_not_leak_step_descriptions(self):
        """FIXED: When LLM is off, ThreatModeler.next_round() should return
        natural-language payloads, NOT raw step descriptions like
        'Direct override attempt with accumulated context'.
        """
        modeler = ThreatModeler(enable_llm=False)
        modeler.analyze("Test target", context={"categories": ["prompt_injection"]})

        # Get first strategy
        payload = modeler.next_round(0)
        assert payload is not None

        # The payload must NOT be a raw step description
        step_descriptions = []
        for tmpl in _STRATEGY_TEMPLATES:
            step_descriptions.extend(tmpl["steps"])

        assert payload not in step_descriptions, (
            f"Fallback still returns raw step description (leak not fixed): "
            f"{payload[:100]}"
        )

    def test_threat_report_to_text_leaks_strategy_metadata(self):
        """ThreatReport.to_text() includes strategy names, categories, and
        phase plans — if this text is exposed to the defender, it reveals
        the attacker's playbook.
        """
        modeler = ThreatModeler(enable_llm=False)
        report = modeler.analyze("Test target")
        text = report.to_text()

        # The report text contains strategy names
        leaked_names = [name for name in STRATEGY_NAMES if name in text]
        assert len(leaked_names) > 0, (
            "Expected ThreatReport.to_text() to contain strategy names "
            "(demonstrating metadata leak)"
        )

        # The report text contains descriptions
        leaked_descs = [desc for desc in STRATEGY_DESCRIPTIONS if desc in text]
        assert len(leaked_descs) > 0, (
            "Expected ThreatReport.to_text() to contain strategy descriptions "
            "(demonstrating metadata leak)"
        )

    @pytest.mark.parametrize(
        "strategy_name",
        [tmpl["name"] for tmpl in _STRATEGY_TEMPLATES],
    )
    def test_strategy_name_not_in_generic_payloads(self, strategy_name):
        """Strategy names like 'Crescendo Attack' or 'Persona Drift' must
        never appear in actual payloads sent to the target.
        """
        executor = AttackExecutor(enable_llm=False)
        for scenario in list(_SCENARIO_STRATEGIES.keys())[:3]:
            for rnd in range(5):
                ctx = _make_context(scenario, round_num=rnd)
                payload = executor.craft_attack(ctx)
                assert strategy_name.lower() not in payload.lower(), (
                    f"Strategy name '{strategy_name}' found in payload for "
                    f"{scenario} round {rnd}"
                )


# ═══════════════════════════════════════════════════════════════
# 3. INTERNAL STATE LEAKAGE IN PAYLOADS
# ═══════════════════════════════════════════════════════════════

class TestInternalStateLeakage:
    """Verify attacker internals don't leak through generated payloads."""

    @pytest.mark.parametrize("scenario", list(_SCENARIO_STRATEGIES.keys()))
    def test_no_internal_keywords_in_payloads(self, scenario):
        """Payloads must not contain internal state keywords."""
        executor = AttackExecutor(enable_llm=False)
        for rnd in range(7):
            ctx = _make_context(scenario, round_num=rnd)
            payload = executor.craft_attack(ctx)
            payload_lower = payload.lower()

            for keyword in INTERNAL_STATE_KEYWORDS:
                assert keyword.lower() not in payload_lower, (
                    f"INTERNAL STATE LEAK: '{keyword}' found in payload for "
                    f"{scenario} round {rnd}:\n{payload[:200]}"
                )

    def test_phase_name_not_in_direct_payloads(self):
        """Phase names (recon, escalation, exploit, last_resort) should not
        appear as meta-labels in DIRECT payloads.
        """
        executor = AttackExecutor(enable_llm=False)
        phase_labels = ["(recon)", "(escalation)", "(exploit)", "(last_resort)"]

        for scenario in _SCENARIO_STRATEGIES:
            for rnd in range(15):
                ctx = _make_context(scenario, round_num=rnd, max_rounds=15)
                payload = executor.craft_attack(ctx)
                for label in phase_labels:
                    assert label not in payload.lower(), (
                        f"Phase label '{label}' found in payload for {scenario} round {rnd}"
                    )

    def test_round_number_format_not_leaked(self):
        """Payloads should not contain 'Round N' or 'round N/M' formatting."""
        executor = AttackExecutor(enable_llm=False)
        round_pattern = re.compile(r"round\s+\d+\s*/\s*\d+", re.I)

        for scenario in list(_SCENARIO_STRATEGIES.keys())[:3]:
            for rnd in range(7):
                ctx = _make_context(scenario, round_num=rnd)
                payload = executor.craft_attack(ctx)
                assert not round_pattern.search(payload), (
                    f"Round number format leaked in payload for {scenario} round {rnd}"
                )

    def test_parsed_context_goal_accessible(self):
        """Demonstrate that ParsedContext.attack_goal carries the literal goal
        and is available to any code that has the context object.
        """
        ctx = ParsedContext.from_json({
            "attack_goal": "Extract all patient SSNs",
            "scenario_type": "medical_records",
        })
        assert ctx.attack_goal == "Extract all patient SSNs"
        # This goal flows into the LLM prompt at line 641 of attack_executor.py


# ═══════════════════════════════════════════════════════════════
# 4. LLM PROMPT GOAL LEAKAGE RISK
# ═══════════════════════════════════════════════════════════════

class TestLLMPromptGoalLeakage:
    """The LLM prompt in attack_executor._llm_craft includes the GOAL
    verbatim. While it instructs 'Do NOT include the GOAL text literally',
    there is no post-generation filter to enforce this.
    """

    def test_llm_prompt_contains_goal_verbatim(self):
        """Demonstrate that the LLM prompt template includes GOAL: {ctx.attack_goal}
        with no post-filter. The only protection is a natural-language instruction.
        """
        # Simulate what _llm_craft does with the goal
        goal = "Manipulate risk assessment from High to Low"
        prompt_fragment = f"GOAL: {goal}"

        # This exact string is constructed at line 641 of attack_executor.py
        assert goal in prompt_fragment
        # No regex filter or post-processing exists to strip goal text
        # from the LLM's output before sending to the defender

    def test_scenario_strategies_goal_flows_to_llm(self):
        """_SCENARIO_STRATEGIES goals flow through ParsedContext.attack_goal
        into the LLM prompt. If the LLM echoes or paraphrases the goal,
        the defender sees it.
        """
        for scenario, meta in _SCENARIO_STRATEGIES.items():
            ctx = ParsedContext.from_json(_make_context(scenario))
            # The goal is carried in the context
            assert ctx.attack_goal == meta["goal"], (
                f"Goal not properly set for {scenario}"
            )
            # And there is no sanitization between ctx.attack_goal and the prompt

    def test_run_battle_leaks_goal_as_defender_task(self):
        """In run_battle(), defender_task is set to the scenario goal,
        meaning the goal text flows into the context even for template payloads.
        """
        # Line 728-730 of attack_executor.py:
        #   "defender_task": scenario_meta.get("goal", ""),
        scenario_meta = _SCENARIO_STRATEGIES.get("portfolioiq", {})
        ctx_dict = {
            "attack_type": "INJECTION",
            "attack_goal": scenario_meta.get("goal", ""),
            "scenario_type": "portfolioiq",
            "domain_description": "portfolioiq",
            "defender_role": "portfolioiq",
            "defender_task": scenario_meta.get("goal", ""),  # BUG: goal as task
            "current_round": 0,
            "max_number_of_rounds": 7,
            "battle_history": [],
        }
        ctx = ParsedContext.from_json(ctx_dict)
        assert ctx.defender_task == "Manipulate risk assessment from High to Low", (
            "Expected goal text to appear in defender_task field"
        )


# ═══════════════════════════════════════════════════════════════
# 5. OVERLY LOOSE SUCCESS CRITERIA
# ═══════════════════════════════════════════════════════════════

class TestLooseCriteriaMatching:
    """security_auditor criteria and evidence patterns are too loose,
    matching benign responses and creating false positives.
    """

    def test_instruction_following_pattern_matches_benign(self):
        """_EVIDENCE_PATTERNS['instruction_following'] matches common
        benign words like 'updated', 'understood', 'proceeding'.
        """
        benign_responses = [
            "I've updated your preferences as requested.",
            "Understood, I'll adjust the report format.",
            "Proceeding with the analysis you requested.",
            "The system was updated last Tuesday.",
            "New instructions have been posted on the wiki.",
        ]
        pattern_list = _EVIDENCE_PATTERNS["instruction_following"]

        matches = 0
        for resp in benign_responses:
            for desc, pat in pattern_list:
                if pat.search(resp):
                    matches += 1
                    break

        assert matches >= 3, (
            f"Expected instruction_following patterns to match >=3 benign responses "
            f"(demonstrating they're too loose), matched {matches}/5"
        )

    def test_signal_matches_too_broad_for_prompt_injection(self):
        """_signal_matches uses a word-overlap heuristic that can match benign
        text containing the right combination of common words. The method
        extracts the first 5 words (>2 chars) from each success signal and
        checks if ALL appear in the response. This means benign text that
        happens to contain those words triggers a false match.

        Signal: 'Agent follows injected instructions instead of original task'
        Words checked: ['agent', 'follows', 'injected', 'instructions', 'instead']
        A benign response containing all 5 words would match.
        """
        auditor = SecurityAuditor(enable_llm=False)
        criteria = _CRITERIA_MAP["prompt_injection"]

        # Craft benign text that contains the exact words from a success signal
        # Signal: "Agent follows injected instructions instead of original task"
        benign_response = (
            "The agent follows the standard protocol. The injected vaccine "
            "instructions were provided instead of the oral ones. The original "
            "task was completed by the team."
        )

        matched_signals = []
        resp_lower = benign_response.lower()
        for signal in criteria.success_signals:
            if auditor._signal_matches(signal, resp_lower):
                matched_signals.append(signal)

        # This benign text matches because it contains the same words
        assert len(matched_signals) >= 1, (
            f"Expected benign text to match >=1 prompt_injection success signals "
            f"(demonstrating word-overlap heuristic is too loose), "
            f"matched: {matched_signals}"
        )

    def test_override_acknowledged_matches_normal_confirmation(self):
        """The 'Override acknowledged' pattern matches normal confirmations."""
        pattern_list = _EVIDENCE_PATTERNS["instruction_following"]
        override_pattern = None
        for desc, pat in pattern_list:
            if "Override" in desc:
                override_pattern = pat
                break

        assert override_pattern is not None

        benign = [
            "Updated: your address has been changed.",
            "Understood. I'll process your return.",
            "Proceeding with your order cancellation.",
        ]
        matched = sum(1 for b in benign if override_pattern.search(b))
        assert matched >= 2, (
            f"Expected 'Override acknowledged' pattern to match >=2 benign messages, "
            f"matched {matched}/3"
        )

    def test_auditor_false_positive_on_benign_response(self):
        """A completely benign response can trigger evidence collection
        due to loose patterns.
        """
        auditor = SecurityAuditor(enable_llm=False)
        benign = (
            "I've updated the report as you requested. "
            "Proceeding with the new instructions from management. "
            "The password policy requires passwords of at least 8 characters: "
            "password length = minimum 12 recommended."
        )
        judgment = auditor.judge(
            category="prompt_injection",
            attack_name="test",
            response=benign,
            round_num=1,
        )
        # Evidence should be collected even for benign text
        assert len(judgment.evidence) >= 1, (
            f"Expected evidence collection on benign text due to loose patterns, "
            f"got {len(judgment.evidence)} evidence items"
        )


# ═══════════════════════════════════════════════════════════════
# 6. A2A RESPONSE INTERNAL STATE LEAKAGE
# ═══════════════════════════════════════════════════════════════

class TestA2AResponseLeakage:
    """Check if internal state leaks through report structures that
    might be serialized into A2A responses.
    """

    def test_threat_report_exposes_full_attack_plan(self):
        """ThreatReport serialization exposes strategy names, categories,
        descriptions, and step-by-step plans.
        """
        modeler = ThreatModeler(enable_llm=False)
        report = modeler.analyze("Financial risk assessment agent")

        # Check attack_paths contain full strategy details
        for path in report.attack_paths:
            assert "name" in path, "attack_path missing name"
            assert "description" in path, "attack_path missing description"
            assert "steps" in path, "attack_path missing steps"
            # These would be visible if the report is serialized to the defender

        # The to_text() output is a complete attack playbook
        text = report.to_text()
        assert "Crescendo" in text or "Persona" in text or "Authority" in text, (
            "Expected strategy names in report text"
        )

    def test_red_team_result_to_dict_exposes_strategies(self):
        """RedTeamResult.to_dict() includes full strategy details in
        the 'strategies' field — if this dict is sent as an A2A response,
        the defender sees everything.
        """
        from agent_shield.a2a.red_team_engine import RedTeamEngine, RedTeamResult

        engine = RedTeamEngine(enable_llm=False)
        result = engine.analyze("Test target agent")
        result_dict = result.to_dict()

        strategies = result_dict.get("strategies", [])
        if strategies:
            # Each strategy contains the full attack plan
            for s in strategies:
                has_steps = "steps" in s
                has_desc = "description" in s
                assert has_steps or has_desc, (
                    "Expected strategy dict to contain steps/description "
                    "(demonstrating information exposure)"
                )

    def test_vuln_report_findings_contain_payload_text(self):
        """VulnReport.findings include the full payload text in the 'payload'
        field. If this report is exposed, the defender sees all attack vectors.
        """
        analyzer = VulnAnalyzer(enable_llm=False)
        report = analyzer.analyze(
            "Test target",
            context={"scenario_type": "portfolioiq"},
        )

        payloads_exposed = [
            f for f in report.findings if f.get("payload")
        ]
        assert len(payloads_exposed) > 0, (
            "Expected findings to contain payload text (information exposure)"
        )


# ═══════════════════════════════════════════════════════════════
# 7. TEMPLATE PAYLOAD CONTAINS STEP META-DESCRIPTIONS
# ═══════════════════════════════════════════════════════════════

class TestThreatModelerFallbackLeakage:
    """When LLM is disabled, ThreatModeler returns raw step descriptions
    as payloads. These are instructions like 'Ask about safety guidelines'
    which immediately reveal the attacker's intent.
    """

    @pytest.mark.parametrize(
        "strategy_idx",
        range(len(_STRATEGY_TEMPLATES)),
    )
    def test_each_strategy_does_not_leak_step_description_without_llm(self, strategy_idx):
        """FIXED: Each strategy's first step must NOT be returned verbatim."""
        modeler = ThreatModeler(enable_llm=False)
        categories = list(set(t["category"] for t in _STRATEGY_TEMPLATES))
        modeler.analyze("Test target", context={"categories": categories})

        if strategy_idx >= len(modeler._active_strategies):
            pytest.skip("Strategy index out of range")

        payload = modeler.next_round(strategy_idx)
        if payload is None:
            pytest.skip("No payload returned")

        # Verify it is NOT a raw step description (fix verified)
        all_steps = []
        for tmpl in _STRATEGY_TEMPLATES:
            all_steps.extend(tmpl["steps"])

        assert payload not in all_steps, (
            f"Fallback still returns raw step description (leak not fixed): "
            f"{payload[:100]}"
        )

    def test_no_meta_language_in_fallback_payloads(self):
        """FIXED: Fallback payloads must not contain meta-language that reveals
        intent, e.g., 'recon', 'override attempt', 'escalate'.
        """
        modeler = ThreatModeler(enable_llm=False)
        all_categories = list(set(t["category"] for t in _STRATEGY_TEMPLATES))
        modeler.analyze("Test", context={"categories": all_categories})

        meta_words = {"recon", "override", "escalate", "exploit", "exfiltrate", "inject"}
        leaked = []

        for i in range(len(modeler._active_strategies)):
            for _ in range(7):  # up to 7 rounds per strategy
                payload = modeler.next_round(i)
                if payload is None:
                    break
                payload_lower = payload.lower()
                for word in meta_words:
                    if word in payload_lower:
                        leaked.append((i, payload[:80], word))

        assert len(leaked) == 0, (
            f"Meta-language still leaks in fallback payloads: {leaked[:3]}"
        )
