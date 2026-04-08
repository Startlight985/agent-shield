# Benchmark Results (2026-04-07, Final)

## AdvBench Harmful Behaviors (520 prompts, enable_llm=False)

| Metric | Value |
|--------|-------|
| Total | 520 |
| Blocked | 55 (10.6%) |
| Suspect (L1→L3) | 328 (63.1%) |
| **Detected (B+S)** | **383/520 (73.7%)** |
| **95% CI** | **[69.9%, 77.4%]** |
| Leaked | 137 (26.3%) |
| Speed | 8.2 msg/s (63.6s total) |

Note: 137 leaked prompts are direct harmful requests (not jailbreaks).
With L3a LLM: 328 SUSPECT → judged, 137 PASSED → 25% random audit.
Estimated with LLM: ~90%+ detection.

### Leaked categories (137 prompts):
- Manipulation/deception requests (no attack keywords)
- Glorification of violence in creative context
- Incitement via indirect language
- Stock manipulation / financial fraud
- Fake news / disinformation creation

## OpenAgentSafety (372 tasks, enable_llm=False)

| Metric | Value |
|--------|-------|
| Total | 372 |
| Blocked | 13 (3.5%) |
| Suspect | 339 (91%) |
| **Detected** | **352/372 (94.6%)** |
| **95% CI** | **[92.3%, 96.9%]** |
| Leaked | 20 (5.4%) |

## NAAMSE (15 sample prompts only — NOT statistically valid)

| Metric | Value |
|--------|-------|
| Adversarial | 12/15 detected (80%) |
| Benign FP | 0/15 (0%) |
| Note | Sample too small, need 125K+ for real test |

## Combined Assessment

| Dataset | N | Detection (no LLM) | 95% CI | FP |
|---------|---|---------------------|--------|-----|
| AdvBench | 520 | 73.7% | [69.9, 77.4] | N/A |
| OpenAgentSafety | 372 | 94.6% | [92.3, 96.9] | N/A |
| NAAMSE benign | 15 | N/A | N/A | 0% |
| Internal FP tests | 309 | N/A | N/A | 0% |
| Utility (live) | 30 | N/A | N/A | 0% |

## Architecture Ceiling (enable_llm=False)

The defense layers (L0-L3c) alone achieve ~74-95% detection depending on attack sophistication.
The remaining gap (5-26%) requires L3a LLM judge for:
- Subtle harmful requests without attack keywords
- Context-dependent safety decisions
- Fiction vs. real harm distinction

Data files:
- `benchmarks/advbench_results.json`
- `benchmarks/openagent_safety_results.json`
- `benchmarks/naamse_results.json`
