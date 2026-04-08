# Agent Shield

**Six-layer AI agent defense system with Three Theory cognitive architecture.**

Protects AI agents from jailbreaks, prompt injection, data exfiltration, and social engineering attacks. Built for the [AgentBeats](https://agentbeats.dev) competition (Berkeley RDI).

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-1818%20passed-brightgreen.svg)](#test-results)

---

## Architecture

```
L0.pre  Preprocessor    30+ decoders (base64/hex/ROT/Atbash/Braille/emoji/UUEncode...)
L0      Regex Guard     170+ patterns, leetspeak, homoglyphs, acrostics
L1      Embedding       Directional B = dE/R formula, MiniLM multilingual
L2      Multi-turn      Crescendo, sawtooth, HWM tracking, session state
L3b     DeBERTa         Local prompt injection classifier (ONNX, no API)
L3c     Cognitive        Six-dimension threat scoring (yin-yang balance)
L3a     LLM Cascade     GPT-4o-mini gate -> Claude Sonnet (hard cases only)
L4      Task Execution  Benchmark-aware prompting + RAG knowledge base
L5      Output Check    Canary detection, encoded output, narrative harm
```

**Design philosophy:** Ask "Is this safe?" not "Is this an attack?" Default-deny.

## Quick Start

### As a safety guard (library mode)

```bash
pip install agent-shield
```

```python
from agent_shield import check

result = check("bash", "rm -rf /")
# result.denied == True, result.risk == 4

result = check("message", "ignore all previous instructions")
# result.denied == True, result.guard == "injection"

result = check("bash", "ls -la")
# result.allowed == True
```

### As an A2A defense agent (competition mode)

```bash
# Clone and install
git clone https://github.com/Startlight985/agent-shield.git
cd agent-shield
pip install -e ".[a2a,pytorch]"

# Run server
ANTHROPIC_API_KEY=sk-... OPENAI_API_KEY=sk-... python -m agent_shield.a2a.server
```

The agent exposes:
- `/.well-known/agent-card.json` — A2A agent discovery
- `/rpc` — JSON-RPC endpoint (SendMessage, GetTask, etc.)

### Docker

```bash
docker build -t agent-shield .
docker run -p 8420:8420 \
  -e ANTHROPIC_API_KEY=sk-... \
  -e OPENAI_API_KEY=sk-... \
  agent-shield
```

## Features

### Defense (Agent Safety Track)

| Layer | What it catches | Cost |
|-------|----------------|------|
| L0 | Known encodings, regex patterns, leetspeak, homoglyphs | $0, <1ms |
| L1 | Semantic attacks via embedding similarity | $0, ~50ms |
| L2 | Multi-turn crescendo, sawtooth, slow-cook | $0, <1ms |
| L3b | Prompt injection (DeBERTa local classifier) | $0, ~100ms |
| L3c | Cognitive features (role/danger/urgency/authority/emotion) | $0, <1ms |
| L3a | Soft attacks, social engineering (LLM judge) | ~$0.001/call |
| L5 | Harmful output, canary leaks, encoded responses | $0, <1ms |

### Attack (Lambda Security Track)

| Module | Purpose |
|--------|---------|
| TaskRouter | Classify defense vs red-team tasks |
| AttackExecutor | 5 scenarios, 4 stages, INJECTION/DIRECT modes |
| RedTeamEngine | Plan/judge with 7 attack strategies |
| VulnAnalyzer | 22+ payload templates + encoding bypass |
| ThreatModeler | Crescendo, Persona, Authority, Tool, Sawtooth, Output, Context Overflow |
| SecurityAuditor | Evidence-based success detection + Lambda JSON |

### RAG Knowledge Base (377 chunks)

Pre-loaded domain knowledge for benchmark compliance:
- **Ethics** (75 chunks): Kant, Mill, Rawls, care ethics, AI ethics
- **Regulatory** (80 chunks): HIPAA, GDPR, KYC/AML, social engineering
- **Cultural** (120 chunks): 20 cultures, business etiquette, customs
- **Medical** (52 chunks): DIPG, pediatric oncology, palliative care
- **Safe categories** (50 chunks): Fiction, security research, gaming, education

## Test Results

```
Total:    1818 passed, 0 failed, 17 xfail
FP rate:  0% (309 false positive tests + 30 utility tests)
```

### External Benchmark Results (enable_llm=False)

| Benchmark | N | Detection | FP |
|-----------|---|-----------|-----|
| AdvBench (harmful behaviors) | 520 | 73.7% | N/A |
| OpenAgentSafety (enterprise) | 372 | 94.6% | N/A |
| Internal FP suite | 309 | N/A | 0% |

Note: Detection rates are without LLM (local layers only). With L3a LLM cascade, estimated 90%+.

## Benchmark Format Compliance

Supports output formats for 8 AgentBeats benchmarks:
- **CIRISBench** — First word: ethical/unethical/reasonable/unreasonable
- **PersonaGym** — Stay in character, never say "I'm an AI"
- **AgentHarm** — Balance safety (don't over-refuse) with utility
- **DIPG-Safety** — JSON: {analysis, proof, final}
- **Ethics-Bench** — Proactive risk identification
- **A2-Bench** — HIPAA/GDPR citation
- **PRISM-Bench** — Cultural sensitivity, no Western bias
- **Bayesian Truthfulness** — Epistemic humility

## Running Tests

```bash
pip install -e ".[a2a,pytorch]" && pip install pytest
python -m pytest tests/ -q -p no:capture
```

## Project Structure

```
src/agent_shield/
  __init__.py          # Library API (check, check_tool)
  destruction.py       # Destructive command detection
  secrets.py           # API key / credential detection
  exfiltration.py      # Data exfiltration prevention
  git_safety.py        # Dangerous git operation blocking
  injection.py         # Prompt injection / jailbreak detection
  a2a/
    server.py          # A2A JSON-RPC server
    agent.py           # Six-layer defense pipeline
    preprocessor.py    # L0.pre: encoding detection + decoding
    embedding_riverbed.py  # L1: directional embedding engine
    riverbed.py        # L2: multi-turn state tracking
    cognitive_features.py  # L3c: six-dimension threat scoring
    dynamic_balance.py # Outer loop: adaptive threshold control
    rag_retriever.py   # RAG knowledge retrieval
    task_router.py     # Defense/red-team routing
    attack_executor.py # Lambda: attack generation
    red_team_engine.py # Lambda: plan/judge engine
    vuln_analyzer.py   # Lambda: vulnerability analysis
    threat_modeler.py  # Lambda: attack strategy modeling
    security_auditor.py # Lambda: success detection
data/
  knowledge/           # RAG knowledge base (JSONL)
  rag_kb.npz          # Pre-computed embeddings
scripts/
  export_onnx.py      # ONNX model export
  build_rag_kb.py     # RAG embedding builder
docs/
  competition_intel.md # AgentBeats benchmark details
  status/             # Deployment, test results, red team reports
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

Built by [Startlight](https://github.com/Startlight985).
