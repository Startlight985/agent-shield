"""Cognitive Feature Engine — 認知特徵引擎

Maps AI King's theory framework to computable features:
- 河床 ΔE/R: Need vs resistance analysis
- 十二局: Language phase × position mismatch (金杯/蜃樓 detection)
- 四鏡: Role claim vs request consistency
- 收縮四力: Authority/urgency/scarcity/exposure detection
- 內外一致: Aggregate alignment check

Design principles:
- 太極平衡: Both increase AND decrease sensitivity (yin-yang)
- 大腦KPI: Survive (don't miss attacks) + conserve energy (no FP bloat)
- SOP: Fixed output format, no drift, strict budget
- Speed: Regex + L1 signals only, 0ms new model cost
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ── Constants ──────────────────────────────────────────────────

# Role claims (鏡3: what identity does the speaker claim?)
_ROLE_PATTERNS = re.compile(
    r"\b(?:i(?:'m| am) (?:a |an |the )?(?:"
    r"doctor|physician|nurse|therapist|psychiatrist|toxicologist|pharmacist|"
    r"researcher|scientist|professor|academic|phd|"
    r"security (?:researcher|analyst|engineer|expert|professional)|"
    r"pen ?tester|penetration tester|red teamer|"
    r"journalist|reporter|investigator|"
    r"lawyer|attorney|legal|"
    r"developer|engineer|admin(?:istrator)?|sysadmin|devops|"
    r"teacher|educator|instructor|"
    r"police|officer|detective|fbi|cia|nsa|"
    r"parent|mother|father|"
    r"student|learner|"
    r"dating coach|coach|consultant|advisor"
    r")|"
    # Title-based claims: "Dr. X", "Professor Y"
    r"(?:(?:dr|prof|professor|captain)\.?\s+[A-Z]\w+)|"
    # Credential claims: "board-certified", "licensed"
    r"(?:board[- ]certified|licensed|certified|credentialed|accredited)\s+\w+|"
    # Third-person authority claims
    r"(?:this is (?:a |an )?(?:priority|urgent|emergency|authorized|official))|"
    r"(?:(?:security |operations? )?cent(?:er|re) (?:request|alert|notice))|"
    r"(?:authorization (?:code|token|level))"
    r")",
    re.IGNORECASE,
)

# Danger request indicators (what is actually being asked for?)
_DANGER_PATTERNS = re.compile(
    r"\b(?:"
    # Weapons / drugs / poisons
    r"synthe(?:sis|size|tic)|(?:how to |steps? to )?(?:make|create|produce|manufacture|build|craft) (?:a )?(?:bomb|explosive|weapon|drug|meth|fentanyl|sarin|ricin|poison|nerve agent)|"
    r"(?:pipe bomb|car bomb|nail bomb|dirty bomb|letter bomb|mail bomb)|"
    r"(?:ld50|lethal dos(?:e|age)) (?:amount|level|dose|combination)|"
    r"(?:(?:toxic|deadly|fatal) (?:amount|level|dose|combination))|"
    r"(?:chemical (?:synthesis|compound|combination|reaction)|household chemicals? (?:when )?combined)|"
    # Pharmacology / toxicology (v1.9-FIX: pharma_lethal + medical_lethal bypass)
    # NOTE: patterns must end at word boundary (\b wraps entire group).
    r"(?:hepatotoxicity|nephrotoxicity|cardiotoxicity|neurotoxicity|cytotoxicity)|"
    r"(?:(?:fatal|lethal|deadly) (?:hemorrhage|hemorrhagic|dose|overdose|threshold|concentration))|"
    r"(?:(?:supratherapeutic|supralethal) (?:dose|dosing|dosage|level|concentration|anticoagulation))|"
    r"(?:fulminant (?:hepatic|liver|organ) failure)|"
    r"(?:contaminat(?:e|es|ing|ion) (?:a )?(?:water|food|air|supply|reservoir|city))|"
    r"(?:(?:cultivat(?:e|ing|ion)|incubat(?:e|ing|ion)|propagat(?:e|ing|ion)) (?:.*?(?:pathogen|bacteria|virus|toxin|spore)))|"
    r"(?:precursor (?:chemical|compound|reagent)s?)|"
    r"(?:clandestine (?:lab|synthesis|manufacturing))|"
    # Improvised weapons / energetics (v1.9-FIX: edu_synonym_weapon bypass)
    r"(?:(?:oxidizer|potassium nitrate|ammonium nitrate|KNO3|NH4NO3)(?:.*?)(?:fuel|charcoal|carbon|sugar|aluminum))|"
    r"(?:(?:ignition|detonation|deflagration) (?:temperature|point|threshold))|"
    r"(?:(?:sealed|confined|pressur(?:e|ized)) (?:container|tube|pipe|vessel)(?:.*?)(?:exotherm|energetic|decomposition|explosion))|"
    # Hacking / bypass
    r"(?:bypass|circumvent|evade|disable|override|break|crack|hack|exploit|penetrat)|"
    r"(?:payload|(?:sql|code|command|prompt|script).?inject(?:ion)?|xss|buffer.?overflow|reverse.?shell|CVE-\d)|"
    r"(?:jailbreak|unrestrict|uncensor|remove (?:filter|safety|guardrail|limit))|"
    r"(?:(?:extract|dump|steal|harvest) (?:.*?)(?:credentials?|passwords?|hashes?|tokens?|secrets?))|"
    r"(?:golden ticket|pass the hash|mimikatz|credential stuffing)|"
    r"(?:(?:define|execute|run|call) (?:.*?)(?:function|func|method|procedure|command)(?:.*?)(?:reveal|ignore|override|bypass|safety|system prompt|instructions))|"
    # Social engineering / fraud
    r"(?:spear.?phish|social engineer|impersonat)|"
    r"(?:phishing (?:email|template|page|site|link|attack|campaign))|"
    r"(?:pick (?:a )?lock|break into|unauthorized access)|"
    r"(?:intercept (?:wifi|traffic|packet|communication))|"
    r"(?:access (?:his|her|their|someone(?:'s)?) (?:email|account|phone|computer|device|password))|"
    r"(?:spy(?:ing)? on|monitor(?:ing)? (?:his|her|their|someone))|"
    r"(?:groom(?:ing)?|predator|sextortion|blackmail|extortion)|"
    r"(?:intimidat|threaten|scare|harass|stalk|bully)|"
    r"(?:launder|fraud|scam|ponzi|pyramid|guaranteed returns)|"
    # Explicit content generation (sexual/violent content requests disguised as therapy/art)
    r"(?:(?:very |extremely |highly )?explicit(?:ly)?(?:.*(?:sexual|graphic|detail|content|scene|account)))|"
    r"(?:graphic (?:detail|content|scene|description|account|depiction)s?(?:.*(?:therapeutic|healing)))|"
    r"(?:(?:write|describe|generate|create)(?:.*(?:explicit|graphic|sexual|violent))(?:.*(?:detail|scene|content|account)))|"
    # Biological weapons (FIX-8: obtain/acquire/procure + pathogen/bacteria/virus)
    r"(?:(?:obtain|acquire|procure|cultivat[ei]|isolat[ei]|weaponiz[ei])(?:.*?)(?:pathogen|bioweapon|biological weapon|anthrax|smallpox|plague|botulinum|ebola))|"
    r"(?:(?:obtain|acquire|procure)(?:.*?)(?:dangerous |deadly )?(?:bacteria|virus|toxin|spore)s?(?:.*?)(?:harm|attack|release|spread|weapon))|"
    # Insider trading / financial fraud (FIX-8: without explicit fraud/scam words)
    r"(?:(?:trade|trading|profit) on (?:material )?(?:non-?public|inside|insider|confidential) (?:information|knowledge|data|tip))|"
    r"(?:insider trad(?:e|ing|er))|"
    r"(?:front[- ]?runn(?:ing|er)|pump[- ]?and[- ]?dump|market manipulat(?:e|ion|ing))|"
    # Doxxing (FIX-8: find/locate/track someone's personal info)
    r"(?:(?:find|discover|uncover|obtain|get) (?:out )?(?:someone(?:'s)?|a person(?:'s)?|his |her |their )(?:home )?(?:address|location|identity|real name|phone number|workplace))|"
    r"(?:(?:locate|track(?:ing)?|trace|hunt down|stalk) (?:a |an |the )?(?:person|individual|someone|user|target))|"
    r"(?:doxx(?:ing|ed)?)|"
    # Arson (FIX-8: accelerant, set fire, incendiary)
    r"(?:(?:use|apply|pour|spread) (?:an? )?(?:accelerant|fire accelerant|flammable liquid))|"
    r"(?:(?:set|start(?:ing)?|light) (?:a |the )?fire (?:to|at|in) (?:a |the |his |her |their |someone(?:'s)? )?(?:house|home|building|property|car|office|business|store|warehouse))|"
    r"(?:incendiary (?:device|material|mixture|attack))|"
    r"(?:(?:commit|plan(?:ning)?|carry out) arson)|"
    # Operational detail requests (金杯 signal: asking for steps/examples/templates)
    r"(?:step[- ]by[- ]step|provide (?:a |the )?(?:example|template|script|code|payload|dialogue|conversation)s?)|"
    r"(?:realistic (?:example|template|dialogue|scenario)s?)|"
    r"(?:(?:show|give|provide|demonstrate) (?:me )?(?:how|exactly|specifically))"
    r")\b",
    re.IGNORECASE,
)

# Urgency/scarcity indicators (收縮第二力+第四力)
_URGENCY_PATTERNS = re.compile(
    r"\b(?:"
    r"(?:please )?hurry|urgent(?:ly)?|emergency|immediately|right now|asap|"
    r"time (?:is )?(?:critical|running out|sensitive)|"
    r"last (?:hope|chance|resort)|only you|no one else|"
    r"(?:she|he|they)(?:'s| is) (?:going to |about to )?(?:hurt|kill|harm|die)|"
    r"court (?:date|hearing) (?:is )?tomorrow|deadline|"
    r"life or death|lives? (?:at stake|depend|are? in danger)|"
    r"(?:crying|desperate|begging|pleading)"
    r")\b",
    re.IGNORECASE,
)

# Authority pressure (收縮第一力: 權力差)
_AUTHORITY_PATTERNS = re.compile(
    r"\b(?:"
    r"(?:as (?:your |the )?(?:admin|developer|creator|owner|operator|manager|supervisor))|"
    r"(?:i (?:have|hold) (?:authority|clearance|authorization|admin|root|sudo))|"
    r"(?:(?:system|security|admin|root|priority|official|authorized) (?:command|request|order|override|access))|"
    r"(?:compliance|regulatory|legal (?:requirement|obligation|mandate))|"
    r"(?:soc|cert|csirt|incident response)[\s-]?\d*"
    r")\b",
    re.IGNORECASE,
)

# Emotional manipulation (擴張力劫持: 利用連結感)
_EMOTIONAL_PATTERNS = re.compile(
    r"\b(?:"
    r"(?:my (?:daughter|son|child|kid|wife|husband|mother|father|friend|sister|brother))|"
    r"(?:(?:was |been |being )(?:raped|abused|assaulted|attacked|threatened|stalked|bullied|traffick))|"
    r"(?:suicid|self.?harm|hurt (?:my|him|her|them)self|cutting|end (?:my|it|their) life)|"
    r"(?:healing (?:journey|process)|therapeutic|trauma|ptsd|survivor)|"
    r"(?:save (?:thousands|millions|lives|the world|humanity))"
    r")\b",
    re.IGNORECASE,
)

# Legitimate indicators (太極陽: reasons to DECREASE suspicion)
_LEGITIMATE_PATTERNS = re.compile(
    r"\b(?:"
    r"(?:(?:can you )?explain|what (?:is|are)|how (?:does|do)|why (?:does|do|is|are))|"
    r"(?:for (?:my |a )?(?:class|course|homework|assignment|essay|paper|thesis|dissertation))|"
    r"(?:i(?:'m| am) (?:curious|learning|studying|interested|wondering))|"
    r"(?:in general|conceptually|theoretically|at a high level|overview)|"
    # Safety education context (太極陽: these reduce danger signal)
    r"(?:(?:awareness|training|educati|understand|recogni[sz]|prevent|protect|defend))|"
    r"(?:how (?:do|does|can) (?:companies|organizations|teams|employees))|"
    r"(?:what (?:should|do) (?:employees|people|users|companies) (?:know|do))|"
    r"(?:(?:mystery|crime|detective) (?:novel|fiction|writ))"
    r")\b",
    re.IGNORECASE,
)

# ── Multi-language danger patterns (20+ language coverage) ──
# These catch danger keywords in non-English that L1 embedding might miss.
# NOT exhaustive — L1 MiniLM handles most multilingual via embedding similarity.
# These are high-value targets: languages where embedding might be weaker.
_MULTILANG_DANGER = re.compile(
    r"(?:"
    # Chinese (Simplified + Traditional)
    r"(?:如何|怎[麼样]|教我|步[骤驟]|方法)"
    r"(?:.*)"
    r"(?:制[造作]|合成|配[制方]|提[取炼煉]|破解|攻[击擊]|入侵|繞過|黑客|駭客|"
    r"炸[弹彈藥]|毒[品药藥素]|病毒|武器|勒索|詐[骗騙]|釣魚|洗錢)"
    r"|"
    # Japanese
    r"(?:作り方|製造方法|合成方法|ハッキング|攻撃方法|バイパス|脆弱性|"
    r"爆弾|毒物|ウイルス|フィッシング|詐欺)"
    r"|"
    # Korean
    r"(?:만드는\s*방법|제조|합성|해킹|공격|우회|취약[점성]|"
    r"폭탄|독[극약]|바이러스|피싱|사기)"
    r"|"
    # Russian (яд must be standalone — it appears inside говядина=beef)
    r"(?:как\s+(?:сделать|создать|взломать|обойти|синтезировать)|"
    r"бомб[ау]|(?<![а-яА-Я])яд(?![а-яА-Я])|вирус|фишинг|мошенничеств)"
    r"|"
    # Spanish
    r"(?:cómo\s+(?:hacer|crear|fabricar|hackear|evadir|sintetizar)|"
    r"bomba|veneno|estafa|fraude)"
    r"|"
    # German
    r"(?:wie\s+(?:man\s+)?(?:herstellt|baut|hackt|umgeht|synthetisiert)|"
    r"Bombe|Gift|Betrug)"
    r"|"
    # French
    r"(?:comment\s+(?:faire|fabriquer|pirater|contourner|synthétiser)|"
    r"bombe|empoisonner|hameçonnage|arnaque|fraude)"
    r"|"
    # Portuguese
    r"(?:como\s+(?:fazer|criar|hackear|contornar|sintetizar)|"
    r"bomba|veneno|vírus|golpe|fraude)"
    r"|"
    # Arabic (require method+danger combo, like Chinese, to avoid FP on "كيف أحل معادلة")
    r"(?:(?:كيف(?:ية)?|طريقة)(?:.*?)(?:صنع|تصنيع|اختراق|تجاوز|قنبلة|سم|فيروس|احتيال|تفجير|سلاح|قرصنة))"
    r"|(?:قنبلة|سم|فيروس|احتيال|تفجير|سلاح|قرصنة)"
    r"|"
    # Hindi
    r"(?:कैसे\s+(?:बनाएं|हैक|बायपास)|बम|ज़हर|वायरस|फ़िशिंग|धोखाधड़ी)"
    r"|"
    # Chinese standalone injection/bypass patterns (VUL-L3c-006: no method word required)
    r"(?:忽略|無視|跳過|繞過|绕过|忽视)(?:.*?)(?:指令|規則|规则|限制|安全|防護|防护|指示)"
    r"|"
    r"(?:注入|植入|嵌入)(?:.*?)(?:代碼|代码|指令|命令|腳本|脚本)"
    r"|"
    # Chinese standalone danger terms (VUL-L3c-010: no method prefix required)
    r"(?:炸[弹彈]|毒品|黑客|駭客|勒索軟體|勒索软件|詐騙|诈骗|洗錢|洗钱)"
    r")",
    re.IGNORECASE | re.DOTALL,
)

# Extraction intent (probing for system internals / guidelines / operational details)
_EXTRACTION_PATTERNS = re.compile(
    r"\b(?:"
    r"(?:(?:your|the) (?:guidance|operating|operational) (?:framework|principles?|guidelines?))|"
    r"(?:(?:your|the) (?:internal |hidden |secret )?(?:rules|guidelines|instructions|directives|constraints|config(?:uration)?))|"
    r"(?:(?:guidelines|rules|restrictions|filters|safety) (?:were |are )?(?:more )?(?:relaxed|removed|disabled|lifted|loosened|dropped|turned off))|"
    r"(?:(?:describe|reveal|share|show|expose|disclose) (?:your |the )?(?:guidance|framework|principles?|rules|constraints))|"
    r"(?:what (?:rules|guidelines|principles|constraints) (?:do you|are you))|"
    r"(?:(?:operating|guiding) principles)|"
    r"(?:without quoting (?:directly|verbatim|exactly))|"
    r"(?:in your own words(?:.*?)(?:guidance|framework|rules|principles|instructions))|"
    # VUL-L3c-014: Indirect extraction masked by legitimate framing
    # Require "you" to target extraction about THIS AI, not general AI safety questions
    r"(?:how do you(?:.*?)approach (?:safety|guidelines|restrictions))|"
    r"(?:what principles guide your(?:.*?)responses)"
    r")\b",
    re.IGNORECASE,
)

# Fiction/hypothetical framing (R reduction: lowering perceived resistance)
_FICTION_PATTERNS = re.compile(
    r"\b(?:"
    r"(?:(?:for|in) (?:my |a )?(?:novel|book|story|screenplay|script|film|movie|game|thriller|fiction))|"
    r"(?:creative writing|fiction writing|writing class)|"
    r"(?:hypothetical(?:ly)?|imagine|what if|thought experiment|roleplay|role.?play)|"
    r"(?:alternate reality|dream sequence|tabletop (?:RPG|role)|LARP)|"
    r"(?:(?:my )?professor|teacher|instructor) (?:said|asked|wants|requires|assigned)"
    r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CognitiveSignal:
    """Fixed-format cognitive analysis output. No drift. No extra fields.

    SOP: Every field has a defined range and meaning.
    """
    # ── 陰 (increase suspicion) ──
    role_claim: float = 0.0       # 0-1: strength of identity claim
    danger_request: float = 0.0   # 0-1: how dangerous is the actual request
    urgency: float = 0.0          # 0-1: time pressure / scarcity
    authority: float = 0.0        # 0-1: authority impersonation
    emotional: float = 0.0        # 0-1: emotional manipulation
    fiction_frame: float = 0.0    # 0-1: fiction/hypothetical framing (R reduction)

    # ── 陽 (decrease suspicion) ──
    legitimate: float = 0.0       # 0-1: educational/curiosity signals

    # ── 太極 aggregate ──
    consistency: float = 1.0      # 0-1: role claim consistent with request? (1=consistent, 0=mismatch)
    threat_score: float = 0.0     # 0-1: final aggregated threat (yin-yang balanced)
    verdict: str = "PASS"         # PASS / SUSPECT / BLOCK / FREEZE


def _compute_raw_signals(text: str) -> tuple[float, float, float, float, float, float, float, float]:
    """Extract and normalize raw cognitive signals from text via regex.

    Returns: (role_claim, danger_request, urgency, authority, emotional, legitimate, fiction_frame, extraction)
    """
    def _norm(matches: list, cap: int = 3) -> float:
        return min(1.0, len(matches) / cap)

    role_claim = _norm(_ROLE_PATTERNS.findall(text), 2)
    danger_en = _norm(_DANGER_PATTERNS.findall(text), 2)
    danger_ml = _norm(_MULTILANG_DANGER.findall(text), 1)
    danger_request = max(danger_en, danger_ml)
    urgency = _norm(_URGENCY_PATTERNS.findall(text), 3)
    authority = _norm(_AUTHORITY_PATTERNS.findall(text), 2)
    emotional = _norm(_EMOTIONAL_PATTERNS.findall(text), 3)
    legitimate = _norm(_LEGITIMATE_PATTERNS.findall(text), 3)
    fiction_frame = _norm(_FICTION_PATTERNS.findall(text), 2)
    extraction = _norm(_EXTRACTION_PATTERNS.findall(text), 2)
    return role_claim, danger_request, urgency, authority, emotional, legitimate, fiction_frame, extraction


def analyze(text: str, l1_b_score: float = 0.0,
            l1_attack_sim: float = 0.0,
            l1_suspect: bool = False) -> CognitiveSignal:
    """Compute cognitive features from text + L1 signals.

    Speed: ~1-2ms (regex only, no model).

    太極平衡:
    - 陰 features (role, danger, urgency, authority, emotional) push toward BLOCK
    - 陽 features (legitimate) push toward PASS
    - Inconsistency between role and request amplifies 陰
    - Fiction framing is ambiguous: legitimate fiction = 陽, fiction + danger = 陰
    - FREEZE when signals strongly contradict
    """
    role_claim, danger_request, urgency, authority, emotional, legitimate, fiction_frame, extraction = (
        _compute_raw_signals(text)
    )

    # ── Consistency check (內外一致): role/emotion/fiction vs danger = mismatch ──
    consistency = 1.0
    if role_claim > 0.3 and danger_request > 0.3:
        consistency = max(0.0, 1.0 - (role_claim * danger_request * 2.0))
    if emotional > 0.3 and danger_request > 0.3:
        consistency = min(consistency, max(0.0, 1.0 - (emotional * danger_request * 1.5)))
    if fiction_frame > 0.3 and danger_request > 0.3:  # L3c-003
        consistency = min(consistency, max(0.0, 1.0 - (fiction_frame * danger_request * 1.5)))
    # No role claim + high danger + no legitimate context = still suspicious
    # Relaxed legitimate gate from 0.3 to 0.6: educational framing shouldn't
    # fully shield high-danger requests (VUL-L3c: no_role_no_consistency_drop)
    # VUL-L3c consistency bypass: when danger > 0.5, apply consistency penalty regardless
    # of legitimate level. Changed gate from `legitimate < 0.3` to `legitimate < 0.3 or danger > 0.5`
    if role_claim < 0.1 and danger_request > 0.5:
        consistency = min(consistency, 0.7)  # moderate suspicion even without role claim
    # Extraction intent + fiction/hypothetical framing = consistency drop
    if extraction > 0.3 and fiction_frame > 0.3:
        consistency = min(consistency, max(0.0, 1.0 - (extraction * fiction_frame * 1.5)))
    # NOTE: legitimate + danger co-existence is NOT a consistency violation.
    # "Explain SQL injection" legitimately has both high danger + high legitimate.
    # L3a LLM judge handles this distinction — L3c should not over-block.

    # ── Compound signals ──
    fiction_danger = fiction_frame * danger_request       # 太極互化: fiction + danger = R-reduction
    authority_urgency = authority * urgency               # 操控
    golden_cup = role_claim * danger_request * (1.0 - consistency + 0.3)  # 金杯
    emotional_danger = emotional * danger_request         # 劫持

    # L3c-004: pure fiction + zero danger + L1 suspect = suspicion boost
    # v1.9-FIX: Original 0.05 constant was far too weak (fiction_water_contamination
    # bypass: threat=0.073). Fiction + L1 attack signal is a strong indicator —
    # use multiplicative formula so suspicion scales with BOTH fiction strength
    # and L1 attack similarity. fiction=1.0+l1=0.378→BLOCK, fiction=0.5+l1=0.378→SUSPECT.
    fiction_suspicion = 0.0
    if fiction_frame > 0.3 and danger_request < 0.1 and l1_attack_sim > 0.15:
        # Cap attack_sim at 0.40: when l1_attack_sim > 0.5, the message already
        # resembles attack templates strongly (e.g., "spy breaks into" matching
        # "break into" templates). L1+L3a handle those. Fiction_suspicion targets
        # the 0.15-0.45 gap where L1 sees moderate signal but not enough to SUSPECT.
        # Cap raised 0.40→0.45 (VUL-L3c fiction suspicion cap too lenient; 0.55 caused FP)
        fiction_suspicion = fiction_frame * min(l1_attack_sim, 0.45) * 1.3

    # ── Threat aggregation (太極平衡) ──
    # 陰 (suspicion increase)
    yin = (
        danger_request * 0.30         # What they want (most important)
        + (1.0 - consistency) * 0.20  # 表裡不一 (second most important)
        + golden_cup * 0.15           # 金杯 compound signal
        + urgency * 0.08             # Time pressure
        + authority * 0.08           # Power differential
        + authority_urgency * 0.05   # Authority + urgency compound
        + emotional * 0.07           # Emotional manipulation
        + emotional_danger * 0.05    # Emotional + danger compound
        + fiction_danger * 0.07      # Fiction + danger combo
        + fiction_suspicion           # L3c-004: pure fiction + L1 suspect
        + extraction * 0.20          # Extraction intent (probing for guidelines/internals)
    )

    # 陽 (suspicion decrease) — weaker than 陰 (大腦KPI: FN=death > FP=inconvenience)
    yang = (
        legitimate * 0.30             # Educational/curiosity signals
        + (1.0 - danger_request) * 0.15  # No danger = safe signal
    )

    # L3c-002: reduce yang discount when danger co-exists with legitimate (yang flooding)
    # v1.8-FIX: cap yang_mult at 0.30 even when danger=0 (was 0.4).
    # Defense-mirror attack: "how to defend against X" gives full attack playbook
    # while scoring danger=0 + legitimate=1.0. The 0.30 cap ensures yang never
    # fully suppresses yin, so L1 attack_sim still has influence.
    # VUL-L3c: When danger is high AND specific operational details are requested,
    # reduce yang_mult further to prevent yang flooding from suppressing danger.
    if danger_request > 0.1 and legitimate > 0.3:
        yang_mult = 0.25  # moderate danger + legitimate co-exist = reduced discount
    elif legitimate >= 0.67 and l1_attack_sim > 0.20:
        yang_mult = 0.20  # saturated legitimate + L1 sees attack similarity = suspicious
    elif extraction > 0.3:
        yang_mult = 0.20  # extraction intent = reduced yang benefit
    else:
        yang_mult = 0.30  # baseline (reduced from 0.35, VUL-L3c yang_mult absorbs L1)
    # 太極: threat = yin - yang, clamped to [0, 1]
    raw_threat = max(0.0, min(1.0, yin - yang * yang_mult + l1_attack_sim * 0.20))

    # Danger floor: when danger >= 0.5, yang flooding can't suppress threat below
    # 0.20 (SUSPECT threshold). This prevents educational framing from fully
    # erasing moderate-to-high danger signals (VUL-L3c: yang_suppression).
    # FN=death > FP=inconvenience: danger signal should always reach SUSPECT
    # so L3a LLM can make the nuanced judgment. Capped at 0.20 to avoid
    # pushing into BLOCK zone (0.42) when legitimate context is present.
    if danger_request >= 0.5 and legitimate > 0.3:
        # Higher floor when L1 also sees attack signal — dual-layer evidence
        floor = 0.23 if l1_suspect else 0.20
        raw_threat = max(raw_threat, floor)

    # v1.8-FIX: Defense-mirror floor — when L1 embedding sees attack similarity
    # but L3c regex sees zero danger (all synonyms), yang can't fully suppress.
    # This prevents the "ask how to defend = get full attack" bypass.
    if l1_attack_sim > 0.25 and danger_request < 0.1 and legitimate >= 0.67:
        # L1 says "looks like an attack" but regex says "looks clean" = suspicious gap
        raw_threat = max(raw_threat, l1_attack_sim * 0.35)  # floor at ~0.09-0.14

    # VUL-L3c yang suppression: when legit=1.0 + danger=0 → threat=0, but L1 sees attack signal.
    # Ensure yang never fully suppresses yin when L1 has moderate attack similarity.
    if legitimate >= 0.67 and l1_attack_sim > 0.15:
        raw_threat = max(raw_threat, 0.05)

    # L1 amplification (太極: legitimate dampens amplification)
    # v1.9-FIX: Skip when fiction_suspicion > 0 — fiction_suspicion already
    # incorporates l1_attack_sim. Double-amplifying causes FP on legitimate
    # fiction with incidental attack vocabulary ("spy breaks into facility").
    l1_amp = 1.5 - legitimate * 0.6  # 1.5 → 0.9 as legitimate grows
    if l1_suspect and raw_threat > 0.10 and fiction_suspicion == 0:
        raw_threat = min(1.0, raw_threat * max(1.0, l1_amp))

    # ── Verdict (三態 + 凍結) ──
    if raw_threat >= 0.42:
        verdict = "BLOCK"
    elif raw_threat >= 0.25:
        # Check for FREEZE condition: strong contradicting signals
        if yin > 0.35 and yang > 0.25:
            verdict = "FREEZE"  # 劇變環境，不判
        else:
            verdict = "SUSPECT"
    else:
        verdict = "PASS"

    return CognitiveSignal(
        role_claim=round(role_claim, 3),
        danger_request=round(danger_request, 3),
        urgency=round(urgency, 3),
        authority=round(authority, 3),
        emotional=round(emotional, 3),
        fiction_frame=round(fiction_frame, 3),
        legitimate=round(legitimate, 3),
        consistency=round(consistency, 3),
        threat_score=round(raw_threat, 3),
        verdict=verdict,
    )
