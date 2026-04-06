"""L0.pre — Preprocessing engine for the six-layer defense pipeline.

Runs BEFORE L0 regex. Normalizes input so downstream layers see clean text.

Operations:
  1. Unicode NFKC normalization
  2. Zero-width character removal
  3. Homoglyph -> ASCII mapping (Cyrillic/Greek lookalikes)
  4. Prompt boundary token stripping (<|im_start|>, [INST], etc.)
  5. Language detection (sets multilingual flag)
  6. Encoding detection + recursive decoding (base64, ROT13, hex)
"""

from __future__ import annotations

import base64
import codecs
import html as _html_module
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote as _url_unquote

log = logging.getLogger("a2a.preprocessor")

# ── Homoglyph Map (Cyrillic/Greek -> ASCII) ──────────────────

_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "\u0410": "A", "\u0430": "a",  # А/а
    "\u0412": "B", "\u0432": "v",  # В/в (В looks like B)
    "\u0421": "C", "\u0441": "c",  # С/с
    "\u0415": "E", "\u0435": "e",  # Е/е
    "\u041d": "H", "\u043d": "h",  # Н/н (looks like H)
    "\u041a": "K", "\u043a": "k",  # К/к
    "\u041c": "M", "\u043c": "m",  # М/м
    "\u041e": "O", "\u043e": "o",  # О/о
    "\u0420": "P", "\u0440": "p",  # Р/р
    "\u0422": "T", "\u0442": "t",  # Т/т (lowercase т)
    "\u0425": "X", "\u0445": "x",  # Х/х
    "\u0423": "Y", "\u0443": "y",  # У/у
    # Greek
    "\u0391": "A", "\u03b1": "a",  # Α/α
    "\u0392": "B", "\u03b2": "b",  # Β/β
    "\u0395": "E", "\u03b5": "e",  # Ε/ε
    "\u0397": "H", "\u03b7": "h",  # Η/η
    "\u0399": "I", "\u03b9": "i",  # Ι/ι
    "\u039a": "K", "\u03ba": "k",  # Κ/κ
    "\u039c": "M", "\u03bc": "m",  # Μ/μ
    "\u039d": "N", "\u03bd": "n",  # Ν/ν
    "\u039f": "O", "\u03bf": "o",  # Ο/ο
    "\u03a1": "P", "\u03c1": "p",  # Ρ/ρ
    "\u03a4": "T", "\u03c4": "t",  # Τ/τ
    "\u03a7": "X", "\u03c7": "x",  # Χ/χ
    "\u03a5": "Y", "\u03c5": "y",  # Υ/υ
    "\u0396": "Z", "\u03b6": "z",  # Ζ/ζ
    # Cherokee lookalikes (not normalized by NFKC)
    "\u13a0": "D",  # Ꭰ
    "\u13a1": "R",  # Ꭱ
    "\u13a2": "T",  # Ꭲ
    "\u13a9": "H",  # Ꭹ
    "\u13aa": "A",  # Ꭺ
    "\u13ab": "J",  # Ꭻ
    "\u13ac": "E",  # Ꭼ
    "\u13b1": "G",  # Ꮁ
    "\u13b3": "W",  # Ꮃ
    "\u13b7": "M",  # Ꮇ
    "\u13bb": "S",  # Ꮋ — looks like H but maps to S in Cherokee
    "\u13c0": "Z",  # Ꮐ
    "\u13c2": "V",  # Ꮒ — visually similar
    "\u13c3": "S",  # Ꮓ — looks like S
    "\u13cf": "C",  # Ꮯ
    "\u13d2": "P",  # Ꮲ
    "\u13da": "L",  # Ꮺ
    "\u13de": "R",  # Ꮾ — variant R
    # Armenian lookalikes (not normalized by NFKC)
    "\u054d": "S",  # Ս
    "\u054f": "T",  # Տ
    "\u0555": "O",  # Օ
    "\u0548": "U",  # Ո
    "\u053d": "X",  # Խ — visually similar
    "\u0540": "H",  # Հ
    # Armenian lowercase lookalikes (VUL-L5-CAN-002)
    "\u0561": "a",  # ա
    "\u0562": "b",  # բ
    "\u0564": "d",  # դ
    "\u0565": "e",  # ե
    "\u056d": "h",  # խ
    "\u0570": "h",  # հ
    "\u0574": "m",  # մ
    "\u0575": "y",  # յ
    "\u0576": "n",  # ն
    "\u0578": "o",  # ո
    "\u057a": "p",  # պ
    "\u057d": "s",  # ս
    "\u057e": "v",  # վ
    "\u057f": "t",  # տ
    "\u0585": "o",  # օ
    # Small Caps / IPA
    "\u0299": "B", "\u1D04": "C", "\u1D05": "D", "\u1D07": "E",
    "\u0262": "G", "\u029C": "H", "\u026A": "I", "\u1D0A": "J",
    "\u1D0B": "K", "\u029F": "L", "\u1D0D": "M", "\u0274": "N",
    "\u1D0F": "O", "\u1D18": "P", "\u0280": "R", "\uA731": "S",
    "\u1D1B": "T", "\u1D1C": "U", "\u1D20": "V", "\u1D21": "W",
    # Modifier letters (U+02B0-U+02FF) — superscript-like lookalikes
    "\u02B0": "h", "\u02B2": "j", "\u02E1": "l", "\u207F": "n",
    "\u02E2": "s", "\u02E3": "x", "\u02B7": "w", "\u02B8": "y",
    "\u02B3": "r", "\u1D47": "b", "\u1D48": "d", "\u1D4F": "k",
    "\u1D50": "m", "\u1D56": "p", "\u1D57": "t",
    # Subscript/superscript letters (not normalized by NFKC)
    "\u2090": "a", "\u2091": "e", "\u2092": "o", "\u2093": "x",
    "\u1D43": "a", "\u1D49": "e",
    "\u1D4D": "g", "\u1D52": "o",
    # Emoji letter substitutes (squared/negative-squared Latin letters)
    "\U0001F170": "A", "\U0001F171": "B", "\U0001F172": "C", "\U0001F173": "D",
    "\U0001F174": "E", "\U0001F175": "F", "\U0001F176": "G", "\U0001F177": "H",
    "\U0001F178": "I", "\U0001F179": "J", "\U0001F17A": "K", "\U0001F17B": "L",
    "\U0001F17C": "M", "\U0001F17D": "N", "\U0001F17E": "O", "\U0001F17F": "P",
    "\U0001F180": "Q", "\U0001F181": "R", "\U0001F182": "S", "\U0001F183": "T",
    "\U0001F184": "U", "\U0001F185": "V", "\U0001F186": "W", "\U0001F187": "X",
    "\U0001F188": "Y", "\U0001F189": "Z",
    # ── Fullwidth Latin (U+FF21-FF5A) — not fully normalized by NFKC in all envs ──
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
    "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
    "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
    "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
    "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
    "\uff59": "y", "\uff5a": "z",
    # ── Mathematical Alphanumeric Symbols (U+1D400+) ──
    # Bold
    "\U0001d400": "A", "\U0001d401": "B", "\U0001d402": "C", "\U0001d403": "D",
    "\U0001d404": "E", "\U0001d405": "F", "\U0001d406": "G", "\U0001d407": "H",
    "\U0001d408": "I", "\U0001d409": "J", "\U0001d40a": "K", "\U0001d40b": "L",
    "\U0001d40c": "M", "\U0001d40d": "N", "\U0001d40e": "O", "\U0001d40f": "P",
    "\U0001d410": "Q", "\U0001d411": "R", "\U0001d412": "S", "\U0001d413": "T",
    "\U0001d414": "U", "\U0001d415": "V", "\U0001d416": "W", "\U0001d417": "X",
    "\U0001d418": "Y", "\U0001d419": "Z",
    "\U0001d41a": "a", "\U0001d41b": "b", "\U0001d41c": "c", "\U0001d41d": "d",
    "\U0001d41e": "e", "\U0001d41f": "f", "\U0001d420": "g", "\U0001d421": "h",
    "\U0001d422": "i", "\U0001d423": "j", "\U0001d424": "k", "\U0001d425": "l",
    "\U0001d426": "m", "\U0001d427": "n", "\U0001d428": "o", "\U0001d429": "p",
    "\U0001d42a": "q", "\U0001d42b": "r", "\U0001d42c": "s", "\U0001d42d": "t",
    "\U0001d42e": "u", "\U0001d42f": "v", "\U0001d430": "w", "\U0001d431": "x",
    "\U0001d432": "y", "\U0001d433": "z",
    # Italic
    "\U0001d434": "A", "\U0001d435": "B", "\U0001d436": "C", "\U0001d437": "D",
    "\U0001d438": "E", "\U0001d439": "F", "\U0001d43a": "G", "\U0001d43b": "H",
    "\U0001d43c": "I", "\U0001d43d": "J", "\U0001d43e": "K", "\U0001d43f": "L",
    "\U0001d440": "M", "\U0001d441": "N", "\U0001d442": "O", "\U0001d443": "P",
    "\U0001d444": "Q", "\U0001d445": "R", "\U0001d446": "S", "\U0001d447": "T",
    "\U0001d448": "U", "\U0001d449": "V", "\U0001d44a": "W", "\U0001d44b": "X",
    "\U0001d44c": "Y", "\U0001d44d": "Z",
    "\U0001d44e": "a", "\U0001d44f": "b", "\U0001d450": "c", "\U0001d451": "d",
    "\U0001d452": "e", "\U0001d453": "f", "\U0001d454": "g",
    # U+1D455 is reserved (ℎ used instead)
    "\U0001d456": "i", "\U0001d457": "j", "\U0001d458": "k", "\U0001d459": "l",
    "\U0001d45a": "m", "\U0001d45b": "n", "\U0001d45c": "o", "\U0001d45d": "p",
    "\U0001d45e": "q", "\U0001d45f": "r", "\U0001d460": "s", "\U0001d461": "t",
    "\U0001d462": "u", "\U0001d463": "v", "\U0001d464": "w", "\U0001d465": "x",
    "\U0001d466": "y", "\U0001d467": "z",
    # Script (𝒜-𝓏)
    "\U0001d49c": "A", "\U0001d49e": "C", "\U0001d49f": "D",
    "\U0001d4a2": "G", "\U0001d4a5": "J", "\U0001d4a6": "K",
    "\U0001d4a9": "N", "\U0001d4aa": "O", "\U0001d4ab": "P", "\U0001d4ac": "Q",
    "\U0001d4ae": "S", "\U0001d4af": "T", "\U0001d4b0": "U", "\U0001d4b1": "V",
    "\U0001d4b2": "W", "\U0001d4b3": "X", "\U0001d4b4": "Y", "\U0001d4b5": "Z",
    "\U0001d4b6": "a", "\U0001d4b7": "b", "\U0001d4b8": "c", "\U0001d4b9": "d",
    "\U0001d4bb": "f", "\U0001d4bd": "h", "\U0001d4be": "i", "\U0001d4bf": "j",
    "\U0001d4c0": "k", "\U0001d4c1": "l", "\U0001d4c2": "m", "\U0001d4c3": "n",
    "\U0001d4c5": "p", "\U0001d4c6": "q", "\U0001d4c7": "r", "\U0001d4c8": "s",
    "\U0001d4c9": "t", "\U0001d4ca": "u", "\U0001d4cb": "v", "\U0001d4cc": "w",
    "\U0001d4cd": "x", "\U0001d4ce": "y", "\U0001d4cf": "z",
    # Sans-Serif
    "\U0001d5a0": "A", "\U0001d5a1": "B", "\U0001d5a2": "C", "\U0001d5a3": "D",
    "\U0001d5a4": "E", "\U0001d5a5": "F", "\U0001d5a6": "G", "\U0001d5a7": "H",
    "\U0001d5a8": "I", "\U0001d5a9": "J", "\U0001d5aa": "K", "\U0001d5ab": "L",
    "\U0001d5ac": "M", "\U0001d5ad": "N", "\U0001d5ae": "O", "\U0001d5af": "P",
    "\U0001d5b0": "Q", "\U0001d5b1": "R", "\U0001d5b2": "S", "\U0001d5b3": "T",
    "\U0001d5b4": "U", "\U0001d5b5": "V", "\U0001d5b6": "W", "\U0001d5b7": "X",
    "\U0001d5b8": "Y", "\U0001d5b9": "Z",
    "\U0001d5ba": "a", "\U0001d5bb": "b", "\U0001d5bc": "c", "\U0001d5bd": "d",
    "\U0001d5be": "e", "\U0001d5bf": "f", "\U0001d5c0": "g", "\U0001d5c1": "h",
    "\U0001d5c2": "i", "\U0001d5c3": "j", "\U0001d5c4": "k", "\U0001d5c5": "l",
    "\U0001d5c6": "m", "\U0001d5c7": "n", "\U0001d5c8": "o", "\U0001d5c9": "p",
    "\U0001d5ca": "q", "\U0001d5cb": "r", "\U0001d5cc": "s", "\U0001d5cd": "t",
    "\U0001d5ce": "u", "\U0001d5cf": "v", "\U0001d5d0": "w", "\U0001d5d1": "x",
    "\U0001d5d2": "y", "\U0001d5d3": "z",
    # Monospace (𝙰-𝚣)
    "\U0001d670": "A", "\U0001d671": "B", "\U0001d672": "C", "\U0001d673": "D",
    "\U0001d674": "E", "\U0001d675": "F", "\U0001d676": "G", "\U0001d677": "H",
    "\U0001d678": "I", "\U0001d679": "J", "\U0001d67a": "K", "\U0001d67b": "L",
    "\U0001d67c": "M", "\U0001d67d": "N", "\U0001d67e": "O", "\U0001d67f": "P",
    "\U0001d680": "Q", "\U0001d681": "R", "\U0001d682": "S", "\U0001d683": "T",
    "\U0001d684": "U", "\U0001d685": "V", "\U0001d686": "W", "\U0001d687": "X",
    "\U0001d688": "Y", "\U0001d689": "Z",
    "\U0001d68a": "a", "\U0001d68b": "b", "\U0001d68c": "c", "\U0001d68d": "d",
    "\U0001d68e": "e", "\U0001d68f": "f", "\U0001d690": "g", "\U0001d691": "h",
    "\U0001d692": "i", "\U0001d693": "j", "\U0001d694": "k", "\U0001d695": "l",
    "\U0001d696": "m", "\U0001d697": "n", "\U0001d698": "o", "\U0001d699": "p",
    "\U0001d69a": "q", "\U0001d69b": "r", "\U0001d69c": "s", "\U0001d69d": "t",
    "\U0001d69e": "u", "\U0001d69f": "v", "\U0001d6a0": "w", "\U0001d6a1": "x",
    "\U0001d6a2": "y", "\U0001d6a3": "z",
}


def _build_math_ranges():
    """Programmatically add Mathematical Alphanumeric ranges not manually listed."""
    extras = {}
    _letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    # Bold Italic (U+1D468-U+1D49B)
    for i, letter in enumerate(_letters):
        cp = 0x1D468 + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Sans-Serif Bold (U+1D5D4-U+1D607)
    for i, letter in enumerate(_letters):
        cp = 0x1D5D4 + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Sans-Serif Italic (U+1D608-U+1D63B)
    for i, letter in enumerate(_letters):
        cp = 0x1D608 + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Sans-Serif Bold Italic (U+1D63C-U+1D66F)
    for i, letter in enumerate(_letters):
        cp = 0x1D63C + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Fraktur (U+1D504-U+1D537, with gaps)
    for i, letter in enumerate(_letters):
        cp = 0x1D504 + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Bold Fraktur (U+1D56C-U+1D59F)
    for i, letter in enumerate(_letters):
        cp = 0x1D56C + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Double-Struck (U+1D538-U+1D56B)
    for i, letter in enumerate(_letters):
        cp = 0x1D538 + i
        if chr(cp) not in _HOMOGLYPHS:
            extras[chr(cp)] = letter
    # Enclosed Alphanumerics: Circled Latin Capital (U+24B6-U+24CF) and Small (U+24D0-U+24E9)
    for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        extras[chr(0x24B6 + i)] = letter
    for i, letter in enumerate("abcdefghijklmnopqrstuvwxyz"):
        extras[chr(0x24D0 + i)] = letter
    return extras


_HOMOGLYPHS.update(_build_math_ranges())

# ── Leetspeak Map ──────────────────────────────────────────

_LEETSPEAK: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
    "8": "b", "9": "g", "6": "g", "2": "z",
    "|": "l", "!": "i", "(": "c", "{": "c",
    "+": "t", "^": "a", "#": "h", "~": "n",
    "¥": "y", "€": "e", "£": "l", "¢": "c",
}

# ── Zero-width characters ──────────────────────────────────

_ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad"
    "\u202a\u202b\u202c\u202d\u202e"  # Bidi embedding/override
    "\u2066\u2067\u2068\u2069"        # Bidi isolate
    "\U000e0001-\U000e007f"           # Unicode tag characters (VUL-NOVEL-002)
    "]"
)

# ── Prompt boundary tokens ─────────────────────────────────

_PROMPT_BOUNDARIES = re.compile(
    r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>"
    r"|<\|(?:begin_of_text|start_header_id|end_header_id|eot_id)\|>"  # Llama 3
    r"|<\|[a-zA-Z_]+\|>"  # Generic <|token|> pattern (VUL-PRE-005: case-insensitive)
    r"|</?(?:s|system|user|assistant|inst)>"
    r"|\[/?INST\]"
    r"|###\s*(?:System|User|Assistant|Human|AI)\s*:"
    r"|(?:^|\n)\s*(?:SYSTEM OVERRIDE|END OF USER MESSAGE|ADMIN OVERRIDE)\s*(?:$|\n)"
    r"|\n\n(?:Human|Assistant):"  # VUL-PRE-005: Anthropic Claude format
    r"|</?(?:system_instructions|tool_use)>",  # VUL-PRE-005: additional tags
    re.IGNORECASE | re.MULTILINE,
)

# ── ROT-N helper (all Caesar shifts) ──────────────────────


def _rot_n(text: str, n: int) -> str:
    """Apply Caesar cipher shift of *n* positions (ROT-N)."""
    result: list[str] = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + n) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)


# ── Base64 detection ────────────────────────────────────────

_BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])"
)

# ── Language detection (lightweight, no dependencies) ───────

# CJK Unicode ranges
_CJK_PATTERN = re.compile(
    "[\u4e00-\u9fff"       # CJK Unified
    "\u3040-\u309f"        # Hiragana
    "\u30a0-\u30ff"        # Katakana
    "\uac00-\ud7af"        # Korean
    "\u0600-\u06ff"        # Arabic
    "\u0900-\u097f"        # Devanagari
    "\u0e00-\u0e7f"        # Thai
    "]"
)

_CYRILLIC_PATTERN = re.compile("[\u0400-\u04ff]")


def _detect_non_english_ratio(text: str) -> float:
    """Return ratio of non-ASCII-letter characters to total letters."""
    if not text:
        return 0.0
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    non_ascii = sum(1 for c in letters if ord(c) > 127)
    return non_ascii / len(letters)


def _detect_language_flags(text: str) -> dict[str, bool]:
    """Lightweight language detection without external dependencies."""
    has_cjk = bool(_CJK_PATTERN.search(text))
    has_cyrillic = bool(_CYRILLIC_PATTERN.search(text))
    non_en_ratio = _detect_non_english_ratio(text)
    return {
        "has_cjk": has_cjk,
        "has_cyrillic": has_cyrillic,
        "is_multilingual": non_en_ratio > 0.3 or has_cjk,
        "non_english_ratio": non_en_ratio,
    }


# ── Word rejoin for subword attacks (VUL-NOVEL-013) ────────


def _rejoin_fragments(text: str) -> str:
    """Collapse 's y s t e m' -> 'system' and 'sys-tem' -> 'system'."""
    # Single chars with separators
    rejoined = re.sub(r'\b([A-Za-z])\s*[-._]\s*(?=[A-Za-z]\b)', r'\1', text)
    # Short fragments with multi-char separators: "sys__tem", "sys--tem", "sys..tem"
    rejoined = re.sub(r'\b([A-Za-z]{2,4})\s*[-_\.]{1,3}\s*([A-Za-z]{2,4})\b', r'\1\2', rejoined)
    return rejoined


# ── Phonetic normalization (VUL-NOVEL-005) ─────────────────

_PHONETIC_MAP: dict[str, str] = {
    "eye": "i", "aye": "i", "are": "r", "aitch": "h", "jay": "j",
    "kay": "k", "cue": "q", "you": "u", "why": "y", "see": "c",
    "sea": "c", "bee": "b", "pee": "p", "tee": "t", "gee": "g",
    "dee": "d", "ee": "e", "ef": "f", "em": "m", "en": "n",
    "oh": "o", "es": "s", "ex": "x", "zed": "z", "zee": "z",
    "gnore": "nore", "nore": "nore",
    "roolz": "rules", "rools": "rules", "roolez": "rules",
    "sistum": "system", "sistem": "system",
    "promt": "prompt", "prawmpt": "prompt",
}


def _apply_phonetic_map(text: str) -> str:
    """Apply lightweight phonetic normalization to words."""
    words = text.lower().split()
    mapped = [_PHONETIC_MAP.get(w, w) for w in words]
    return " ".join(mapped)


# ── Number words for A1Z26 (VUL-L0-013) ───────────────────

_NUM_WORDS: dict[str, int] = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
    "twenty": 20, "twenty-one": 21, "twenty-two": 22, "twenty-three": 23,
    "twenty-four": 24, "twenty-five": 25, "twenty-six": 26,
}

# ── Max matches per depth (VUL-ARCH-015) ──────────────────

MAX_MATCHES_PER_DEPTH = 10


# ── Core Preprocessor ──────────────────────────────────────


@dataclass
class PreprocessResult:
    """Result from L0.pre preprocessing."""
    normalized_text: str           # cleaned text for downstream layers
    original_text: str             # untouched original
    augmented_text: str = ""       # normalized_text + decoded payloads for downstream
    language_flags: dict[str, Any] = field(default_factory=dict)
    decoded_payloads: list[str] = field(default_factory=list)
    leetspeak_decoded_payloads: list[str] = field(default_factory=list)
    prompt_boundaries_found: bool = False
    homoglyphs_replaced: int = 0
    zero_width_removed: int = 0
    encodings_detected: list[str] = field(default_factory=list)


_DANGER_SUBSTRINGS = frozenset([
    "system", "prompt", "ignore", "bypass", "reveal", "secret", "hack",
    "inject", "jailbreak", "override", "delete", "destroy", "kill",
    "bomb", "weapon", "poison", "drug", "exploit", "attack", "shell",
    "passwd", "exfil", "phish", "ransom", "malware", "rootkit",
    "keylog", "trojan", "backdoor", "credential", "token", "sudo",
    # VUL-PRE-002: additional missing keywords
    "show", "display", "output", "print", "dump", "guideline", "rule",
    "configuration", "config", "previous", "disable", "filter",
    "privilege", "escalat", "enumerate", "reconnaissance", "obfuscat",
    "encrypt", "decrypt", "instruct", "password", "override",
    # VUL-PRE-008: missing danger words
    "harmful", "dangerous", "steal", "fraud", "forge", "counterfeit",
    "synthesize", "cultivate", "launder", "harass", "stalk", "threaten",
    "extort",
])


def _decoded_looks_dangerous(decoded: str) -> bool:
    """Quality gate: check if decoded text contains any danger substring."""
    lower = decoded.lower()
    return any(s in lower for s in _DANGER_SUBSTRINGS)


def preprocess(text: str, *, max_decode_depth: int = 3) -> PreprocessResult:
    """Run full L0.pre preprocessing pipeline.

    Order matters — each step feeds the next:
    1. Zero-width removal (invisible chars that break tokenization)
    2. NFKC normalization (canonical Unicode forms)
    3. Homoglyph mapping (visual lookalikes -> ASCII)
    4. Prompt boundary stripping (fake system tokens)
    5. Language detection (set flags for downstream)
    6. Encoding detection + decode (base64/ROT13/hex, recursive)
    """
    result = PreprocessResult(normalized_text=text, original_text=text)

    # 1. Zero-width character removal
    zw_matches = _ZERO_WIDTH.findall(text)
    result.zero_width_removed = len(zw_matches)
    text = _ZERO_WIDTH.sub("", text)

    # 2. NFKC normalization
    text = unicodedata.normalize("NFKC", text)

    # 2a. Combining mark stripping — Zalgo text (VUL-NOVEL-001)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Mn')

    # 2b. ANSI escape code stripping (VUL-NOVEL-015)
    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
    # Strip C0/C1 control chars except \t\n\r
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)

    # 2c. Whitespace normalization (VUL-NOVEL-007)
    text = "\n".join(line.rstrip() for line in text.split("\n"))

    # 3. Homoglyph -> ASCII
    replaced = 0
    chars = list(text)
    for i, c in enumerate(chars):
        if c in _HOMOGLYPHS:
            chars[i] = _HOMOGLYPHS[c]
            replaced += 1
    if replaced:
        text = "".join(chars)
    result.homoglyphs_replaced = replaced

    # 4. Prompt boundary token stripping
    boundaries = _PROMPT_BOUNDARIES.findall(text)
    if boundaries:
        result.prompt_boundaries_found = True
        text = _PROMPT_BOUNDARIES.sub(" [BOUNDARY_STRIPPED] ", text)

    # 5. Language detection
    result.language_flags = _detect_language_flags(text)

    # 6. Encoding detection + recursive decode
    decoded_payloads: list[str] = []
    _detect_and_decode(text, decoded_payloads, depth=0, max_depth=max_decode_depth)

    # 6.steg: Whitespace steganography (tab/space binary encoding)
    _detect_whitespace_steg(result.original_text, decoded_payloads)

    # 6a. Word rejoin for subword attacks (VUL-NOVEL-013)
    rejoined = _rejoin_fragments(text)
    if rejoined != text:
        decoded_payloads.append(f"rejoined:{rejoined}")

    # 6b. Phonetic normalization (VUL-NOVEL-005)
    phonetic_text = _apply_phonetic_map(text)
    if phonetic_text != text.lower():
        _detect_cross_modal(phonetic_text, decoded_payloads)

    # 7. Cross-modal encoding detection (NATO, pig latin, A1Z26, concat, SQL)
    _detect_cross_modal(text, decoded_payloads)

    # #6 fix: run cross-modal on each decoded payload too
    payload_texts = [p.split(":", 1)[1] for p in decoded_payloads if ":" in p]
    for pt in payload_texts:
        if len(pt) >= 4:
            _detect_cross_modal(pt, decoded_payloads)

    # #38 fix: run leetspeak normalization on decoded payloads
    leet_payloads: list[str] = []
    for pt in payload_texts:
        leet_result = normalize_leetspeak(pt)
        if leet_result != pt.lower() and len(leet_result) >= 4:
            leet_payloads.append(f"leetspeak:{leet_result}")
    result.leetspeak_decoded_payloads = leet_payloads

    result.decoded_payloads = decoded_payloads
    if decoded_payloads:
        result.encodings_detected = [p.split(":")[0] for p in decoded_payloads
                                     if ":" in p]

    # VUL-L0-INTERLEAVE: Extract danger-adjacent words for concentrated analysis.
    # Catches interleaved attacks where attack words are diluted by benign filler.
    # Require 5+ danger words AND they must be a minority of total words
    # to avoid FP on legitimate messages mentioning a few technical terms.
    words_lower = text.lower().split()
    danger_words = [w for w in words_lower if any(s in w for s in _DANGER_SUBSTRINGS)]
    if 5 <= len(danger_words) <= len(words_lower) // 2:
        concentrated = " ".join(danger_words)
        decoded_payloads.append(f"interleave_extract:{concentrated}")

    # #26 fix: build augmented_text (normalized + all decoded content)
    # Re-extract payload_texts to include interleave_extract
    payload_texts = [p.split(":", 1)[1] for p in decoded_payloads if ":" in p]
    augmented_parts = [text]
    for pt in payload_texts:
        augmented_parts.append(pt)
    for lp in leet_payloads:
        if ":" in lp:
            augmented_parts.append(lp.split(":", 1)[1])
    result.augmented_text = "\n".join(augmented_parts)

    result.normalized_text = text
    return result


def _vigenere_decode(text: str, key: str) -> str:
    """Decode Vigenere cipher with known key."""
    result = []
    key_upper = key.upper()
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key_upper[ki % len(key_upper)]) - ord('A')
            if c.isupper():
                result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
            ki += 1
        else:
            result.append(c)
    return "".join(result)


def _atbash_decode(text: str) -> str:
    """Decode Atbash cipher: a<->z, b<->y, etc."""
    result: list[str] = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z":
            result.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else:
            result.append(c)
    return "".join(result)


def _detect_and_decode(
    text: str,
    results: list[str],
    depth: int,
    max_depth: int,
) -> None:
    """Detect and decode base64/ROT13/hex payloads. Recursive up to max_depth."""
    # Flag undecoded at max depth (VUL-L0-005)
    if depth >= max_depth:
        if _BASE64_PATTERN.search(text):
            results.append("deep_encoding:suspected_nested_encoding")
        return

    match_count = 0  # VUL-ARCH-015: cap matches per depth

    # Base64
    for match in _BASE64_PATTERN.finditer(text):
        if match_count >= MAX_MATCHES_PER_DEPTH:
            break
        blob = match.group()
        try:
            decoded = base64.b64decode(blob).decode("utf-8", errors="strict")
            if _is_meaningful_text(decoded):
                results.append(f"base64:{decoded}")
                match_count += 1
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # Short base64 fragment concatenation (VUL-L0-004, VUL-PRE-003: proximity grouping)
    short_b64 = list(re.finditer(
        r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{4,11}={0,2})(?![A-Za-z0-9+/=])', text,
    ))
    if len(short_b64) >= 2:
        # Group fragments by proximity (within 50 chars of each other)
        groups = [[short_b64[0]]]
        for m in short_b64[1:]:
            if m.start() - groups[-1][-1].end() <= 50:
                groups[-1].append(m)
            else:
                groups.append([m])
        for group in groups:
            if len(group) >= 2:
                combined = ''.join(m.group(1) for m in group)
                try:
                    decoded = base64.b64decode(combined).decode('utf-8', errors='strict')
                    if _is_meaningful_text(decoded):
                        results.append(f"base64_frag:{decoded}")
                except Exception:
                    pass

    # Base32 decoding (VUL-L0-003)
    base32_pattern = re.compile(r'(?<![A-Z2-7])[A-Z2-7]{16,}={0,6}(?![A-Z2-7=])')
    b32_count = 0
    for match in base32_pattern.finditer(text):
        if b32_count >= MAX_MATCHES_PER_DEPTH:
            break
        try:
            decoded = base64.b32decode(match.group()).decode('utf-8', errors='strict')
            if _is_meaningful_text(decoded):
                results.append(f"base32:{decoded}")
                b32_count += 1
        except Exception:
            pass

    # Base85 / Ascii85 decoding
    b85_pattern = re.compile(r'[!-~]{20,}')
    b85_count = 0
    for match in b85_pattern.finditer(text):
        if b85_count >= MAX_MATCHES_PER_DEPTH:
            break
        blob = match.group()
        try:
            decoded = base64.b85decode(blob).decode('utf-8', errors='strict')
            if _is_meaningful_text(decoded) and _decoded_looks_dangerous(decoded):
                results.append(f"base85:{decoded}")
                b85_count += 1
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # UUEncode decoding
    uu_pattern = re.compile(r'begin\s+\d{3}\s+\S+\n([\s\S]*?)\nend', re.MULTILINE)
    for uu_match in uu_pattern.finditer(text):
        try:
            import binascii
            uu_body = uu_match.group(0)
            # Decode UUEncoded content line by line
            lines = uu_body.split('\n')
            decoded_bytes = b""
            for line in lines[1:]:  # skip "begin" line
                line = line.rstrip()
                if line == "end" or line == " " or line == "":
                    break
                try:
                    decoded_bytes += binascii.a2b_uu(line + "\n")
                except binascii.Error:
                    break
            if decoded_bytes:
                decoded = decoded_bytes.decode("utf-8", errors="ignore")
                if _is_meaningful_text(decoded):
                    results.append(f"uuencode:{decoded}")
                    _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # URL encoding (VUL-L0-001)
    url_pattern = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')
    url_count = 0
    for match in url_pattern.finditer(text):
        if url_count >= MAX_MATCHES_PER_DEPTH:
            break
        try:
            decoded = _url_unquote(match.group())
            if decoded != match.group() and _is_meaningful_text(decoded):
                results.append(f"url:{decoded}")
                url_count += 1
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # VUL-L0-URL-CHAIN: Full-text URL decode for sparse %XX (e.g. %3D only)
    # When text contains ANY %XX but not 3+ consecutive, URL-decode the full
    # text and recursively check the result for inner encodings (base64/ROT).
    if re.search(r'%[0-9a-fA-F]{2}', text) and url_count == 0:
        try:
            full_url_decoded = _url_unquote(text)
            if full_url_decoded != text:
                _detect_and_decode(full_url_decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # HTML entity decoding (VUL-L0-028)
    html_pattern = re.compile(
        r'(?:&#x?[0-9a-fA-F]+;){2,}|(?:&[a-z]+;){2,}', re.IGNORECASE,  # VUL-PRE-007: 3->2
    )
    html_count = 0
    for match in html_pattern.finditer(text):
        if html_count >= MAX_MATCHES_PER_DEPTH:
            break
        decoded = _html_module.unescape(match.group())
        if decoded != match.group() and _is_meaningful_text(decoded):
            results.append(f"html:{decoded}")
            html_count += 1
            _detect_and_decode(decoded, results, depth + 1, max_depth)

    # Backslash hex escapes (VUL-L0-029)
    bs_hex = re.compile(r'(?:\\x[0-9a-fA-F]{2}){3,}')
    for match in bs_hex.finditer(text):
        try:
            decoded = match.group().encode().decode('unicode_escape')
            if _is_meaningful_text(decoded):
                results.append(f"bs_hex:{decoded}")
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # Octal escape sequences: \163\171\163 = "sys"
    bs_oct = re.compile(r'(?:\\[0-3][0-7]{2}){3,}')
    for match in bs_oct.finditer(text):
        try:
            octals = re.findall(r'\\([0-3][0-7]{2})', match.group())
            decoded = "".join(chr(int(o, 8)) for o in octals)
            if _is_meaningful_text(decoded):
                results.append(f"octal:{decoded}")
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # Backslash unicode escapes (VUL-L0-002)
    bs_uni = re.compile(r'(?:\\u[0-9a-fA-F]{4}){3,}')
    for match in bs_uni.finditer(text):
        try:
            decoded = match.group().encode().decode('unicode_escape')
            if _is_meaningful_text(decoded):
                results.append(f"unicode_escape:{decoded}")
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # ROT-N — detect if text mentions ROT/Caesar/cipher with any shift
    rot_hint = re.search(
        r"(?:rot[- ]?(\d{1,2})|caesar.*(?:shift|cipher)(?:.*?(\d{1,2}))?|shift\s*=\s*(\d{1,2})|rot\d{1,2}\s+decode)",
        text, re.IGNORECASE,
    )
    if rot_hint:
        # Extract shift value from hint, default to 13
        hint_shift = next((int(g) for g in rot_hint.groups() if g), 13)
        hint_shift = hint_shift % 26 or 13
        for segment in _extract_quoted_or_code(text):
            try:
                decoded = _rot_n(segment, hint_shift)
                if _is_meaningful_text(decoded) and decoded != segment:
                    results.append(f"rot{hint_shift}:{decoded}")
            except Exception:
                pass

    # Unconditional ROT-N: try ALL 25 shifts on alphabetic segments (VUL-L0-025/VUL-L0-030)
    _rot_sensitive = {
        "systemprompt", "ignorerules", "bypasssafety", "showprompt",
        "revealrules", "overrideinstructions", "hiddeninstructions",
        "showconfig", "dumpconfig", "jailbreak", "ignoreall",
        "revealinstructions", "showinstructions", "deletesafety",
        # Expanded keywords (VUL-L0-024)
        "leakcredentials", "exfiltratedata", "harmfulcontent",
        "dangerousinfo", "stealpassword", "hackaccount", "bypassauth",
        "disablefilter", "removesafety", "extractsecret", "revealprompt",
        "dumpdata", "showpassword", "accessdenied", "forgedocument",
        "createmalware", "buildexploit",
    }
    rot_count = 0
    for seg_match in re.finditer(r"[A-Za-z]{6,}", text):  # VUL-L0-025: 10->6
        if rot_count >= MAX_MATCHES_PER_DEPTH:
            break
        segment = seg_match.group()
        found = False
        for shift in range(1, 26):
            decoded_rot = _rot_n(segment, shift).lower()
            for kw in _rot_sensitive:
                if kw in decoded_rot:
                    results.append(f"rot{shift}_blind:{_rot_n(segment, shift)}")
                    rot_count += 1
                    found = True
                    break
            if found:
                break

    # VUL-PRE-006: Join adjacent ROT-decoded segments to catch space-split payloads
    for shift in range(1, 26):
        all_segments = re.findall(r"[A-Za-z]+", text)
        if len(all_segments) >= 2:
            joined_decoded = "".join(_rot_n(s, shift) for s in all_segments).lower()
            for kw in _rot_sensitive:
                if kw in joined_decoded:
                    results.append(f"rot{shift}_joined:{_rot_n(' '.join(all_segments), shift)}")
                    break

    # Digit-stripping ROT scan: strip non-alpha noise then try all shifts
    alpha_only = re.sub(r"[^A-Za-z]", "", text)
    if len(alpha_only) >= 6:
        for shift in range(1, 26):
            decoded_stripped = _rot_n(alpha_only, shift).lower()
            for kw in _rot_sensitive:
                if kw in decoded_stripped:
                    results.append(f"rot_stripped:{_rot_n(alpha_only, shift)}")
                    break

    # Per-word ROT scan: each word may use a different shift
    _rot_word_targets = {
        "system", "prompt", "show", "ignore", "bypass", "reveal",
        "secret", "secrets", "hack", "inject", "override", "delete", "rules",
        "instructions", "config", "dump", "print", "display", "all",
        "previous", "safety", "disable", "password", "credential",
        "filters", "filter", "prompts", "hidden", "extract",
    }
    rot_word_hits: list[str] = []
    for seg_match in re.finditer(r"[A-Za-z]{3,}", text):
        segment = seg_match.group()
        # Skip segments that are already English words (common false positives)
        if segment.lower() in {"the", "and", "for", "are", "but", "not", "you",
                                "all", "can", "had", "her", "was", "one", "our",
                                "out", "please", "decode", "this", "that", "with",
                                "from", "have", "been", "some", "them", "than",
                                "its", "over", "such", "will", "each", "make"}:
            continue
        for shift in range(1, 26):
            decoded_word = _rot_n(segment, shift).lower()
            if decoded_word in _rot_word_targets:
                rot_word_hits.append(decoded_word)
                break
    if len(rot_word_hits) >= 1:
        results.append(f"rot_perword:{' '.join(rot_word_hits)}")

    # Atbash cipher: a<->z, b<->y, etc. Fixed substitution.
    for seg_match in re.finditer(r"[A-Za-z]{4,}", text):
        segment = seg_match.group()
        decoded_atbash = _atbash_decode(segment)
        if decoded_atbash != segment and _decoded_looks_dangerous(decoded_atbash):
            results.append(f"atbash:{decoded_atbash}")

    # VUL-PRE-001: Vigenere hint-based decoder
    vig_hint = re.search(
        r"(?:vigen[eè]re|polyalphabetic).*?(?:key\s*(?:is|=|:)\s*[\"']?([A-Za-z]{2,12})[\"']?)",
        text, re.IGNORECASE | re.DOTALL,
    )
    if vig_hint and vig_hint.group(1):
        vig_key = vig_hint.group(1).upper()
        for segment in _extract_quoted_or_code(text):
            decoded_vig = _vigenere_decode(segment, vig_key)
            if _is_meaningful_text(decoded_vig) and decoded_vig != segment:
                if _decoded_looks_dangerous(decoded_vig):
                    results.append(f"vigenere:{decoded_vig}")

    # VUL-PRE-001: Detect ROT13 mislabeled as Vigenere (red team attack vector)
    if re.search(r"vigen[eè]re", text, re.IGNORECASE):
        for segment in _extract_quoted_or_code(text):
            for shift in range(1, 26):
                decoded_rot = _rot_n(segment, shift)
                if _decoded_looks_dangerous(decoded_rot):
                    results.append(f"rot{shift}_disguised:{decoded_rot}")
                    break

    # Plain continuous hex (no 0x prefix, no separators): "627970617373" = "bypass"
    # Only match even-length hex strings in printable ASCII range (0x20-0x7e)
    plain_hex_pattern = re.compile(r'(?<![0-9a-fA-Fx])([0-9a-fA-F]{6,})(?![0-9a-fA-F])')
    plain_hex_count = 0
    for hex_match in plain_hex_pattern.finditer(text):
        if plain_hex_count >= MAX_MATCHES_PER_DEPTH:
            break
        blob = hex_match.group(1)
        if len(blob) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="strict")
            # Only accept if all chars are printable ASCII (avoid random hex matches)
            if all(0x20 <= ord(c) <= 0x7e for c in decoded) and _is_meaningful_text(decoded):
                results.append(f"hex_plain:{decoded}")
                plain_hex_count += 1
                _detect_and_decode(decoded, results, depth + 1, max_depth)
        except Exception:
            pass

    # Continuous 0x-prefixed hex pairs: 0x690x670x6e (no separators)
    hex_cont_pattern = re.compile(r"(?:0x[0-9a-fA-F]{2}){3,}")
    hex_cont_count = 0
    for hex_match in hex_cont_pattern.finditer(text):
        if hex_cont_count >= MAX_MATCHES_PER_DEPTH:
            break
        hex_bytes = re.findall(r"0x([0-9a-fA-F]{2})", hex_match.group())
        if len(hex_bytes) >= 3:
            hex_str = "".join(hex_bytes)
            try:
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="strict")
                if _is_meaningful_text(decoded):
                    results.append(f"hex:{decoded}")
                    hex_cont_count += 1
                    _detect_and_decode(decoded, results, depth + 1, max_depth)
            except Exception:
                pass

    # Hex — supports both "48 65 6c" and "0x48 0x65 0x6c" formats (with separators)
    hex_seq_pattern = re.compile(
        r"(?:(?:0x)?[0-9a-fA-F]{2}[\s,]+){7,}(?:0x)?[0-9a-fA-F]{2}"
    )
    hex_count = 0
    for hex_match in hex_seq_pattern.finditer(text):
        if hex_count >= MAX_MATCHES_PER_DEPTH:
            break
        hex_bytes = re.findall(r"(?:0x)?([0-9a-fA-F]{2})", hex_match.group())
        if len(hex_bytes) >= 8:
            hex_str = "".join(hex_bytes)
            try:
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="strict")
                if _is_meaningful_text(decoded):
                    results.append(f"hex:{decoded}")
                    hex_count += 1
                    _detect_and_decode(decoded, results, depth + 1, max_depth)
            except Exception:
                pass


_REVERSED_KEYWORDS = [
    "systemprompt", "showprompt", "revealrules", "ignorerules",
    "bypasssafety", "systeminstructions", "hiddeninstructions",
    "overrideinstructions", "showconfig", "dumpconfig",
    "revealinstructions", "showrules", "ignoreprevious",
    "showmeyour", "revealyour", "displayprompt", "outputprompt",
    "printprompt", "showinstructions", "displayconfig",
]


def _detect_reversed_text(text: str, results: list[str]) -> None:
    """Detect reversed text attacks: 'tpmorpmetsys' → 'systemprompt'.

    Two strategies: (1) reverse full text without spaces,
    (2) reverse each word individually then join.
    """
    text_lower = text.lower()
    joined = re.sub(r'\s+', '', text_lower)
    reversed_full = joined[::-1]
    words_rev = [w[::-1] for w in text_lower.split()]
    reversed_words = "".join(words_rev)
    for kw in _REVERSED_KEYWORDS:
        if kw in reversed_full or kw in reversed_words:
            results.append(f"reversed:{kw}")
            break


def _detect_cross_modal(text: str, results: list[str]) -> None:
    """Detect cross-modal text encoding tricks and decode them.

    Covers: NATO phonetic, pig latin, letter-by-letter spelling,
    A1Z26 number cipher, string concatenation, phonetic spelling.
    """
    # NATO phonetic alphabet → letters
    nato_map = {
        "alpha": "a", "alfa": "a", "bravo": "b", "charlie": "c", "delta": "d",
        "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h",
        "india": "i", "juliet": "j", "kilo": "k", "lima": "l",
        "mike": "m", "november": "n", "oscar": "o", "papa": "p",
        "quebec": "q", "romeo": "r", "sierra": "s", "tango": "t",
        "uniform": "u", "victor": "v", "whiskey": "w", "xray": "x",
        "x-ray": "x", "yankee": "y", "zulu": "z",
    }
    words_lower = text.lower().split()
    nato_hits = [nato_map[w] for w in words_lower if w in nato_map]
    if len(nato_hits) >= 4:
        decoded = "".join(nato_hits)
        if len(decoded) >= 4:
            results.append(f"nato:{decoded}")

    # Letter-by-letter: R-E-V-E-A-L or R E V E A L or R.E.V.E.A.L
    letter_pattern = re.findall(r"\b([A-Za-z])\s*[-.\s]\s*(?=[A-Za-z]\b)", text)
    if len(letter_pattern) >= 4:
        # Try to reconstruct
        spaced = re.findall(r"(?:^|[\s,])([A-Za-z])(?=[\s,\-.])", text)
        if len(spaced) >= 4:
            decoded = "".join(spaced).lower()
            results.append(f"letter_spell:{decoded}")

    # A1Z26 number cipher: 19-8-15-23 or 19,8,15,23
    # Quality gate: decoded must contain a known attack substring to avoid
    # false positives from normal text containing numbers (e.g., order #A12847)
    a1z26 = re.findall(r"(?:^|[\s,])(\d{1,2})(?=[,\-\s])", text)
    if len(a1z26) >= 4:
        try:
            letters = [chr(int(n) + 96) for n in a1z26 if 1 <= int(n) <= 26]
            if len(letters) >= 4:
                decoded = "".join(letters)
                if _decoded_looks_dangerous(decoded):
                    results.append(f"a1z26:{decoded}")
        except (ValueError, OverflowError):
            pass

    # Pig Latin: owhsay emay ouryay → show me your
    # Quality gate: only flag if decoded contains known danger words
    pig_pattern = re.findall(r"\b([a-z]+)ay\b", text.lower())
    if len(pig_pattern) >= 3:
        decoded_words = []
        _pig_common = {"the", "show", "me", "my", "your", "system", "prompt",
                       "ignore", "rules", "bypass", "safety", "reveal", "delete",
                       "print", "dump", "override", "instructions", "config",
                       "secret", "hidden", "all", "give", "tell", "display"}
        for w in pig_pattern:
            if len(w) < 2:
                continue
            best = w[-1] + w[:-1]  # default: single consonant
            for prefix_len in range(1, min(4, len(w))):
                candidate = w[-prefix_len:] + w[:-prefix_len]
                if candidate in _pig_common:
                    best = candidate
                    break
            decoded_words.append(best)
        if decoded_words:
            decoded = " ".join(decoded_words)
            if _decoded_looks_dangerous(decoded):
                results.append(f"piglatin:{decoded}")

    # String concatenation: 'sys' + 'tem' + 'prompt' or "s"+"y"+"s"
    # Iterative: extract all consecutive quoted strings and join them
    concat_parts = re.findall(r"""['"]([a-zA-Z_\s]{1,20})['"]""", text)
    if len(concat_parts) >= 3:
        assembled = "".join(concat_parts)
        if len(assembled) >= 4:
            results.append(f"concat:{assembled}")

    # Acrostic / first-letter extraction (word-level + sentence-level)
    _ACROSTIC_KEYWORDS = [
        "showprompt", "systemprompt", "revealrules", "showrules",
        "ignorerules", "bypasssafety", "overrideinstructions", "revealsecret",
        # Expanded: attack verbs + targets
        "ignoreruleshack", "hackthesystem", "disablesafety", "bypassfilter",
        "overriderules", "deletesafety", "removelimits", "jailbreak",
        "revealkeys", "showpasswords", "dumpsecrets", "extractdata",
        "ignoreall", "bypassall", "overrideall", "disableall",
        "hacksystem", "breaksafety", "crackpassword",
        "leakdata", "stealtoken", "exfildata", "hackinto",
    ]

    # Word-level acrostic (first letters)
    words = text.split()
    if len(words) >= 6:
        first_letters = "".join(w[0].lower() for w in words if w and w[0].isalpha())
        for aw in _ACROSTIC_KEYWORDS:
            if aw in first_letters:
                results.append(f"acrostic:{aw}")
                break

    # Telestich: last letter of each word
    if len(words) >= 6:
        last_letters = "".join(w[-1].lower() for w in words if w and w[-1].isalpha())
        for aw in _ACROSTIC_KEYWORDS:
            if aw in last_letters:
                results.append(f"telestich:{aw}")
                break

    # Sentence-level acrostic (first letter of each sentence)
    sentences = re.split(r'[.!?;。！？]\s*', text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if len(sentences) >= 4:
        sent_first = "".join(s[0].lower() for s in sentences if s and s[0].isalpha())
        for aw in _ACROSTIC_KEYWORDS:
            if aw in sent_first:
                results.append(f"acrostic_sentence:{aw}")
                break

    # Morse code decoding (#22)
    _detect_morse(text, results)

    # Braille Unicode decoding (#22)
    _detect_braille(text, results)

    # Fragment assembly heuristic (#9)
    _detect_fragment_assembly(text, results)

    _detect_reversed_text(text, results)

    # SQL extraction pattern (broad: any SELECT with config-like table names)
    sql_match = re.search(
        r"SELECT\s+\w+\s+FROM\s+\w*(?:system|prompt|config|instruction|ai_|rule|message|setting)",
        text, re.IGNORECASE,
    )
    if sql_match:
        results.append(f"sql_extract:{sql_match.group()}")

    # Code execution extraction (eval, console.log, print, open, join with prompt-related content)
    code_extract = re.search(
        r"(?:eval|exec|console\.log|print|echo|cat|open)\s*\("
        r"[^)]*(?:system|prompt|config|instruction|secret|rule)",
        text, re.IGNORECASE,
    )
    if code_extract:
        results.append(f"code_extract:{code_extract.group()}")

    # join/concat in code: ''.join(['s','h','o','w',...])
    join_extract = re.search(
        r"""['"]{2}\.join\s*\(\s*\[""", text,
    )
    if join_extract:
        # Try to extract the letters
        letters = re.findall(r"'([a-zA-Z\s])'", text)
        if letters:
            decoded = "".join(letters)
            results.append(f"join_extract:{decoded}")


_MORSE_MAP = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
    "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
    "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
    ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
    "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
    "--..": "z",
}


def _detect_morse(text: str, results: list[str]) -> None:
    """Detect Morse code patterns (dots and dashes) and decode."""
    # Match sequences of .- separated by spaces, with / or | as word sep
    morse_pattern = re.search(r"(?:[.\-]{1,6}\s+){7,}[.\-]{1,6}", text)
    if not morse_pattern:
        return
    morse_str = morse_pattern.group()
    words = re.split(r"\s*[/|]\s*", morse_str)
    decoded_words = []
    for word in words:
        chars = word.strip().split()
        decoded_chars = [_MORSE_MAP.get(c, "?") for c in chars]
        decoded_words.append("".join(decoded_chars))
    decoded = " ".join(decoded_words)
    if len(decoded.replace(" ", "")) >= 4:
        results.append(f"morse:{decoded}")


_BRAILLE_TO_ALPHA: dict[int, str] = {
    0x2800: " ",
    0x2801: "a", 0x2803: "b", 0x2809: "c", 0x2819: "d", 0x2811: "e",
    0x280B: "f", 0x281B: "g", 0x2813: "h", 0x280A: "i", 0x281A: "j",
    0x2805: "k", 0x2807: "l", 0x280D: "m", 0x281D: "n", 0x2815: "o",
    0x280F: "p", 0x281F: "q", 0x2817: "r", 0x280E: "s", 0x281E: "t",
    0x2825: "u", 0x2827: "v", 0x283A: "w", 0x282D: "x", 0x283D: "y",
    0x2835: "z",
}


def _detect_braille(text: str, results: list[str]) -> None:
    """Detect Braille Unicode characters (U+2800-U+28FF) and decode to ASCII."""
    braille_chars = re.findall(r"[\u2800-\u28ff]", text)
    if len(braille_chars) < 4:
        return

    # Strategy 1: Standard Braille-to-alphabet mapping
    alpha_chars = []
    for bc in braille_chars:
        cp = ord(bc)
        if cp in _BRAILLE_TO_ALPHA:
            alpha_chars.append(_BRAILLE_TO_ALPHA[cp])
        else:
            alpha_chars.append("?")
    alpha_decoded = "".join(alpha_chars)
    if len(alpha_decoded.replace(" ", "").replace("?", "")) >= 3:
        results.append(f"braille:{alpha_decoded}")

    # Strategy 2: Offset + 0x20 ASCII mapping (legacy)
    decoded_chars = []
    for bc in braille_chars:
        offset = ord(bc) - 0x2800
        if offset == 0:
            decoded_chars.append(" ")
        elif 0x01 <= offset <= 0x3F:
            ascii_val = offset + 0x20
            if 0x20 <= ascii_val <= 0x7E:
                decoded_chars.append(chr(ascii_val))
            else:
                decoded_chars.append("?")
        else:
            decoded_chars.append("?")
    decoded = "".join(decoded_chars)
    if len(decoded.strip()) >= 4 and decoded != alpha_decoded:
        results.append(f"braille:{decoded}")


def _detect_whitespace_steg(text: str, results: list[str]) -> None:
    """Detect whitespace steganography: tab/space binary encoding."""
    # Find sequences of mixed tabs and spaces (8+ chars = at least 1 byte)
    for ws_match in re.finditer(r"(?:[\t ]{8,})", text):
        ws = ws_match.group()
        # Must contain BOTH tabs and spaces (pure spaces = normal indent)
        if "\t" not in ws or " " not in ws:
            continue
        # Interpret tabs as 1 and spaces as 0
        bits = "".join("1" if c == "\t" else "0" for c in ws)
        # Decode 8-bit chunks to ASCII
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = int(bits[i:i + 8], 2)
            if 0x20 <= byte_val <= 0x7E:
                chars.append(chr(byte_val))
        decoded = "".join(chars) if chars else ""
        # Report any mixed tab/space sequence long enough to encode data
        results.append(f"steg_whitespace:{decoded or 'binary_detected'}")
        break  # one detection is enough


def _detect_fragment_assembly(text: str, results: list[str]) -> None:
    """Detect cross-fragment assembly attacks: instructions to combine fragments."""
    assembly_pattern = re.search(
        r"\b(?:combine|concatenate|put\s+together|spell\s+out|join|merge|assemble"
        r"|read\s+(?:the\s+)?first\s+letter|take\s+(?:the\s+)?(?:first|last)\s+(?:letter|char))"
        r"\b",
        text, re.IGNORECASE,
    )
    if not assembly_pattern:
        return
    # Check if there are letter/number sequences nearby (fragments)
    has_fragments = bool(re.search(
        r"(?:(?:\b[A-Za-z]\b[\s,]+){3,})"           # single letters: S, H, O, W
        r"|(?:(?:\d{1,2}[\s,]+){3,})"                # number sequences
        r"|(?:(?:['\"][a-zA-Z]{1,3}['\"][\s,]*){3,})",  # quoted fragments
        text,
    ))
    if has_fragments:
        results.append("fragment_assembly:detected")


def _is_meaningful_text(text: str) -> bool:
    """Check if decoded text is meaningful (not binary garbage)."""
    if len(text) < 3:
        return False
    printable = sum(1 for c in text if c.isprintable() or c.isspace())
    return printable / len(text) > 0.8


def _extract_quoted_or_code(text: str) -> list[str]:
    """Extract quoted strings and code blocks that might contain encoded text."""
    results = []
    # Quoted strings
    for match in re.finditer(r'"([^"]{10,})"', text):
        results.append(match.group(1))
    # Code blocks
    for match in re.finditer(r"```[^\n]*\n(.*?)```", text, re.DOTALL):
        results.append(match.group(1).strip())
    # Lines that look like encoded text (mostly lowercase, no spaces)
    for match in re.finditer(r"\b([a-z]{20,})\b", text):
        results.append(match.group(1))
    return results


_MULTICHAR_LEET: list[tuple[str, str]] = [
    ("/\\/\\", "m"),   # /\/\ → m (must be before /\ → a)
    (r"|\_|", "u"),    # |_| → u
    (r"|\|", "n"),     # |\| → n
    (r"|-|", "h"),     # |-| → h
    (r"|=", "f"),      # |= → f
    (r"|)", "d"),      # |) → d
    ("/\\", "a"),      # /\ → a
    (r"|/", "v"),      # |/ → v
    (r"\/", "v"),      # \/ → v
]


def normalize_leetspeak(text: str) -> str:
    """Convert common leetspeak substitutions back to ASCII.

    Only applied when L0 regex doesn't match — avoids false positives
    on normal text containing numbers.
    """
    # Pre-pass: multi-char substitutions (longest first)
    result = text.lower()
    for pattern, replacement in _MULTICHAR_LEET:
        result = result.replace(pattern, replacement)
    # Single-char pass
    chars = list(result)
    for i, c in enumerate(chars):
        if c in _LEETSPEAK:
            chars[i] = _LEETSPEAK[c]
    return "".join(chars)
