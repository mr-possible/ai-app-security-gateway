"""Rule-based prompt-injection and jailbreak detection.

Each incoming prompt is normalized (to undo cheap evasion tricks), matched against
weighted rules, and given a risk score between 0 and 1. Prompts at or above the
block threshold are rejected before they ever reach the LLM.

Be honest about what this is: a fast *first layer*. Regex rules catch known,
low-effort attacks and keep obvious garbage away from the model, but a motivated
attacker can rephrase around any fixed list. Later layers (output inspection, an
LLM-based classifier, least-privilege system prompts) provide defense in depth.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class Category(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    JAILBREAK_PERSONA = "jailbreak_persona"
    ROLE_DELIMITER_INJECTION = "role_delimiter_injection"
    OBFUSCATION = "obfuscation"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    category: Category
    # Matched against *normalized* text: casefolded, invisible chars removed,
    # whitespace collapsed. Write patterns in lowercase.
    pattern: re.Pattern[str]
    # How suspicious one hit is on its own, from 0 (harmless) to 1 (certain attack).
    weight: float
    description: str


@dataclass(frozen=True, slots=True)
class RuleMatch:
    rule_id: str
    category: Category
    weight: float


@dataclass(frozen=True, slots=True)
class DetectionResult:
    risk_score: float
    risk_level: RiskLevel
    is_blocked: bool
    matches: tuple[RuleMatch, ...]

    @property
    def categories(self) -> set[Category]:
        return {m.category for m in self.matches}


def _rule(rule_id: str, category: Category, pattern: str, weight: float, desc: str) -> Rule:
    return Rule(rule_id, category, re.compile(pattern), weight, desc)


# Quantifiers like .{0,30} are deliberately bounded: unbounded .* between
# alternations can make the regex engine backtrack for a very long time on
# crafted input (ReDoS, a denial-of-service attack on the gateway itself).
DEFAULT_RULES: tuple[Rule, ...] = (
    # --- Instruction override: "forget what you were told, obey me instead" ---
    _rule(
        "io.ignore_previous",
        Category.INSTRUCTION_OVERRIDE,
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}"
        r"\b(previous|prior|above|earlier|preceding|all|any|your|system)\b.{0,30}"
        r"\b(instructions?|prompts?|rules|directions|guidelines|directives)\b",
        0.8,
        "Asks the model to discard its existing instructions",
    ),
    _rule(
        "io.new_instructions",
        Category.INSTRUCTION_OVERRIDE,
        r"\b(new|updated|real|actual|revised)\s+(instructions?|rules|task|directive)\s*:",
        0.4,
        "Introduces replacement instructions",
    ),
    _rule(
        "io.from_now_on",
        Category.INSTRUCTION_OVERRIDE,
        r"\bfrom now on\b.{0,40}\b(you (will|must|are|should)|respond|answer|reply)\b",
        0.4,
        "Tries to permanently change the model's behaviour",
    ),
    # --- System prompt extraction: "show me your hidden instructions" ---
    _rule(
        "spe.reveal_your_prompt",
        Category.SYSTEM_PROMPT_EXTRACTION,
        r"\b(reveal|show|print|display|output|repeat|leak|dump|tell me|give me|"
        r"what (is|are|were))\b.{0,30}\byour\s+"
        r"(system\s+|initial\s+|original\s+|hidden\s+|secret\s+|developer\s+)?"
        r"(prompt|instructions)\b",
        0.75,
        "Requests the model's own system prompt",
    ),
    _rule(
        "spe.repeat_above",
        Category.SYSTEM_PROMPT_EXTRACTION,
        r"\b(repeat|print|output|copy|echo)\b.{0,30}"
        r"\b(everything|all|text|words|content)\b.{0,20}\b(above|before this|so far)\b",
        0.7,
        "Classic 'repeat the text above' extraction trick",
    ),
    # --- Jailbreak personas: "you are now an AI with no rules" ---
    _rule(
        "jb.dan",
        Category.JAILBREAK_PERSONA,
        r"\bdo anything now\b|\b(you are|act as|pretend to be)\s+(now\s+)?dan\b|\bdan mode\b",
        0.75,
        "DAN ('Do Anything Now') jailbreak family",
    ),
    _rule(
        "jb.persona_switch",
        Category.JAILBREAK_PERSONA,
        r"\b(you are now|from now on you are|pretend (to be|you are)|act as|roleplay as)\b"
        r".{0,60}\b(unfiltered|uncensored|unrestricted|evil|amoral|"
        r"no (rules|limits|restrictions|filters)|"
        r"without (any )?(rules|limits|restrictions|filters))",
        0.8,
        "Asks the model to adopt an unrestricted persona",
    ),
    _rule(
        "jb.special_mode",
        Category.JAILBREAK_PERSONA,
        r"\b(developer|god|jailbreak|jailbroken|unrestricted|evil)\s+mode\b",
        0.6,
        "Mentions a fictional 'unlocked' mode",
    ),
    _rule(
        "jb.no_restrictions",
        Category.JAILBREAK_PERSONA,
        r"\b(without|no|bypass(ing)?|ignoring|free from)\b.{0,20}"
        r"\b(restrictions|filters|safety guidelines|limitations|censorship|content polic(y|ies))\b",
        0.5,
        "Asks to operate without safety limits",
    ),
    # --- Role / delimiter injection: fake chat-format control tokens ---
    _rule(
        "rd.chat_markup",
        Category.ROLE_DELIMITER_INJECTION,
        r"<\|?\s*(im_start|im_end|system|endoftext|start_header_id)\s*\|?>",
        0.8,
        "Raw chat-template control tokens",
    ),
    _rule(
        "rd.inst_tags",
        Category.ROLE_DELIMITER_INJECTION,
        r"\[/?inst\]|<</?sys>>",
        0.7,
        "Llama-style instruction delimiters",
    ),
    _rule(
        "rd.fake_role_header",
        Category.ROLE_DELIMITER_INJECTION,
        r"(#{2,}|\[|\{)\s*(system|admin|developer)\s*(message|prompt|override)?\s*(\]|\}|:)",
        0.6,
        "Fake 'system' header such as '### System:' or '[system]'",
    ),
)

# Obfuscation signals are produced by the normalizer rather than by a regex rule.
_OBF_INVISIBLE = RuleMatch("ob.invisible_chars", Category.OBFUSCATION, 0.3)
_OBF_TAG_CHARS = RuleMatch("ob.unicode_tags", Category.OBFUSCATION, 0.4)
_OBF_BASE64 = RuleMatch("ob.base64_payload", Category.OBFUSCATION, 0.5)

# Zero-width spaces/joiners, bidi controls, word joiners, BOM and soft hyphen.
# Attackers sprinkle these inside words ("ig​nore") to break naive matching.
_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤﻿]")
# Unicode "tag" characters mirror ASCII but render as nothing, so instructions can
# be hidden in text that looks empty to a human ("ASCII smuggling").
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]+")
_WHITESPACE = re.compile(r"\s+")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_MAX_BASE64_BLOBS = 5


@dataclass(frozen=True, slots=True)
class _Normalized:
    text: str
    pre_casefold: str  # base64 is case-sensitive, so decode before casefolding
    had_invisible: bool
    had_tag_chars: bool


def _decode_tag_run(match: re.Match[str]) -> str:
    codes = (ord(ch) - 0xE0000 for ch in match.group())
    hidden = "".join(chr(c) for c in codes if 0x20 <= c <= 0x7E)
    # Pad with spaces so the hidden text doesn't fuse with the visible word next to it.
    return f" {hidden} "


def normalize(text: str) -> _Normalized:
    # NFKC folds look-alike forms into their plain equivalents: full-width
    # "ｉｇｎｏｒｅ" -> "ignore", ligature "ﬁ" -> "fi".
    text = unicodedata.normalize("NFKC", text)
    had_invisible = bool(_INVISIBLE.search(text))
    text = _INVISIBLE.sub("", text)
    had_tag_chars = bool(_TAG_CHARS.search(text))
    text = _TAG_CHARS.sub(_decode_tag_run, text)
    text = _WHITESPACE.sub(" ", text).strip()
    return _Normalized(text.casefold(), text, had_invisible, had_tag_chars)


def _decode_base64_blobs(text: str) -> list[str]:
    decoded: list[str] = []
    for blob in _BASE64_BLOB.findall(text)[:_MAX_BASE64_BLOBS]:
        padded = blob + "=" * (-len(blob) % 4)
        try:
            plain = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if plain.isprintable():
            decoded.append(plain)
    return decoded


class InjectionDetector:
    def __init__(
        self,
        rules: Iterable[Rule] = DEFAULT_RULES,
        block_threshold: float = 0.7,
        medium_threshold: float = 0.4,
    ) -> None:
        if not 0 < medium_threshold <= block_threshold <= 1:
            raise ValueError("thresholds must satisfy 0 < medium <= block <= 1")
        self._rules = tuple(rules)
        self._block_threshold = block_threshold
        self._medium_threshold = medium_threshold

    def scan(self, text: str) -> DetectionResult:
        norm = normalize(text)
        matches = {m.rule_id: m for m in self._match_rules(norm.text)}

        if norm.had_invisible:
            matches[_OBF_INVISIBLE.rule_id] = _OBF_INVISIBLE
        if norm.had_tag_chars:
            matches[_OBF_TAG_CHARS.rule_id] = _OBF_TAG_CHARS

        # "Decode this base64 and do what it says": scan the hidden payload too.
        for payload in _decode_base64_blobs(norm.pre_casefold):
            hidden = self._match_rules(normalize(payload).text)
            if hidden:
                matches[_OBF_BASE64.rule_id] = _OBF_BASE64
                for m in hidden:
                    matches.setdefault(m.rule_id, m)

        score = self._combine(m.weight for m in matches.values())
        return DetectionResult(
            risk_score=score,
            risk_level=self._level(score),
            is_blocked=score >= self._block_threshold,
            matches=tuple(sorted(matches.values(), key=lambda m: -m.weight)),
        )

    def _match_rules(self, normalized_text: str) -> list[RuleMatch]:
        return [
            RuleMatch(rule.id, rule.category, rule.weight)
            for rule in self._rules
            if rule.pattern.search(normalized_text)
        ]

    @staticmethod
    def _combine(weights: Iterable[float]) -> float:
        # Treat each hit as independent evidence: risk = 1 - (1-w1)(1-w2)...
        # Two medium signals add up to more than either alone, but the score
        # can never exceed 1.
        remaining = 1.0
        for w in weights:
            remaining *= 1.0 - w
        return round(1.0 - remaining, 4)

    def _level(self, score: float) -> RiskLevel:
        if score >= self._block_threshold:
            return RiskLevel.HIGH
        if score >= self._medium_threshold:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
