"""PII detection and masking for text flowing through the gateway.

Sensitive values (API keys, card numbers, emails, phone numbers) are swapped for
numbered placeholder tokens *before* a prompt leaves our network, so the LLM
provider never sees them. The token -> value mapping lives in memory for one
request only, which lets us optionally put *safe* values back into the answer.

This detector is regex-based: fast, dependency-free and easy to audit. It does not
understand context, so it cannot find names or street addresses. The `PIIDetector`
protocol lets an NLP-based engine (e.g. Microsoft Presidio) be plugged in later.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class PIIType(StrEnum):
    # Declaration order is detection priority: when two matches overlap, the
    # earlier type wins (e.g. digits inside an API key are not also a phone number).
    API_KEY = "API_KEY"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE = "PHONE"


@dataclass(frozen=True, slots=True)
class PIIFinding:
    """Where a piece of PII was found. Holds no raw value, so it is safe to log."""

    pii_type: PIIType
    start: int
    end: int


@dataclass(slots=True)
class MaskResult:
    masked_text: str
    # token -> original value. repr=False keeps secrets out of logs and tracebacks
    # if someone prints or logs the whole result by accident.
    mapping: dict[str, str] = field(default_factory=dict, repr=False)
    findings: list[PIIFinding] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)


class PIIDetector(Protocol):
    """Anything that can locate PII spans in text (regex today, Presidio later)."""

    def detect(self, text: str) -> list[PIIFinding]: ...


def luhn_valid(digits: str) -> bool:
    """Luhn checksum used by every major card network.

    Walking right-to-left, double every second digit (subtracting 9 if the result
    is > 9) and sum everything. Real card numbers sum to a multiple of 10, which
    filters out most random long numbers such as order IDs.
    """
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _only_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _is_card(value: str) -> bool:
    digits = _only_digits(value)
    return 13 <= len(digits) <= 19 and luhn_valid(digits)


def _is_phone(value: str) -> bool:
    return 10 <= len(_only_digits(value)) <= 15


@dataclass(frozen=True, slots=True)
class _Pattern:
    pii_type: PIIType
    regex: re.Pattern[str]
    # Optional second check for patterns that are too loose on their own.
    validator: Callable[[str], bool] | None = None


_DEFAULT_PATTERNS: tuple[_Pattern, ...] = (
    # --- API keys / secrets -------------------------------------------------
    # OpenAI (sk-, sk-proj-, ...) and Anthropic (sk-ant-) keys
    _Pattern(PIIType.API_KEY, re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    # AWS access key IDs (long-term AKIA, temporary ASIA)
    _Pattern(PIIType.API_KEY, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # GitHub classic and fine-grained personal access tokens
    _Pattern(PIIType.API_KEY, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    _Pattern(PIIType.API_KEY, re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    # Generic "Authorization: Bearer <token>" values
    _Pattern(PIIType.API_KEY, re.compile(r"\b[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    # --- Payment cards ------------------------------------------------------
    # 13-19 digits, optionally grouped by spaces/dashes; confirmed with Luhn.
    _Pattern(
        PIIType.CREDIT_CARD,
        re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"),
        validator=_is_card,
    ),
    # --- Email --------------------------------------------------------------
    _Pattern(PIIType.EMAIL, re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # --- Phone --------------------------------------------------------------
    # International format: +<country code> followed by digits and separators.
    _Pattern(PIIType.PHONE, re.compile(r"\+\d[\d\s().\-]{8,20}\d"), validator=_is_phone),
    # North American format: (415) 555-0123, 415-555-0123, 415.555.0123
    _Pattern(
        PIIType.PHONE,
        re.compile(r"(?<![\d+])(?:\(\d{3}\)\s?|\d{3}[\s.\-])\d{3}[\s.\-]\d{4}(?!\d)"),
    ),
)

_PRIORITY = {pii_type: rank for rank, pii_type in enumerate(PIIType)}


class RegexPIIDetector:
    def __init__(self, patterns: Iterable[_Pattern] = _DEFAULT_PATTERNS) -> None:
        self._patterns = tuple(patterns)

    def detect(self, text: str) -> list[PIIFinding]:
        candidates: list[PIIFinding] = []
        for pattern in self._patterns:
            for match in pattern.regex.finditer(text):
                if pattern.validator and not pattern.validator(match.group()):
                    continue
                candidates.append(PIIFinding(pattern.pii_type, match.start(), match.end()))
        return _resolve_overlaps(candidates)


def _resolve_overlaps(candidates: list[PIIFinding]) -> list[PIIFinding]:
    """Keep the highest-priority (then longest) finding wherever spans overlap."""
    ranked = sorted(candidates, key=lambda f: (_PRIORITY[f.pii_type], -(f.end - f.start), f.start))
    accepted: list[PIIFinding] = []
    for finding in ranked:
        if all(finding.end <= kept.start or finding.start >= kept.end for kept in accepted):
            accepted.append(finding)
    return sorted(accepted, key=lambda f: f.start)


_TOKEN_RE = re.compile(r"\[([A-Z_]+)_REDACTED_\d+\]")

# Values that are safe to hand back to the end user who typed them. Secrets are
# never restored: if a response echoes a key token, it stays redacted.
DEFAULT_RESTORABLE: frozenset[PIIType] = frozenset({PIIType.EMAIL, PIIType.PHONE})


class PIIMasker:
    def __init__(
        self,
        detector: PIIDetector | None = None,
        restorable_types: frozenset[PIIType] = DEFAULT_RESTORABLE,
    ) -> None:
        self._detector = detector or RegexPIIDetector()
        self._restorable = restorable_types

    def mask(self, text: str) -> MaskResult:
        findings = self._detector.detect(text)
        if not findings:
            return MaskResult(masked_text=text)

        mapping: dict[str, str] = {}
        token_for_value: dict[tuple[PIIType, str], str] = {}
        counters: dict[PIIType, int] = {}
        parts: list[str] = []
        cursor = 0

        for finding in findings:
            value = text[finding.start : finding.end]
            key = (finding.pii_type, value)
            token = token_for_value.get(key)
            if token is None:
                # Same value -> same token, so the model can still tell that
                # "[EMAIL_REDACTED_1]" mentioned twice is one person.
                counters[finding.pii_type] = counters.get(finding.pii_type, 0) + 1
                token = f"[{finding.pii_type}_REDACTED_{counters[finding.pii_type]}]"
                token_for_value[key] = token
                mapping[token] = value
            parts.append(text[cursor : finding.start])
            parts.append(token)
            cursor = finding.end

        parts.append(text[cursor:])
        return MaskResult(masked_text="".join(parts), mapping=mapping, findings=findings)

    def restore(self, text: str, mapping: dict[str, str]) -> str:
        """Put back original values for restorable types; leave everything else redacted."""

        def _swap(match: re.Match[str]) -> str:
            token = match.group()
            original = mapping.get(token)
            if original is None:
                return token
            try:
                pii_type = PIIType(match.group(1))
            except ValueError:
                return token
            return original if pii_type in self._restorable else token

        return _TOKEN_RE.sub(_swap, text)
