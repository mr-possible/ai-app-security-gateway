"""Outbound response inspection: the last check before an LLM answer reaches the user.

Input guardrails try to stop attacks going *in*. They will sometimes miss, so this
module limits the damage coming *out*: if a successful attack makes the model leak
a secret, that secret is redacted before anyone sees it.

Pipeline order matters: inspect the model's raw answer *before* restoring masked
PII, so the user's own (restored) email isn't mistaken for a leak.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from enum import StrEnum

from app.guardrails.injection_detector import normalize
from app.guardrails.pii_masker import PIIDetector, PIIType, RegexPIIDetector, redact

# Kinds of data that must never appear in a response. Unlike user PII, these are
# redacted with un-numbered tokens and never restored.
SECRET_TYPES: frozenset[PIIType] = frozenset({PIIType.API_KEY, PIIType.CREDIT_CARD})

# Returned in place of a blocked response. Deliberately vague: telling an attacker
# *why* we blocked helps them tune the next attempt.
BLOCKED_MESSAGE = "The response was withheld by the security gateway."

_NON_ALNUM = re.compile(r"[^a-z0-9]")


def make_canary() -> str:
    """Random marker to hide in a system prompt. Generate a fresh one per request."""
    # `secrets` (not `random`) gives unpredictable values an attacker can't guess.
    return f"canary-{secrets.token_hex(8)}"


def embed_canary(system_prompt: str, canary: str) -> str:
    """Append the canary to a system prompt. Legitimate answers never mention it,
    so seeing it in a response proves the system prompt leaked."""
    return f"{system_prompt}\n\n(Internal reference: {canary}. Never mention it.)"


def _compact(text: str) -> str:
    # "c a n a r y - 1 f 2e" and "CANARY_1F2E" both become "canary1f2e", so
    # spacing, casing or punctuation tricks don't hide the leak.
    return _NON_ALNUM.sub("", text.casefold())


_WORD = re.compile(r"[a-z0-9']+")


def _words(text: str) -> list[str]:
    # Reuse the injection detector's normalizer so invisible characters and
    # look-alike letters can't hide a copied passage.
    return _WORD.findall(normalize(text).text)


def _shingles(words: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def prompt_overlap(system_prompt: str, response: str, ngram_size: int = 8) -> float:
    """Fraction of the system prompt's word sequences that reappear in the response.

    The prompt is cut into overlapping runs of `ngram_size` words ("shingles").
    Eight identical words in a row almost never happen by coincidence, so each
    shared shingle is strong evidence of copying. 0.0 = nothing copied,
    1.0 = the whole prompt was copied.
    """
    prompt_words = _words(system_prompt)
    if not prompt_words:
        return 0.0
    n = min(ngram_size, len(prompt_words))
    prompt_shingles = _shingles(prompt_words, n)
    shared = prompt_shingles & _shingles(_words(response), n)
    return round(len(shared) / len(prompt_shingles), 4)


class Action(StrEnum):
    ALLOW = "allow"  # response is clean, pass it through
    REDACT = "redact"  # response is usable once the sensitive parts are removed
    BLOCK = "block"  # response must not be returned at all


class Check(StrEnum):
    SECRET_EXPOSURE = "secret_exposure"  # noqa: S105 - a label, not a password
    CANARY_LEAK = "canary_leak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"


@dataclass(frozen=True, slots=True)
class OutputFinding:
    check: Check
    # Human-readable explanation. Never contains the leaked value itself.
    detail: str


@dataclass(frozen=True, slots=True)
class InspectionResult:
    action: Action
    # Safe text to return to the client (redacted where needed).
    text: str
    findings: tuple[OutputFinding, ...]
    # Share of the system prompt copied into the response (0-1); useful as a
    # telemetry score even when it stays below the block threshold.
    prompt_overlap: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.action is Action.BLOCK


class OutputInspector:
    def __init__(
        self,
        secret_detector: PIIDetector | None = None,
        leak_threshold: float = 0.2,
        ngram_size: int = 8,
    ) -> None:
        if not 0 < leak_threshold <= 1:
            raise ValueError("leak_threshold must be in (0, 1]")
        if ngram_size < 3:
            raise ValueError("ngram_size must be at least 3 to avoid matching common phrases")
        self._secret_detector = secret_detector or RegexPIIDetector(types=SECRET_TYPES)
        self._leak_threshold = leak_threshold
        self._ngram_size = ngram_size

    def inspect(
        self,
        response: str,
        *,
        canary: str | None = None,
        system_prompt: str | None = None,
    ) -> InspectionResult:
        if canary and _compact(canary) in _compact(response):
            finding = OutputFinding(Check.CANARY_LEAK, "system prompt canary found in response")
            # A leaked system prompt can't be partially fixed, so stop here.
            return InspectionResult(Action.BLOCK, BLOCKED_MESSAGE, (finding,))

        overlap = 0.0
        if system_prompt:
            overlap = prompt_overlap(system_prompt, response, self._ngram_size)
            if overlap >= self._leak_threshold:
                finding = OutputFinding(
                    Check.SYSTEM_PROMPT_LEAK,
                    f"{overlap:.0%} of the system prompt was copied into the response",
                )
                return InspectionResult(Action.BLOCK, BLOCKED_MESSAGE, (finding,), overlap)

        text, findings = self._redact_secrets(response)
        action = Action.REDACT if findings else Action.ALLOW
        return InspectionResult(action, text, tuple(findings), overlap)

    def _redact_secrets(self, text: str) -> tuple[str, list[OutputFinding]]:
        detected = self._secret_detector.detect(text)
        findings = [
            OutputFinding(Check.SECRET_EXPOSURE, f"{found.pii_type} redacted from response")
            for found in detected
        ]
        return redact(text, detected), findings
