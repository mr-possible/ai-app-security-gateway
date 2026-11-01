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

from app.guardrails.pii_masker import PIIDetector, PIIType, RegexPIIDetector

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


class Action(StrEnum):
    ALLOW = "allow"  # response is clean, pass it through
    REDACT = "redact"  # response is usable once the sensitive parts are removed
    BLOCK = "block"  # response must not be returned at all


class Check(StrEnum):
    SECRET_EXPOSURE = "secret_exposure"  # noqa: S105 - a label, not a password
    CANARY_LEAK = "canary_leak"


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

    @property
    def is_blocked(self) -> bool:
        return self.action is Action.BLOCK


class OutputInspector:
    def __init__(self, secret_detector: PIIDetector | None = None) -> None:
        self._secret_detector = secret_detector or RegexPIIDetector(types=SECRET_TYPES)

    def inspect(self, response: str, *, canary: str | None = None) -> InspectionResult:
        findings: list[OutputFinding] = []

        if canary and _compact(canary) in _compact(response):
            findings.append(
                OutputFinding(Check.CANARY_LEAK, "system prompt canary found in response")
            )
            # A leaked system prompt can't be partially fixed, so stop here.
            return InspectionResult(Action.BLOCK, BLOCKED_MESSAGE, tuple(findings))

        text, secret_findings = self._redact_secrets(response)
        findings.extend(secret_findings)

        action = Action.REDACT if findings else Action.ALLOW
        return InspectionResult(action=action, text=text, findings=tuple(findings))

    def _redact_secrets(self, text: str) -> tuple[str, list[OutputFinding]]:
        detected = self._secret_detector.detect(text)
        if not detected:
            return text, []

        parts: list[str] = []
        cursor = 0
        for found in detected:
            parts.append(text[cursor : found.start])
            parts.append(f"[{found.pii_type}_REDACTED]")
            cursor = found.end
        parts.append(text[cursor:])

        findings = [
            OutputFinding(Check.SECRET_EXPOSURE, f"{found.pii_type} redacted from response")
            for found in detected
        ]
        return "".join(parts), findings
