"""Outbound response inspection: the last check before an LLM answer reaches the user.

Input guardrails try to stop attacks going *in*. They will sometimes miss, so this
module limits the damage coming *out*: if a successful attack makes the model leak
a secret, that secret is redacted before anyone sees it.

Pipeline order matters: inspect the model's raw answer *before* restoring masked
PII, so the user's own (restored) email isn't mistaken for a leak.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.guardrails.pii_masker import PIIDetector, PIIType, RegexPIIDetector

# Kinds of data that must never appear in a response. Unlike user PII, these are
# redacted with un-numbered tokens and never restored.
SECRET_TYPES: frozenset[PIIType] = frozenset({PIIType.API_KEY, PIIType.CREDIT_CARD})


class Action(StrEnum):
    ALLOW = "allow"  # response is clean, pass it through
    REDACT = "redact"  # response is usable once the sensitive parts are removed
    BLOCK = "block"  # response must not be returned at all


class Check(StrEnum):
    SECRET_EXPOSURE = "secret_exposure"  # noqa: S105 - a label, not a password


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

    def inspect(self, response: str) -> InspectionResult:
        findings: list[OutputFinding] = []

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
