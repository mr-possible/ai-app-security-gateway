"""Errors the gateway returns to clients, in OpenAI's error format.

Clients already speak the OpenAI API, so blocked requests come back in the shape
their SDKs know how to parse:

    {"error": {"message": "...", "type": "security_violation",
               "code": "prompt_injection_detected", "request_id": "..."}}

What a client sees is deliberately minimal. Rule ids, scores and matched categories
go to logs and traces for defenders. They only reach the client when
`expose_violation_details` is switched on, for local debugging.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ViolationCode(StrEnum):
    PROMPT_INJECTION = "prompt_injection_detected"
    PROMPT_TOO_LARGE = "prompt_too_large"


class GatewayError(Exception):
    """Base class for errors that map to a clean HTTP response."""

    status_code: int = 500
    error_type: str = "gateway_error"

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        # Internal context for logs and traces. Never put raw prompt text in here.
        self.details = details or {}

    def to_payload(
        self, *, request_id: str | None = None, include_details: bool = False
    ) -> dict[str, Any]:
        error: dict[str, Any] = {
            "message": self.message,
            "type": self.error_type,
            "code": self.code,
            # Lets a user quote an id to support, so we can find the logs, without
            # us having to explain to them what triggered the block.
            "request_id": request_id,
        }
        if include_details and self.details:
            error["details"] = self.details
        return {"error": error}


class SecurityViolation(GatewayError):
    """The request was refused by a guardrail.

    400 Bad Request means "this request is unacceptable; don't retry it unchanged".
    422 is FastAPI's code for malformed JSON/schema errors, so keeping the two apart
    lets dashboards tell attacks apart from client bugs.
    """

    status_code = 400
    error_type = "security_violation"

    @classmethod
    def prompt_injection(cls, details: dict[str, Any] | None = None) -> SecurityViolation:
        return cls(
            "The request was blocked by the security gateway.",
            code=ViolationCode.PROMPT_INJECTION,
            details=details,
        )


class PromptTooLarge(SecurityViolation):
    # 413 Content Too Large: oversized input is a cost / denial-of-service risk.
    status_code = 413

    def __init__(self, length: int, limit: int) -> None:
        super().__init__(
            f"Prompt exceeds the maximum length of {limit} characters.",
            code=ViolationCode.PROMPT_TOO_LARGE,
            details={"length": length, "limit": limit},
        )
