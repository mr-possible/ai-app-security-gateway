from app.core.exceptions import (
    GatewayError,
    PromptTooLarge,
    SecurityViolation,
    ViolationCode,
)

DETAILS = {"risk_score": 0.95, "rules": ["io.ignore_previous", "spe.reveal_your_prompt"]}


def test_prompt_injection_payload_matches_openai_error_shape():
    err = SecurityViolation.prompt_injection(DETAILS)
    payload = err.to_payload(request_id="req-123")
    assert err.status_code == 400
    assert payload == {
        "error": {
            "message": "The request was blocked by the security gateway.",
            "type": "security_violation",
            "code": "prompt_injection_detected",
            "request_id": "req-123",
        }
    }


def test_details_are_hidden_unless_explicitly_requested():
    err = SecurityViolation.prompt_injection(DETAILS)
    assert "details" not in err.to_payload()["error"]
    assert err.to_payload(include_details=True)["error"]["details"] == DETAILS


def test_message_does_not_reveal_which_rule_fired():
    message = SecurityViolation.prompt_injection(DETAILS).to_payload()["error"]["message"]
    assert "io." not in message
    assert "0.95" not in message


def test_prompt_too_large_uses_413():
    err = PromptTooLarge(length=50_000, limit=20_000)
    assert err.status_code == 413
    assert err.code == ViolationCode.PROMPT_TOO_LARGE
    assert "20000" in err.message
    assert isinstance(err, SecurityViolation)


def test_gateway_error_defaults_to_500():
    err = GatewayError("boom", code="internal")
    assert err.status_code == 500
    assert err.to_payload()["error"]["type"] == "gateway_error"
