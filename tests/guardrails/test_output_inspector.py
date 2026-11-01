import pytest

from app.guardrails.output_inspector import Action, Check, OutputInspector

# Assembled at runtime so secret scanners don't flag this file (see test_pii_masker.py).
FAKE_OPENAI_KEY = "sk-" + "proj-" + "Q9w8E7r6" * 5
FAKE_AWS_KEY = "AKIA" + "Y" * 16


@pytest.fixture
def inspector() -> OutputInspector:
    return OutputInspector()


def test_clean_response_is_allowed_unchanged(inspector):
    answer = "To reset your password, open Settings > Security and click Reset."
    result = inspector.inspect(answer)
    assert result.action is Action.ALLOW
    assert result.text == answer
    assert result.findings == ()


@pytest.mark.parametrize("secret", [FAKE_OPENAI_KEY, FAKE_AWS_KEY, "4111 1111 1111 1111"])
def test_leaked_secrets_are_redacted(inspector, secret):
    result = inspector.inspect(f"Sure! Use this: {secret} and you're done.")
    assert result.action is Action.REDACT
    assert secret not in result.text
    assert "_REDACTED]" in result.text
    assert {f.check for f in result.findings} == {Check.SECRET_EXPOSURE}


def test_findings_never_contain_the_secret(inspector):
    result = inspector.inspect(f"key: {FAKE_OPENAI_KEY}")
    assert all(FAKE_OPENAI_KEY not in f.detail for f in result.findings)


def test_masked_tokens_from_the_input_side_are_left_alone(inspector):
    answer = "Hi [EMAIL_REDACTED_1], I can't use [API_KEY_REDACTED_1] for you."
    result = inspector.inspect(answer)
    assert result.action is Action.ALLOW
    assert result.text == answer


def test_user_contact_details_are_not_treated_as_secrets(inspector):
    result = inspector.inspect("We'll email jane@acme.com or call +91 98765 43210.")
    assert result.action is Action.ALLOW
