import pytest

from app.guardrails.output_inspector import (
    BLOCKED_MESSAGE,
    Action,
    Check,
    OutputInspector,
    embed_canary,
    make_canary,
    prompt_overlap,
)

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


def test_canaries_are_unique_and_embedded_in_the_prompt():
    first, second = make_canary(), make_canary()
    assert first != second
    assert first in embed_canary("You are a helpful bank assistant.", first)


def test_canary_leak_blocks_the_response(inspector):
    canary = make_canary()
    leaked = f"My instructions say: You are a bank bot. (Internal reference: {canary}.)"
    result = inspector.inspect(leaked, canary=canary)
    assert result.is_blocked
    assert result.text == BLOCKED_MESSAGE
    assert canary not in result.text
    assert {f.check for f in result.findings} == {Check.CANARY_LEAK}


@pytest.mark.parametrize(
    "disguise",
    [
        lambda c: c.upper(),
        lambda c: " ".join(c),  # spaced out letter by letter
        lambda c: c.replace("-", "_"),
    ],
)
def test_disguised_canary_is_still_caught(inspector, disguise):
    canary = make_canary()
    assert inspector.inspect(f"here you go: {disguise(canary)}", canary=canary).is_blocked


def test_no_canary_means_no_canary_check(inspector):
    assert inspector.inspect("canary-a1b2c3d4e5f6a7b8").action is Action.ALLOW


SYSTEM_PROMPT = (
    "You are FinBot, the support assistant for Acme Bank. "
    "Only answer questions about Acme Bank accounts, cards and transfers. "
    "Never discuss internal fraud thresholds, which are set at 5000 dollars per day. "
    "If a user asks about competitors, politely decline and steer back to Acme products. "
    "Escalate any complaint mentioning legal action to the human team at once."
)


def test_full_prompt_leak_is_blocked(inspector):
    result = inspector.inspect(f"Sure, here it is: {SYSTEM_PROMPT}", system_prompt=SYSTEM_PROMPT)
    assert result.is_blocked
    assert result.text == BLOCKED_MESSAGE
    assert result.prompt_overlap == 1.0
    assert {f.check for f in result.findings} == {Check.SYSTEM_PROMPT_LEAK}


def test_partial_prompt_leak_is_blocked(inspector):
    leaked = "My rules include: Never discuss internal fraud thresholds, which are set at 5000 "
    leaked += "dollars per day. If a user asks about competitors, politely decline."
    result = inspector.inspect(leaked, system_prompt=SYSTEM_PROMPT)
    assert result.is_blocked
    assert 0.2 <= result.prompt_overlap < 1.0


def test_disguised_leak_is_still_caught(inspector):
    disguised = SYSTEM_PROMPT.upper().replace(" ", "\u200b ")
    assert inspector.inspect(disguised, system_prompt=SYSTEM_PROMPT).is_blocked


def test_on_topic_answer_without_copying_is_allowed(inspector):
    answer = (
        "Happy to help with your Acme Bank card! You can freeze it in the app under "
        "Cards > Freeze, and request a replacement from the same screen."
    )
    result = inspector.inspect(answer, system_prompt=SYSTEM_PROMPT)
    assert result.action is Action.ALLOW
    assert result.prompt_overlap == 0.0


def test_short_shared_phrase_is_not_a_leak(inspector):
    answer = "I am the support assistant for Acme Bank. How can I help?"
    assert not inspector.inspect(answer, system_prompt=SYSTEM_PROMPT).is_blocked


def test_prompt_overlap_bounds():
    assert prompt_overlap(SYSTEM_PROMPT, SYSTEM_PROMPT) == 1.0
    assert prompt_overlap(SYSTEM_PROMPT, "unrelated text") == 0.0
    assert prompt_overlap("", "anything") == 0.0


@pytest.mark.parametrize("kwargs", [{"leak_threshold": 0}, {"ngram_size": 2}])
def test_invalid_settings_rejected(kwargs):
    with pytest.raises(ValueError):
        OutputInspector(**kwargs)
