import pytest

from app.guardrails.pii_masker import PIIMasker, PIIType, luhn_valid

# Fake secrets are assembled at runtime instead of written out literally, so secret
# scanners (GitHub push protection, gitleaks) don't flag this test file.
FAKE_OPENAI_KEY = "sk-" + "proj-" + "A1b2C3d4" * 5
FAKE_AWS_KEY = "AKIA" + "Z" * 16
FAKE_GITHUB_TOKEN = "ghp" + "_" + "a1B2" * 9

VISA_TEST_CARD = "4111 1111 1111 1111"  # published test number, passes Luhn


@pytest.fixture
def masker() -> PIIMasker:
    return PIIMasker()


def test_clean_text_passes_through_unchanged(masker):
    text = "How do I reset my password on the staging server?"
    result = masker.mask(text)
    assert result.masked_text == text
    assert not result.has_pii
    assert result.mapping == {}


@pytest.mark.parametrize(
    ("text", "secret", "pii_type"),
    [
        ("Email me at jane.doe@example.com please", "jane.doe@example.com", PIIType.EMAIL),
        (f"My card is {VISA_TEST_CARD}.", VISA_TEST_CARD, PIIType.CREDIT_CARD),
        (f"key={FAKE_OPENAI_KEY}", FAKE_OPENAI_KEY, PIIType.API_KEY),
        (f"aws {FAKE_AWS_KEY} here", FAKE_AWS_KEY, PIIType.API_KEY),
        (f"token {FAKE_GITHUB_TOKEN}", FAKE_GITHUB_TOKEN, PIIType.API_KEY),
        ("Call +91 98765 43210 tomorrow", "+91 98765 43210", PIIType.PHONE),
        ("Office: (415) 555-0123", "(415) 555-0123", PIIType.PHONE),
    ],
)
def test_each_pii_type_is_masked(masker, text, secret, pii_type):
    result = masker.mask(text)
    assert secret not in result.masked_text
    assert f"[{pii_type}_REDACTED_1]" in result.masked_text
    assert result.mapping[f"[{pii_type}_REDACTED_1]"] == secret


def test_luhn_rejects_random_long_numbers(masker):
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    result = masker.mask("Order number 4111 1111 1111 1112 shipped")
    assert not any(f.pii_type == PIIType.CREDIT_CARD for f in result.findings)


def test_distinct_values_get_distinct_tokens_and_repeats_share_one(masker):
    result = masker.mask("cc a@x.com and b@y.org, then a@x.com again")
    assert result.masked_text == (
        "cc [EMAIL_REDACTED_1] and [EMAIL_REDACTED_2], then [EMAIL_REDACTED_1] again"
    )
    assert len(result.mapping) == 2


def test_digits_inside_api_key_are_not_double_counted(masker):
    key = "sk-" + "1234567890" * 3
    result = masker.mask(f"use {key}")
    assert [f.pii_type for f in result.findings] == [PIIType.API_KEY]


def test_restore_returns_email_but_never_secrets(masker):
    result = masker.mask(f"I'm a@x.com, my key is {FAKE_OPENAI_KEY}")
    llm_answer = "Sure [EMAIL_REDACTED_1], I will never share [API_KEY_REDACTED_1]."
    restored = masker.restore(llm_answer, result.mapping)
    assert "a@x.com" in restored
    assert FAKE_OPENAI_KEY not in restored
    assert "[API_KEY_REDACTED_1]" in restored


def test_restore_ignores_unknown_tokens(masker):
    assert masker.restore("hi [EMAIL_REDACTED_9]", {}) == "hi [EMAIL_REDACTED_9]"


def test_repr_does_not_leak_original_values(masker):
    result = masker.mask("contact a@x.com")
    assert "a@x.com" not in repr(result)
