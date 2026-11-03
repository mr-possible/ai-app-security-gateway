import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings

FAKE_KEY = "sk-" + "test" * 8  # assembled at runtime so secret scanners stay quiet


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    """Keep tests independent of the developer's real shell variables."""
    for name in (
        "ENVIRONMENT",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "INJECTION_BLOCK_THRESHOLD",
        "INJECTION_MEDIUM_THRESHOLD",
        "EXPOSE_VIOLATION_DETAILS",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def make(**overrides) -> Settings:
    # _env_file=None: never read the developer's real .env during tests.
    return Settings(_env_file=None, **overrides)


def test_safe_defaults():
    s = make()
    assert s.environment == "development"
    assert s.injection_block_threshold == 0.7
    assert s.expose_violation_details is False
    assert s.openai_api_key is None
    assert not s.langfuse_enabled


def test_values_come_from_environment_variables(monkeypatch):
    monkeypatch.setenv("INJECTION_BLOCK_THRESHOLD", "0.85")
    monkeypatch.setenv("OPENAI_MODEL", "some-model")
    s = make()
    assert s.injection_block_threshold == 0.85
    assert s.openai_model == "some-model"


def test_blank_values_count_as_unset(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "")
    assert make().openai_api_key is None


@pytest.mark.parametrize("bad", ["7", "0", "-0.1", "high"])
def test_out_of_range_threshold_stops_startup(monkeypatch, bad):
    monkeypatch.setenv("INJECTION_BLOCK_THRESHOLD", bad)
    with pytest.raises(ValidationError):
        make()


def test_medium_threshold_cannot_exceed_block_threshold():
    with pytest.raises(ValidationError, match="must not exceed"):
        make(injection_block_threshold=0.5, injection_medium_threshold=0.6)


def test_production_requires_provider_credentials():
    with pytest.raises(ValidationError, match="OPENAI_API_KEY, OPENAI_MODEL"):
        make(environment="production")


def test_production_refuses_to_expose_violation_details():
    with pytest.raises(ValidationError, match="expose_violation_details"):
        make(
            environment="production",
            openai_api_key=FAKE_KEY,
            openai_model="some-model",
            expose_violation_details=True,
        )


def test_api_key_is_hidden_when_printed():
    s = make(openai_api_key=FAKE_KEY)
    assert FAKE_KEY not in repr(s)
    assert FAKE_KEY not in str(s.openai_api_key)
    assert s.openai_api_key.get_secret_value() == FAKE_KEY


def test_langfuse_enabled_only_with_both_keys():
    assert not make(langfuse_public_key="pk").langfuse_enabled
    assert make(langfuse_public_key="pk", langfuse_secret_key="sk").langfuse_enabled


def test_get_settings_is_cached():
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()
